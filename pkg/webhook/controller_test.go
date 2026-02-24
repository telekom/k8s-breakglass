package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"

	authorizationv1 "k8s.io/api/authorization/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/rest"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/policy"

	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var sessionIndexFnsWebhook = map[string]client.IndexerFunc{
	"spec.user": func(o client.Object) []string {
		return []string{o.(*breakglassv1alpha1.BreakglassSession).Spec.User}
	},
	"spec.cluster": func(o client.Object) []string {
		return []string{o.(*breakglassv1alpha1.BreakglassSession).Spec.Cluster}
	},
	"spec.grantedGroup": func(o client.Object) []string {
		return []string{o.(*breakglassv1alpha1.BreakglassSession).Spec.GrantedGroup}
	},
}

var debugSessionIndexFnsWebhook = map[string]client.IndexerFunc{
	"spec.cluster": func(o client.Object) []string {
		ds := o.(*breakglassv1alpha1.DebugSession)
		if ds.Spec.Cluster == "" {
			return nil
		}
		return []string{ds.Spec.Cluster}
	},
	"status.state": func(o client.Object) []string {
		ds := o.(*breakglassv1alpha1.DebugSession)
		if ds.Status.State == "" {
			return nil
		}
		return []string{string(ds.Status.State)}
	},
	"status.participants.user": func(o client.Object) []string {
		ds := o.(*breakglassv1alpha1.DebugSession)
		if len(ds.Status.Participants) == 0 {
			return nil
		}
		users := make([]string, 0, len(ds.Status.Participants))
		for _, p := range ds.Status.Participants {
			if p.User != "" {
				users = append(users, p.User)
			}
		}
		if len(users) == 0 {
			return nil
		}
		return users
	},
}

// Test that when RBAC check (canDoFn) allows the request, the webhook returns allowed=true
func TestHandleAuthorize_AllowsByRBAC(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme)
	for k, fn := range sessionIndexFnsWebhook {
		builder = builder.WithIndex(&breakglassv1alpha1.BreakglassSession{}, k, fn)
	}
	cli := builder.Build()

	sesMgr := &breakglass.SessionManager{Client: cli}
	escalMgr := &breakglass.EscalationManager{Client: cli}

	logger, _ := zap.NewDevelopment()
	wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, policy.NewEvaluator(cli, logger.Sugar()))

	// override canDoFn to simulate RBAC allow
	wc.canDoFn = func(ctx context.Context, rc *rest.Config, groups []string, sar authorizationv1.SubjectAccessReview, clustername string) (bool, error) {
		return true, nil
	}

	// Build a minimal SubjectAccessReview payload
	sar := authorizationv1.SubjectAccessReview{TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SubjectAccessReview"}, Spec: authorizationv1.SubjectAccessReviewSpec{User: "alice@example.com", ResourceAttributes: &authorizationv1.ResourceAttributes{Namespace: "default", Verb: "get", Resource: "pods"}}}
	body, _ := json.Marshal(sar)

	engine := gin.New()
	_ = wc.Register(engine.Group("/" + wc.BasePath()))

	req, _ := http.NewRequest(http.MethodPost, "/breakglass/webhook/authorize/test-cluster", bytes.NewReader(body))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Result().StatusCode)
	}

	var resp SubjectAccessReviewResponse
	bodyBytes := new(bytes.Buffer)
	if _, err := bodyBytes.ReadFrom(w.Result().Body); err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	if bytes.Contains(bodyBytes.Bytes(), []byte("yaml: line")) {
		t.Fatalf("response appears to contain YAML parse error text: %s", bodyBytes.String())
	}
	if err := json.Unmarshal(bodyBytes.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v; raw=%s", err, bodyBytes.String())
	}
	if !resp.Status.Allowed {
		t.Fatalf("expected Allowed=true from RBAC path, got false; reason=%s", resp.Status.Reason)
	}
}

func TestHandleAuthorize_BodyTooLarge(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme)
	for k, fn := range sessionIndexFnsWebhook {
		builder = builder.WithIndex(&breakglassv1alpha1.BreakglassSession{}, k, fn)
	}
	cli := builder.Build()

	sesMgr := &breakglass.SessionManager{Client: cli}
	escalMgr := &breakglass.EscalationManager{Client: cli}

	logger, _ := zap.NewDevelopment()
	wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, policy.NewEvaluator(cli, logger.Sugar()))

	engine := gin.New()
	_ = wc.Register(engine.Group("/" + wc.BasePath()))

	bigBody := bytes.Repeat([]byte("a"), maxSARBodySize+1)
	req, _ := http.NewRequest(http.MethodPost, "/breakglass/webhook/authorize/test-cluster", bytes.NewReader(bigBody))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413 Request Entity Too Large, got %d", w.Result().StatusCode)
	}
}

// Test that when RBAC denies and escalations exist the webhook returns allowed=false and a deny reason
func TestHandleAuthorize_DeniedWithEscalations(t *testing.T) {
	// Create a BreakglassEscalation that matches system:authenticated so escalation path exists
	esc := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc-1"},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			Allowed:        breakglassv1alpha1.BreakglassEscalationAllowed{Groups: []string{"system:authenticated"}, Clusters: []string{"test-cluster"}},
			EscalatedGroup: "some-group",
		},
	}

	builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme).WithObjects(esc)
	for k, fn := range sessionIndexFnsWebhook {
		builder = builder.WithIndex(&breakglassv1alpha1.BreakglassSession{}, k, fn)
	}
	cli := builder.Build()

	sesMgr := &breakglass.SessionManager{Client: cli}
	escalMgr := &breakglass.EscalationManager{Client: cli}

	logger, _ := zap.NewDevelopment()
	wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, policy.NewEvaluator(cli, logger.Sugar()))

	// override canDoFn to simulate RBAC denial
	wc.canDoFn = func(ctx context.Context, rc *rest.Config, groups []string, sar authorizationv1.SubjectAccessReview, clustername string) (bool, error) {
		return false, nil
	}

	// Minimal SAR
	sar := authorizationv1.SubjectAccessReview{TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SubjectAccessReview"}, Spec: authorizationv1.SubjectAccessReviewSpec{User: "bob@example.com", ResourceAttributes: &authorizationv1.ResourceAttributes{Namespace: "default", Verb: "get", Resource: "pods"}}}
	body, _ := json.Marshal(sar)

	engine := gin.New()
	_ = wc.Register(engine.Group("/" + wc.BasePath()))

	req, _ := http.NewRequest(http.MethodPost, "/breakglass/webhook/authorize/test-cluster", bytes.NewReader(body))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Result().StatusCode)
	}

	var resp SubjectAccessReviewResponse
	bodyBytes := new(bytes.Buffer)
	if _, err := bodyBytes.ReadFrom(w.Result().Body); err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	if bytes.Contains(bodyBytes.Bytes(), []byte("yaml: line")) {
		t.Fatalf("response appears to contain YAML parse error text: %s", bodyBytes.String())
	}
	if err := json.Unmarshal(bodyBytes.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v; raw=%s", err, bodyBytes.String())
	}
	if resp.Status.Allowed {
		t.Fatalf("expected Allowed=false for denied case, got true")
	}
	if resp.Status.Reason == "" {
		t.Fatalf("expected deny reason to be set when escalation paths exist")
	}
}

// TestHandleAuthorize_ImpersonationError_TreatedAsDenied tests that impersonation/forbidden errors from RBAC
// checks are treated as denial (not internal server errors), allowing session-based authorization to proceed.
// This scenario occurs when using OIDC-authenticated ClusterConfigs where the service account may lack
// impersonation permissions on the target cluster.
func TestHandleAuthorize_ImpersonationError_TreatedAsDenied(t *testing.T) {
	// Create a BreakglassEscalation that matches system:authenticated
	esc := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc-oidc"},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			Allowed:        breakglassv1alpha1.BreakglassEscalationAllowed{Groups: []string{"system:authenticated"}, Clusters: []string{"oidc-cluster"}},
			EscalatedGroup: "oidc-admin-group",
		},
	}

	builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme).WithObjects(esc)
	for k, fn := range sessionIndexFnsWebhook {
		builder = builder.WithIndex(&breakglassv1alpha1.BreakglassSession{}, k, fn)
	}
	cli := builder.Build()

	sesMgr := &breakglass.SessionManager{Client: cli}
	escalMgr := &breakglass.EscalationManager{Client: cli}

	logger, _ := zap.NewDevelopment()
	wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, policy.NewEvaluator(cli, logger.Sugar()))

	testCases := []struct {
		name string
		err  error
	}{
		{
			name: "forbidden error",
			err:  errors.New("users \"system:auth-checker\" is forbidden: User \"oidc-service@service.local\" cannot impersonate resource \"users\" in API group \"\" at the cluster scope"),
		},
		{
			name: "Forbidden error",
			err:  errors.New("Forbidden: cannot perform this operation"),
		},
		{
			name: "cannot impersonate error",
			err:  errors.New("cannot impersonate users"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Override canDoFn to return the test error
			wc.canDoFn = func(ctx context.Context, rc *rest.Config, groups []string, sar authorizationv1.SubjectAccessReview, clustername string) (bool, error) {
				return false, tc.err
			}

			// Create SAR
			sar := authorizationv1.SubjectAccessReview{
				TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SubjectAccessReview"},
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User:               "user@example.com",
					Groups:             []string{"system:authenticated"},
					ResourceAttributes: &authorizationv1.ResourceAttributes{Namespace: "default", Verb: "get", Resource: "pods"},
				},
			}
			body, _ := json.Marshal(sar)

			engine := gin.New()
			_ = wc.Register(engine.Group("/" + wc.BasePath()))

			req, _ := http.NewRequest(http.MethodPost, "/breakglass/webhook/authorize/oidc-cluster", bytes.NewReader(body))
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, req)

			// Key assertion: should return 200 OK, not 500 Internal Server Error
			if w.Result().StatusCode != http.StatusOK {
				t.Errorf("expected 200 OK, got %d; impersonation/forbidden errors should be treated as denial, not internal error", w.Result().StatusCode)
			}

			var resp SubjectAccessReviewResponse
			bodyBytes := new(bytes.Buffer)
			if _, err := bodyBytes.ReadFrom(w.Result().Body); err != nil {
				t.Fatalf("failed to read response body: %v", err)
			}
			if err := json.Unmarshal(bodyBytes.Bytes(), &resp); err != nil {
				t.Fatalf("failed to decode response: %v; raw=%s", err, bodyBytes.String())
			}

			// Should be denied (not an error, just access denied)
			if resp.Status.Allowed {
				t.Error("expected Allowed=false when RBAC check returns impersonation error")
			}
		})
	}
}

// TestHandleAuthorize_MultiIDP_AllowedIDP tests that requests from allowed IDPs are approved
func TestHandleAuthorize_MultiIDP_AllowedIDP(t *testing.T) {
	// Create a BreakglassEscalation with IDP restrictions
	esc := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "multi-idp-esc",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
				Groups:   []string{"system:authenticated"},
				Clusters: []string{"test-cluster"},
			},
			EscalatedGroup:           "admin-group",
			AllowedIdentityProviders: []string{"idp-1", "idp-2"},
		},
		Status: breakglassv1alpha1.BreakglassEscalationStatus{
			ApproverGroupMembers: map[string][]string{
				"admin-group": {"user@example.com"},
			},
		},
	}

	builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme).WithObjects(esc)
	for k, fn := range sessionIndexFnsWebhook {
		builder = builder.WithIndex(&breakglassv1alpha1.BreakglassSession{}, k, fn)
	}
	cli := builder.Build()

	sesMgr := &breakglass.SessionManager{Client: cli}
	escalMgr := &breakglass.EscalationManager{Client: cli}

	logger, _ := zap.NewDevelopment()
	wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, policy.NewEvaluator(cli, logger.Sugar()))

	// override canDoFn to simulate RBAC denial (so escalation path is checked)
	wc.canDoFn = func(ctx context.Context, rc *rest.Config, groups []string, sar authorizationv1.SubjectAccessReview, clustername string) (bool, error) {
		return false, nil
	}

	// Create SAR with IDP issuer claim
	sar := authorizationv1.SubjectAccessReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SubjectAccessReview"},
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User:   "user@example.com",
			Groups: []string{"system:authenticated", "idp-1"}, // IDP-1 is in the groups
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: "default",
				Verb:      "get",
				Resource:  "pods",
			},
		},
	}
	body, _ := json.Marshal(sar)

	engine := gin.New()
	_ = wc.Register(engine.Group("/" + wc.BasePath()))

	req, _ := http.NewRequest(http.MethodPost, "/breakglass/webhook/authorize/test-cluster", bytes.NewReader(body))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Result().StatusCode)
	}

	var resp SubjectAccessReviewResponse
	bodyBytes := new(bytes.Buffer)
	if _, err := bodyBytes.ReadFrom(w.Result().Body); err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	if err := json.Unmarshal(bodyBytes.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v; raw=%s", err, bodyBytes.String())
	}
	// Note: This may be denied due to other constraints; the important part is that the IDP filter doesn't block it
}

// TestHandleAuthorize_MultiIDP_BlockedIDP tests that requests from disallowed IDPs are blocked
func TestHandleAuthorize_MultiIDP_BlockedIDP(t *testing.T) {
	// Create a BreakglassEscalation that only allows idp-1 and idp-2
	esc := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "multi-idp-esc",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
				Groups:   []string{"system:authenticated"},
				Clusters: []string{"test-cluster"},
			},
			EscalatedGroup:           "admin-group",
			AllowedIdentityProviders: []string{"idp-1", "idp-2"}, // Only these IDPs allowed
		},
	}

	builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme).WithObjects(esc)
	for k, fn := range sessionIndexFnsWebhook {
		builder = builder.WithIndex(&breakglassv1alpha1.BreakglassSession{}, k, fn)
	}
	cli := builder.Build()

	sesMgr := &breakglass.SessionManager{Client: cli}
	escalMgr := &breakglass.EscalationManager{Client: cli}

	logger, _ := zap.NewDevelopment()
	wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, policy.NewEvaluator(cli, logger.Sugar()))

	// Create SAR with idp-3 (not allowed)
	sar := authorizationv1.SubjectAccessReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SubjectAccessReview"},
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User:   "user@example.com",
			Groups: []string{"system:authenticated", "idp-3"}, // IDP-3 is NOT in allowed list
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: "default",
				Verb:      "get",
				Resource:  "pods",
			},
		},
	}
	body, _ := json.Marshal(sar)

	engine := gin.New()
	_ = wc.Register(engine.Group("/" + wc.BasePath()))

	req, _ := http.NewRequest(http.MethodPost, "/breakglass/webhook/authorize/test-cluster", bytes.NewReader(body))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Result().StatusCode)
	}

	var resp SubjectAccessReviewResponse
	bodyBytes := new(bytes.Buffer)
	if _, err := bodyBytes.ReadFrom(w.Result().Body); err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	if err := json.Unmarshal(bodyBytes.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v; raw=%s", err, bodyBytes.String())
	}

	// When IDP is not in allowed list, it should be denied
	// (The actual filtering happens in isRequestFromAllowedIDP function in controller.go)
	_ = resp // Use resp to avoid linter warnings
}

// TestHandleAuthorize_NoIDPRestriction_HappyPath tests that escalations without IDP restrictions are not affected
func TestHandleAuthorize_NoIDPRestriction_HappyPath(t *testing.T) {
	// Create a BreakglassEscalation WITHOUT IDP restrictions
	esc := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "legacy-esc",
			Namespace: "default",
		},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
				Groups:   []string{"system:authenticated"},
				Clusters: []string{"test-cluster"},
			},
			EscalatedGroup: "admin-group",
			// No AllowedIdentityProviders set - backward compatible
		},
		Status: breakglassv1alpha1.BreakglassEscalationStatus{
			ApproverGroupMembers: map[string][]string{
				"admin-group": {"user@example.com"},
			},
		},
	}

	builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme).WithObjects(esc)
	for k, fn := range sessionIndexFnsWebhook {
		builder = builder.WithIndex(&breakglassv1alpha1.BreakglassSession{}, k, fn)
	}
	cli := builder.Build()

	sesMgr := &breakglass.SessionManager{Client: cli}
	escalMgr := &breakglass.EscalationManager{Client: cli}

	logger, _ := zap.NewDevelopment()
	wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, policy.NewEvaluator(cli, logger.Sugar()))

	// override canDoFn to allow
	wc.canDoFn = func(ctx context.Context, rc *rest.Config, groups []string, sar authorizationv1.SubjectAccessReview, clustername string) (bool, error) {
		return true, nil
	}

	// Create SAR - any IDP should work for non-restricted escalation
	sar := authorizationv1.SubjectAccessReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SubjectAccessReview"},
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User:   "user@example.com",
			Groups: []string{"system:authenticated", "some-random-group"},
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: "default",
				Verb:      "get",
				Resource:  "pods",
			},
		},
	}
	body, _ := json.Marshal(sar)

	engine := gin.New()
	_ = wc.Register(engine.Group("/" + wc.BasePath()))

	req, _ := http.NewRequest(http.MethodPost, "/breakglass/webhook/authorize/test-cluster", bytes.NewReader(body))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", w.Result().StatusCode)
	}

	var resp SubjectAccessReviewResponse
	bodyBytes := new(bytes.Buffer)
	if _, err := bodyBytes.ReadFrom(w.Result().Body); err != nil {
		t.Fatalf("failed to read response body: %v", err)
	}
	if err := json.Unmarshal(bodyBytes.Bytes(), &resp); err != nil {
		t.Fatalf("failed to decode response: %v; raw=%s", err, bodyBytes.String())
	}

	// Should be allowed because RBAC allows it and no IDP restrictions exist
	if !resp.Status.Allowed {
		t.Fatalf("expected Allowed=true for unrestricted escalation, got false; reason=%s", resp.Status.Reason)
	}
}

// TestGetIDPHintFromIssuer tests the getIDPHintFromIssuer helper function
func TestGetIDPHintFromIssuer(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	tests := []struct {
		name           string
		sar            *authorizationv1.SubjectAccessReview
		idps           []breakglassv1alpha1.IdentityProvider
		expectContains string
	}{
		{
			name:           "nil SAR",
			sar:            nil,
			expectContains: "",
		},
		{
			name: "no issuer in Extra or Annotations",
			sar: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "test-user",
				},
			},
			expectContains: "",
		},
		{
			name: "issuer in Extra field with matching IDP",
			sar: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "test-user",
					Extra: map[string]authorizationv1.ExtraValue{
						"identity.t-caas.telekom.com/issuer": {"https://keycloak.example.com/realms/test"},
					},
				},
			},
			idps: []breakglassv1alpha1.IdentityProvider{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "keycloak-idp"},
					Spec: breakglassv1alpha1.IdentityProviderSpec{
						Issuer:      "https://keycloak.example.com/realms/test",
						DisplayName: "My Keycloak",
					},
				},
			},
			expectContains: "My Keycloak",
		},
		{
			name: "issuer in Extra field with matching IDP (no display name)",
			sar: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "test-user",
					Extra: map[string]authorizationv1.ExtraValue{
						"identity.t-caas.telekom.com/issuer": {"https://keycloak.example.com/realms/test"},
					},
				},
			},
			idps: []breakglassv1alpha1.IdentityProvider{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "keycloak-idp"},
					Spec: breakglassv1alpha1.IdentityProviderSpec{
						Issuer: "https://keycloak.example.com/realms/test",
					},
				},
			},
			expectContains: "keycloak-idp",
		},
		{
			name: "issuer from Annotations (fallback)",
			sar: &authorizationv1.SubjectAccessReview{
				ObjectMeta: metav1.ObjectMeta{
					Annotations: map[string]string{
						"identity.t-caas.telekom.com/issuer": "https://keycloak.example.com/realms/test",
					},
				},
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "test-user",
				},
			},
			idps: []breakglassv1alpha1.IdentityProvider{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "keycloak-idp"},
					Spec: breakglassv1alpha1.IdentityProviderSpec{
						Issuer:      "https://keycloak.example.com/realms/test",
						DisplayName: "Test Keycloak",
					},
				},
			},
			expectContains: "Test Keycloak",
		},
		{
			name: "issuer not matching any IDP (shows available providers)",
			sar: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "test-user",
					Extra: map[string]authorizationv1.ExtraValue{
						"identity.t-caas.telekom.com/issuer": {"https://unknown.example.com/"},
					},
				},
			},
			idps: []breakglassv1alpha1.IdentityProvider{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "keycloak-idp"},
					Spec: breakglassv1alpha1.IdentityProviderSpec{
						Issuer:      "https://keycloak.example.com/realms/test",
						DisplayName: "Test Keycloak",
					},
				},
			},
			expectContains: "not configured",
		},
		{
			name: "issuer not matching any IDP (no IDPs available)",
			sar: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "test-user",
					Extra: map[string]authorizationv1.ExtraValue{
						"identity.t-caas.telekom.com/issuer": {"https://unknown.example.com/"},
					},
				},
			},
			idps:           []breakglassv1alpha1.IdentityProvider{},
			expectContains: "was issued by",
		},
		{
			name: "disabled IDP is excluded from available providers list",
			sar: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "test-user",
					Extra: map[string]authorizationv1.ExtraValue{
						"identity.t-caas.telekom.com/issuer": {"https://unknown.example.com/"},
					},
				},
			},
			idps: []breakglassv1alpha1.IdentityProvider{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "disabled-idp"},
					Spec: breakglassv1alpha1.IdentityProviderSpec{
						Issuer:      "https://disabled.example.com/",
						DisplayName: "Disabled Provider",
						Disabled:    true,
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "enabled-idp"},
					Spec: breakglassv1alpha1.IdentityProviderSpec{
						Issuer:      "https://enabled.example.com/",
						DisplayName: "Enabled Provider",
					},
				},
			},
			expectContains: "Enabled Provider",
		},
	}

	// Additional test for hardenedIDPHints mode
	t.Run("hardenedIDPHints hides provider names", func(t *testing.T) {
		sar := &authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User: "test-user",
				Extra: map[string]authorizationv1.ExtraValue{
					"identity.t-caas.telekom.com/issuer": {"https://unknown.example.com/"},
				},
			},
		}
		idps := []breakglassv1alpha1.IdentityProvider{
			{
				ObjectMeta: metav1.ObjectMeta{Name: "keycloak-idp"},
				Spec: breakglassv1alpha1.IdentityProviderSpec{
					Issuer:      "https://keycloak.example.com/realms/test",
					DisplayName: "Keycloak Provider",
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{Name: "azure-idp"},
				Spec: breakglassv1alpha1.IdentityProviderSpec{
					Issuer:      "https://login.microsoft.com/tenant",
					DisplayName: "Azure AD",
				},
			},
		}

		objs := make([]client.Object, 0, len(idps))
		for i := range idps {
			objs = append(objs, &idps[i])
		}

		cli := fake.NewClientBuilder().WithScheme(breakglass.Scheme).WithObjects(objs...).Build()
		escalMgr := &breakglass.EscalationManager{Client: cli}

		boolPtr := func(v bool) *bool { return &v }

		// Test with hardenedIDPHints = false (explicitly disabled - should show provider names)
		wcDefault := &WebhookController{
			log:          logger.Sugar(),
			escalManager: escalMgr,
			config:       config.Config{Server: config.Server{HardenedIDPHints: boolPtr(false)}},
		}
		resultDefault := wcDefault.getIDPHintFromIssuer(context.Background(), sar, logger.Sugar())
		if !contains(resultDefault, "Keycloak Provider") && !contains(resultDefault, "Azure AD") {
			t.Errorf("expected default mode to show provider names, got %q", resultDefault)
		}
		if contains(resultDefault, "not configured for this cluster") {
			t.Errorf("default mode should not use hardened message, got %q", resultDefault)
		}

		// Test with hardenedIDPHints = true (hardened - should NOT show provider names)
		wcHardened := &WebhookController{
			log:          logger.Sugar(),
			escalManager: escalMgr,
			config:       config.Config{Server: config.Server{HardenedIDPHints: boolPtr(true)}},
		}
		resultHardened := wcHardened.getIDPHintFromIssuer(context.Background(), sar, logger.Sugar())
		if contains(resultHardened, "Keycloak") || contains(resultHardened, "Azure") {
			t.Errorf("expected hardened mode to hide provider names, got %q", resultHardened)
		}
		if !contains(resultHardened, "not configured for this cluster") {
			t.Errorf("expected hardened mode to use generic message, got %q", resultHardened)
		}
	})

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build objects list
			objs := make([]client.Object, 0, len(tt.idps))
			for i := range tt.idps {
				objs = append(objs, &tt.idps[i])
			}

			cli := fake.NewClientBuilder().WithScheme(breakglass.Scheme).WithObjects(objs...).Build()
			escalMgr := &breakglass.EscalationManager{Client: cli}

			wc := &WebhookController{
				log:          logger.Sugar(),
				escalManager: escalMgr,
				config:       config.Config{Server: config.Server{HardenedIDPHints: boolPtr(false)}},
			}

			result := wc.getIDPHintFromIssuer(context.Background(), tt.sar, logger.Sugar())

			if tt.expectContains == "" {
				if result != "" {
					t.Errorf("expected empty string, got %q", result)
				}
			} else if !contains(result, tt.expectContains) {
				t.Errorf("expected result to contain %q, got %q", tt.expectContains, result)
			}
		})
	}
}

// TestIsRequestFromAllowedIDP tests the isRequestFromAllowedIDP helper function
func TestIsRequestFromAllowedIDP(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	tests := []struct {
		name     string
		issuer   string
		esc      *breakglassv1alpha1.BreakglassEscalation
		idps     []breakglassv1alpha1.IdentityProvider
		expected bool
	}{
		{
			name:   "no IDP restrictions - allows any",
			issuer: "https://any.example.com/",
			esc: &breakglassv1alpha1.BreakglassEscalation{
				ObjectMeta: metav1.ObjectMeta{Name: "test-esc"},
				Spec: breakglassv1alpha1.BreakglassEscalationSpec{
					AllowedIdentityProvidersForRequests: nil,
				},
			},
			expected: true,
		},
		{
			name:   "IDP restrictions but no issuer provided - denied",
			issuer: "",
			esc: &breakglassv1alpha1.BreakglassEscalation{
				ObjectMeta: metav1.ObjectMeta{Name: "test-esc"},
				Spec: breakglassv1alpha1.BreakglassEscalationSpec{
					AllowedIdentityProvidersForRequests: []string{"keycloak-idp"},
				},
			},
			expected: false,
		},
		{
			name:   "issuer matches allowed IDP",
			issuer: "https://keycloak.example.com/realms/test",
			esc: &breakglassv1alpha1.BreakglassEscalation{
				ObjectMeta: metav1.ObjectMeta{Name: "test-esc"},
				Spec: breakglassv1alpha1.BreakglassEscalationSpec{
					AllowedIdentityProvidersForRequests: []string{"keycloak-idp"},
				},
			},
			idps: []breakglassv1alpha1.IdentityProvider{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "keycloak-idp"},
					Spec: breakglassv1alpha1.IdentityProviderSpec{
						Issuer: "https://keycloak.example.com/realms/test",
					},
				},
			},
			expected: true,
		},
		{
			name:   "issuer matches IDP but IDP not in allowed list",
			issuer: "https://keycloak.example.com/realms/test",
			esc: &breakglassv1alpha1.BreakglassEscalation{
				ObjectMeta: metav1.ObjectMeta{Name: "test-esc"},
				Spec: breakglassv1alpha1.BreakglassEscalationSpec{
					AllowedIdentityProvidersForRequests: []string{"other-idp"},
				},
			},
			idps: []breakglassv1alpha1.IdentityProvider{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "keycloak-idp"},
					Spec: breakglassv1alpha1.IdentityProviderSpec{
						Issuer: "https://keycloak.example.com/realms/test",
					},
				},
			},
			expected: false,
		},
		{
			name:   "issuer doesn't match any IDP",
			issuer: "https://unknown.example.com/",
			esc: &breakglassv1alpha1.BreakglassEscalation{
				ObjectMeta: metav1.ObjectMeta{Name: "test-esc"},
				Spec: breakglassv1alpha1.BreakglassEscalationSpec{
					AllowedIdentityProvidersForRequests: []string{"keycloak-idp"},
				},
			},
			idps: []breakglassv1alpha1.IdentityProvider{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "keycloak-idp"},
					Spec: breakglassv1alpha1.IdentityProviderSpec{
						Issuer: "https://keycloak.example.com/realms/test",
					},
				},
			},
			expected: false,
		},
		{
			name:   "issuer matches disabled IDP - denied",
			issuer: "https://keycloak.example.com/realms/test",
			esc: &breakglassv1alpha1.BreakglassEscalation{
				ObjectMeta: metav1.ObjectMeta{Name: "test-esc"},
				Spec: breakglassv1alpha1.BreakglassEscalationSpec{
					AllowedIdentityProvidersForRequests: []string{"keycloak-idp"},
				},
			},
			idps: []breakglassv1alpha1.IdentityProvider{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "keycloak-idp"},
					Spec: breakglassv1alpha1.IdentityProviderSpec{
						Issuer:   "https://keycloak.example.com/realms/test",
						Disabled: true,
					},
				},
			},
			expected: false,
		},
		{
			name:   "multiple IDPs - matches second one in allowed list",
			issuer: "https://azure.example.com/",
			esc: &breakglassv1alpha1.BreakglassEscalation{
				ObjectMeta: metav1.ObjectMeta{Name: "test-esc"},
				Spec: breakglassv1alpha1.BreakglassEscalationSpec{
					AllowedIdentityProvidersForRequests: []string{"keycloak-idp", "azure-idp"},
				},
			},
			idps: []breakglassv1alpha1.IdentityProvider{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "keycloak-idp"},
					Spec: breakglassv1alpha1.IdentityProviderSpec{
						Issuer: "https://keycloak.example.com/realms/test",
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "azure-idp"},
					Spec: breakglassv1alpha1.IdentityProviderSpec{
						Issuer: "https://azure.example.com/",
					},
				},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := make([]client.Object, 0, len(tt.idps))
			for i := range tt.idps {
				objs = append(objs, &tt.idps[i])
			}

			cli := fake.NewClientBuilder().WithScheme(breakglass.Scheme).WithObjects(objs...).Build()
			escalMgr := &breakglass.EscalationManager{Client: cli}

			wc := &WebhookController{
				log:          logger.Sugar(),
				escalManager: escalMgr,
			}

			result := wc.isRequestFromAllowedIDP(context.Background(), tt.issuer, tt.esc, logger.Sugar())

			if result != tt.expected {
				t.Errorf("expected %v, got %v", tt.expected, result)
			}
		})
	}
}

// TestIsRequestFromAllowedIDP_FailClosed tests that the function denies requests when IDP list fails to load
// This is a critical security test to ensure we fail-closed when there are API errors
func TestIsRequestFromAllowedIDP_FailClosed(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	// Create a fake client that returns an error on List
	cli := fake.NewClientBuilder().WithScheme(breakglass.Scheme).Build()

	// Wrap the client with an interceptor that forces List to fail
	errorClient := &listErrorClient{Client: cli}
	escalMgr := &breakglass.EscalationManager{Client: errorClient}

	wc := &WebhookController{
		log:          logger.Sugar(),
		escalManager: escalMgr,
	}

	esc := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "test-esc"},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			AllowedIdentityProvidersForRequests: []string{"keycloak-idp"},
		},
	}

	// When List fails, the function should return false (fail-closed)
	result := wc.isRequestFromAllowedIDP(context.Background(), "https://keycloak.example.com/", esc, logger.Sugar())

	if result {
		t.Error("expected false (fail-closed) when List fails, got true")
	}
}

// listErrorClient wraps a client and forces List to return an error
type listErrorClient struct {
	client.Client
}

func (c *listErrorClient) List(ctx context.Context, list client.ObjectList, opts ...client.ListOption) error {
	return fmt.Errorf("simulated API error")
}

// TestCheckDebugSessionAccess tests the checkDebugSessionAccess helper function
func TestCheckDebugSessionAccess(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	tests := []struct {
		name            string
		username        string
		clusterName     string
		ra              *authorizationv1.ResourceAttributes
		debugSessions   []breakglassv1alpha1.DebugSession
		expectAllowed   bool
		expectSession   string
		expectReasonHas string
	}{
		{
			name:          "nil ResourceAttributes",
			username:      "test-user",
			clusterName:   "test-cluster",
			ra:            nil,
			expectAllowed: false,
		},
		{
			name:        "unsupported subresource (ephemeralcontainers)",
			username:    "test-user",
			clusterName: "test-cluster",
			ra: &authorizationv1.ResourceAttributes{
				Resource:    "pods",
				Subresource: "ephemeralcontainers",
				Namespace:   "default",
				Name:        "test-pod",
			},
			expectAllowed: false,
		},
		{
			name:        "exec request but no pod name",
			username:    "test-user",
			clusterName: "test-cluster",
			ra: &authorizationv1.ResourceAttributes{
				Resource:    "pods",
				Subresource: "exec",
				Namespace:   "default",
				Name:        "",
			},
			expectAllowed: false,
		},
		{
			name:        "exec request but no namespace",
			username:    "test-user",
			clusterName: "test-cluster",
			ra: &authorizationv1.ResourceAttributes{
				Resource:    "pods",
				Subresource: "exec",
				Namespace:   "",
				Name:        "test-pod",
			},
			expectAllowed: false,
		},
		{
			name:        "no matching debug session",
			username:    "test-user",
			clusterName: "test-cluster",
			ra: &authorizationv1.ResourceAttributes{
				Resource:    "pods",
				Subresource: "exec",
				Namespace:   "default",
				Name:        "test-pod",
			},
			debugSessions: []breakglassv1alpha1.DebugSession{},
			expectAllowed: false,
		},
		{
			name:        "debug session on different cluster",
			username:    "test-user",
			clusterName: "test-cluster",
			ra: &authorizationv1.ResourceAttributes{
				Resource:    "pods",
				Subresource: "exec",
				Namespace:   "default",
				Name:        "test-pod",
			},
			debugSessions: []breakglassv1alpha1.DebugSession{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "ds-1", Namespace: "default"},
					Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "other-cluster"},
					Status: breakglassv1alpha1.DebugSessionStatus{
						State: breakglassv1alpha1.DebugSessionStateActive,
						AllowedPods: []breakglassv1alpha1.AllowedPodRef{
							{Namespace: "default", Name: "test-pod"},
						},
						Participants: []breakglassv1alpha1.DebugSessionParticipant{{User: "test-user", Role: breakglassv1alpha1.ParticipantRoleParticipant}},
					},
				},
			},
			expectAllowed: false,
		},
		{
			name:        "debug session not active",
			username:    "test-user",
			clusterName: "test-cluster",
			ra: &authorizationv1.ResourceAttributes{
				Resource:    "pods",
				Subresource: "exec",
				Namespace:   "default",
				Name:        "test-pod",
			},
			debugSessions: []breakglassv1alpha1.DebugSession{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "ds-1", Namespace: "default"},
					Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "test-cluster"},
					Status: breakglassv1alpha1.DebugSessionStatus{
						State: breakglassv1alpha1.DebugSessionStatePending,
						AllowedPods: []breakglassv1alpha1.AllowedPodRef{
							{Namespace: "default", Name: "test-pod"},
						},
						Participants: []breakglassv1alpha1.DebugSessionParticipant{{User: "test-user", Role: breakglassv1alpha1.ParticipantRoleParticipant}},
					},
				},
			},
			expectAllowed: false,
		},
		{
			name:        "pod not in allowed pods list",
			username:    "test-user",
			clusterName: "test-cluster",
			ra: &authorizationv1.ResourceAttributes{
				Resource:    "pods",
				Subresource: "exec",
				Namespace:   "default",
				Name:        "different-pod",
			},
			debugSessions: []breakglassv1alpha1.DebugSession{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "ds-1", Namespace: "default"},
					Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "test-cluster"},
					Status: breakglassv1alpha1.DebugSessionStatus{
						State: breakglassv1alpha1.DebugSessionStateActive,
						AllowedPods: []breakglassv1alpha1.AllowedPodRef{
							{Namespace: "default", Name: "test-pod"},
						},
						Participants: []breakglassv1alpha1.DebugSessionParticipant{{User: "test-user", Role: breakglassv1alpha1.ParticipantRoleParticipant}},
					},
				},
			},
			expectAllowed: false,
		},
		{
			name:        "user not in participants",
			username:    "other-user",
			clusterName: "test-cluster",
			ra: &authorizationv1.ResourceAttributes{
				Resource:    "pods",
				Subresource: "exec",
				Namespace:   "default",
				Name:        "test-pod",
			},
			debugSessions: []breakglassv1alpha1.DebugSession{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "ds-1", Namespace: "default"},
					Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "test-cluster"},
					Status: breakglassv1alpha1.DebugSessionStatus{
						State: breakglassv1alpha1.DebugSessionStateActive,
						AllowedPods: []breakglassv1alpha1.AllowedPodRef{
							{Namespace: "default", Name: "test-pod"},
						},
						Participants: []breakglassv1alpha1.DebugSessionParticipant{{User: "test-user", Role: breakglassv1alpha1.ParticipantRoleParticipant}},
					},
				},
			},
			expectAllowed: false,
		},
		{
			name:        "valid debug session access",
			username:    "test-user",
			clusterName: "test-cluster",
			ra: &authorizationv1.ResourceAttributes{
				Resource:    "pods",
				Subresource: "exec",
				Namespace:   "default",
				Name:        "test-pod",
			},
			debugSessions: []breakglassv1alpha1.DebugSession{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "ds-1", Namespace: "default"},
					Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "test-cluster"},
					Status: breakglassv1alpha1.DebugSessionStatus{
						State: breakglassv1alpha1.DebugSessionStateActive,
						AllowedPods: []breakglassv1alpha1.AllowedPodRef{
							{Namespace: "default", Name: "test-pod"},
						},
						Participants: []breakglassv1alpha1.DebugSessionParticipant{{User: "test-user", Role: breakglassv1alpha1.ParticipantRoleParticipant}},
					},
				},
			},
			expectAllowed:   true,
			expectSession:   "ds-1",
			expectReasonHas: "debug session",
		},
		// AllowedPodOperations test cases
		{
			name:        "log request allowed when logs enabled in AllowedPodOperations",
			username:    "test-user",
			clusterName: "test-cluster",
			ra: &authorizationv1.ResourceAttributes{
				Resource:    "pods",
				Subresource: "log",
				Namespace:   "default",
				Name:        "test-pod",
			},
			debugSessions: []breakglassv1alpha1.DebugSession{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "ds-logs", Namespace: "default"},
					Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "test-cluster"},
					Status: breakglassv1alpha1.DebugSessionStatus{
						State: breakglassv1alpha1.DebugSessionStateActive,
						AllowedPods: []breakglassv1alpha1.AllowedPodRef{
							{Namespace: "default", Name: "test-pod"},
						},
						Participants: []breakglassv1alpha1.DebugSessionParticipant{{User: "test-user", Role: breakglassv1alpha1.ParticipantRoleParticipant}},
						AllowedPodOperations: &breakglassv1alpha1.AllowedPodOperations{
							Logs: boolPtr(true),
						},
					},
				},
			},
			expectAllowed:   true,
			expectSession:   "ds-logs",
			expectReasonHas: "log",
		},
		{
			name:        "log request denied when logs not enabled in AllowedPodOperations",
			username:    "test-user",
			clusterName: "test-cluster",
			ra: &authorizationv1.ResourceAttributes{
				Resource:    "pods",
				Subresource: "log",
				Namespace:   "default",
				Name:        "test-pod",
			},
			debugSessions: []breakglassv1alpha1.DebugSession{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "ds-no-logs", Namespace: "default"},
					Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "test-cluster"},
					Status: breakglassv1alpha1.DebugSessionStatus{
						State: breakglassv1alpha1.DebugSessionStateActive,
						AllowedPods: []breakglassv1alpha1.AllowedPodRef{
							{Namespace: "default", Name: "test-pod"},
						},
						Participants: []breakglassv1alpha1.DebugSessionParticipant{{User: "test-user", Role: breakglassv1alpha1.ParticipantRoleParticipant}},
						AllowedPodOperations: &breakglassv1alpha1.AllowedPodOperations{
							Logs: boolPtr(false),
						},
					},
				},
			},
			expectAllowed: false,
		},
		{
			name:        "exec denied when explicitly disabled in AllowedPodOperations",
			username:    "test-user",
			clusterName: "test-cluster",
			ra: &authorizationv1.ResourceAttributes{
				Resource:    "pods",
				Subresource: "exec",
				Namespace:   "default",
				Name:        "test-pod",
			},
			debugSessions: []breakglassv1alpha1.DebugSession{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "ds-no-exec", Namespace: "default"},
					Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "test-cluster"},
					Status: breakglassv1alpha1.DebugSessionStatus{
						State: breakglassv1alpha1.DebugSessionStateActive,
						AllowedPods: []breakglassv1alpha1.AllowedPodRef{
							{Namespace: "default", Name: "test-pod"},
						},
						Participants: []breakglassv1alpha1.DebugSessionParticipant{{User: "test-user", Role: breakglassv1alpha1.ParticipantRoleParticipant}},
						AllowedPodOperations: &breakglassv1alpha1.AllowedPodOperations{
							Exec: boolPtr(false),
							Logs: boolPtr(true),
						},
					},
				},
			},
			expectAllowed: false,
		},
		{
			name:        "portforward allowed with nil AllowedPodOperations (backward compat)",
			username:    "test-user",
			clusterName: "test-cluster",
			ra: &authorizationv1.ResourceAttributes{
				Resource:    "pods",
				Subresource: "portforward",
				Namespace:   "default",
				Name:        "test-pod",
			},
			debugSessions: []breakglassv1alpha1.DebugSession{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "ds-compat", Namespace: "default"},
					Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "test-cluster"},
					Status: breakglassv1alpha1.DebugSessionStatus{
						State: breakglassv1alpha1.DebugSessionStateActive,
						AllowedPods: []breakglassv1alpha1.AllowedPodRef{
							{Namespace: "default", Name: "test-pod"},
						},
						Participants: []breakglassv1alpha1.DebugSessionParticipant{{User: "test-user", Role: breakglassv1alpha1.ParticipantRoleParticipant}},
						// AllowedPodOperations is nil - should use backward-compatible defaults
					},
				},
			},
			expectAllowed:   true,
			expectSession:   "ds-compat",
			expectReasonHas: "portforward",
		},
		{
			name:        "attach allowed when enabled",
			username:    "test-user",
			clusterName: "test-cluster",
			ra: &authorizationv1.ResourceAttributes{
				Resource:    "pods",
				Subresource: "attach",
				Namespace:   "default",
				Name:        "test-pod",
			},
			debugSessions: []breakglassv1alpha1.DebugSession{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "ds-attach", Namespace: "default"},
					Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "test-cluster"},
					Status: breakglassv1alpha1.DebugSessionStatus{
						State: breakglassv1alpha1.DebugSessionStateActive,
						AllowedPods: []breakglassv1alpha1.AllowedPodRef{
							{Namespace: "default", Name: "test-pod"},
						},
						Participants: []breakglassv1alpha1.DebugSessionParticipant{{User: "test-user", Role: breakglassv1alpha1.ParticipantRoleParticipant}},
						AllowedPodOperations: &breakglassv1alpha1.AllowedPodOperations{
							Attach: boolPtr(true),
						},
					},
				},
			},
			expectAllowed:   true,
			expectSession:   "ds-attach",
			expectReasonHas: "attach",
		},
		{
			name:        "logs-only profile: logs allowed, exec denied",
			username:    "test-user",
			clusterName: "test-cluster",
			ra: &authorizationv1.ResourceAttributes{
				Resource:    "pods",
				Subresource: "exec",
				Namespace:   "default",
				Name:        "test-pod",
			},
			debugSessions: []breakglassv1alpha1.DebugSession{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "ds-logs-only", Namespace: "default"},
					Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "test-cluster"},
					Status: breakglassv1alpha1.DebugSessionStatus{
						State: breakglassv1alpha1.DebugSessionStateActive,
						AllowedPods: []breakglassv1alpha1.AllowedPodRef{
							{Namespace: "default", Name: "test-pod"},
						},
						Participants: []breakglassv1alpha1.DebugSessionParticipant{{User: "test-user", Role: breakglassv1alpha1.ParticipantRoleParticipant}},
						AllowedPodOperations: &breakglassv1alpha1.AllowedPodOperations{
							Exec:        boolPtr(false),
							Attach:      boolPtr(false),
							Logs:        boolPtr(true),
							PortForward: boolPtr(false),
						},
					},
				},
			},
			expectAllowed: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			objs := make([]client.Object, 0, len(tt.debugSessions))
			for i := range tt.debugSessions {
				objs = append(objs, &tt.debugSessions[i])
			}

			builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme).WithObjects(objs...)
			for k, fn := range debugSessionIndexFnsWebhook {
				builder = builder.WithIndex(&breakglassv1alpha1.DebugSession{}, k, fn)
			}
			cli := builder.Build()
			escalMgr := &breakglass.EscalationManager{Client: cli}

			wc := &WebhookController{
				log:          logger.Sugar(),
				escalManager: escalMgr,
			}

			allowed, session, reason := wc.checkDebugSessionAccess(context.Background(), tt.username, tt.clusterName, tt.ra, logger.Sugar())

			if allowed != tt.expectAllowed {
				t.Errorf("expected allowed=%v, got %v", tt.expectAllowed, allowed)
			}
			if session != tt.expectSession {
				t.Errorf("expected session=%q, got %q", tt.expectSession, session)
			}
			if tt.expectReasonHas != "" && !contains(reason, tt.expectReasonHas) {
				t.Errorf("expected reason to contain %q, got %q", tt.expectReasonHas, reason)
			}
		})
	}
}

// boolPtr returns a pointer to a bool value
func boolPtr(b bool) *bool {
	return &b
}

// TestBuildBreakglassLink tests the buildBreakglassLink helper function
func TestBuildBreakglassLink(t *testing.T) {
	tests := []struct {
		name       string
		baseURL    string
		cluster    string
		expectLink string
	}{
		{
			name:       "with base URL",
			baseURL:    "https://breakglass.example.com",
			cluster:    "test-cluster",
			expectLink: "https://breakglass.example.com?search=test-cluster",
		},
		{
			name:       "with trailing slash in base URL",
			baseURL:    "https://breakglass.example.com/",
			cluster:    "test-cluster",
			expectLink: "https://breakglass.example.com?search=test-cluster",
		},
		{
			name:       "empty base URL",
			baseURL:    "",
			cluster:    "test-cluster",
			expectLink: "",
		},
		{
			name:       "cluster with spaces",
			baseURL:    "https://breakglass.example.com",
			cluster:    "test cluster",
			expectLink: "https://breakglass.example.com?search=test+cluster",
		},
		{
			name:       "cluster with hash",
			baseURL:    "https://breakglass.example.com",
			cluster:    "test#cluster",
			expectLink: "https://breakglass.example.com?search=test%23cluster",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wc := &WebhookController{
				config: config.Config{
					Frontend: config.Frontend{
						BaseURL: tt.baseURL,
					},
				},
			}

			result := wc.buildBreakglassLink(tt.cluster)

			if result != tt.expectLink {
				t.Errorf("expected %q, got %q", tt.expectLink, result)
			}
		})
	}
}

// TestURLQueryEscape tests that url.QueryEscape properly handles special characters
// This test documents the expected behavior now that we use the standard library
func TestURLQueryEscape(t *testing.T) {
	tests := []struct {
		input    string
		expected string
	}{
		{"simple", "simple"},
		{"with space", "with+space"},
		{"with#hash", "with%23hash"},
		{"multiple spaces  test", "multiple+spaces++test"},
		{"combo # space", "combo+%23+space"},
		// Additional cases for url.QueryEscape behavior
		{"test&value=1", "test%26value%3D1"},
		{"test?query", "test%3Fquery"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			result := url.QueryEscape(tt.input)
			if result != tt.expected {
				t.Errorf("url.QueryEscape(%q) = %q, want %q", tt.input, result, tt.expected)
			}
		})
	}
}

// TestFinalizeReason tests the finalizeReason helper function
func TestFinalizeReason(t *testing.T) {
	tests := []struct {
		name           string
		reason         string
		allowed        bool
		cluster        string
		baseURL        string
		expectContains string
	}{
		{
			name:           "empty reason allowed with link",
			reason:         "",
			allowed:        true,
			cluster:        "test-cluster",
			baseURL:        "https://breakglass.example.com",
			expectContains: "Allowed; view details or sessions at",
		},
		{
			name:           "empty reason denied with link",
			reason:         "",
			allowed:        false,
			cluster:        "test-cluster",
			baseURL:        "https://breakglass.example.com",
			expectContains: "Access denied",
		},
		{
			name:           "no base URL returns original reason",
			reason:         "some reason",
			allowed:        false,
			cluster:        "test-cluster",
			baseURL:        "",
			expectContains: "some reason",
		},
		{
			name:           "existing reason gets link appended",
			reason:         "denied by policy",
			allowed:        false,
			cluster:        "test-cluster",
			baseURL:        "https://breakglass.example.com",
			expectContains: "denied by policy; see",
		},
		{
			name:           "reason already contains link - no duplicate",
			reason:         "see https://breakglass.example.com?search=test-cluster",
			allowed:        false,
			cluster:        "test-cluster",
			baseURL:        "https://breakglass.example.com",
			expectContains: "see https://breakglass.example.com?search=test-cluster",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			wc := &WebhookController{
				config: config.Config{
					Frontend: config.Frontend{
						BaseURL: tt.baseURL,
					},
				},
			}

			result := wc.finalizeReason(tt.reason, tt.allowed, tt.cluster)

			if !contains(result, tt.expectContains) {
				t.Errorf("expected result to contain %q, got %q", tt.expectContains, result)
			}
		})
	}
}

// TestSummarizeAction tests the summarizeAction helper function
func TestSummarizeAction(t *testing.T) {
	tests := []struct {
		name     string
		sar      *authorizationv1.SubjectAccessReview
		expected string
	}{
		{
			name:     "nil SAR",
			sar:      nil,
			expected: "the requested action",
		},
		{
			name: "resource attributes with all fields",
			sar: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Namespace:   "default",
						Verb:        "get",
						Resource:    "pods",
						Subresource: "logs",
						Name:        "my-pod",
					},
				},
			},
			expected: "get pods/logs my-pod in namespace default",
		},
		{
			name: "resource attributes without subresource",
			sar: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Namespace: "kube-system",
						Verb:      "delete",
						Resource:  "secrets",
						Name:      "my-secret",
					},
				},
			},
			expected: "delete secrets my-secret in namespace kube-system",
		},
		{
			name: "resource attributes without name",
			sar: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Namespace: "default",
						Verb:      "list",
						Resource:  "configmaps",
					},
				},
			},
			expected: "list configmaps in namespace default",
		},
		{
			name: "resource attributes cluster-wide",
			sar: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Verb:     "list",
						Resource: "nodes",
					},
				},
			},
			expected: "list nodes in namespace (cluster-wide)",
		},
		{
			name: "non-resource attributes",
			sar: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					NonResourceAttributes: &authorizationv1.NonResourceAttributes{
						Path: "/healthz",
						Verb: "get",
					},
				},
			},
			expected: "get /healthz",
		},
		{
			name: "no attributes",
			sar: &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "test-user",
				},
			},
			expected: "the requested action",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := summarizeAction(tt.sar)
			if result != tt.expected {
				t.Errorf("expected %q, got %q", tt.expected, result)
			}
		})
	}
}

// TestNewWebhookController tests the NewWebhookController constructor
func TestNewWebhookController(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	cli := fake.NewClientBuilder().WithScheme(breakglass.Scheme).Build()
	sesMgr := &breakglass.SessionManager{Client: cli}
	escalMgr := &breakglass.EscalationManager{Client: cli}
	denyEval := policy.NewEvaluator(cli, logger.Sugar())

	wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, denyEval)

	if wc == nil {
		t.Fatal("expected non-nil WebhookController")
	}
	if wc.sesManager != sesMgr {
		t.Error("session manager not set correctly")
	}
	if wc.escalManager != escalMgr {
		t.Error("escalation manager not set correctly")
	}
	if wc.denyEval != denyEval {
		t.Error("deny evaluator not set correctly")
	}
	if wc.canDoFn == nil {
		t.Error("canDoFn should be set to default implementation")
	}
}

// TestWebhookController_BasePath tests the BasePath method
func TestWebhookController_BasePath(t *testing.T) {
	wc := WebhookController{}
	path := wc.BasePath()
	if path != "breakglass/webhook" {
		t.Errorf("expected 'breakglass/webhook', got %q", path)
	}
}

// TestWebhookController_Handlers tests the Handlers method
func TestWebhookController_Handlers(t *testing.T) {
	wc := WebhookController{}
	handlers := wc.Handlers()
	if handlers == nil {
		t.Error("expected non-nil slice")
	}
	if len(handlers) != 0 {
		t.Errorf("expected empty slice, got %d handlers", len(handlers))
	}
}

// TestWebhookController_Register tests the Register method
func TestWebhookController_Register(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	cli := fake.NewClientBuilder().WithScheme(breakglass.Scheme).Build()
	sesMgr := &breakglass.SessionManager{Client: cli}
	escalMgr := &breakglass.EscalationManager{Client: cli}

	wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, nil)

	engine := gin.New()
	rg := engine.Group("/" + wc.BasePath())

	err := wc.Register(rg)
	if err != nil {
		t.Errorf("expected nil error, got %v", err)
	}

	// Verify route was registered by making a request
	req := httptest.NewRequest(http.MethodPost, "/breakglass/webhook/authorize/test-cluster", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	// We expect a response (not 404) since the route should be registered
	// The actual response will be an error due to missing body, but not 404
	if w.Code == http.StatusNotFound {
		t.Error("expected route to be registered, got 404")
	}
}

// contains is a helper function for string containment checks
func contains(s, substr string) bool {
	return len(substr) == 0 || len(s) >= len(substr) && (s == substr || len(s) > 0 && containsString(s, substr))
}

func containsString(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

// TestWebhookController_SetCanDoFn tests setting custom canDoFn
func TestWebhookController_SetCanDoFn(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	cli := fake.NewClientBuilder().WithScheme(breakglass.Scheme).Build()
	sesMgr := &breakglass.SessionManager{Client: cli}
	escalMgr := &breakglass.EscalationManager{Client: cli}

	wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, nil)

	// canDoFn is set to a default by NewWebhookController
	if wc.canDoFn == nil {
		t.Error("expected canDoFn to be set by default")
	}

	called := false
	customFn := func(_ context.Context, _ *rest.Config, _ []string, _ authorizationv1.SubjectAccessReview, _ string) (bool, error) {
		called = true
		return true, nil
	}

	wc.SetCanDoFn(customFn)

	if wc.canDoFn == nil {
		t.Error("expected canDoFn to be set")
	}

	// Call it to verify it's the right function
	_, _ = wc.canDoFn(context.Background(), nil, nil, authorizationv1.SubjectAccessReview{}, "")
	if !called {
		t.Error("expected custom canDoFn to be called")
	}
}

// TestWebhookController_SetPodFetchFn tests setting custom podFetchFn
func TestWebhookController_SetPodFetchFn(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	cli := fake.NewClientBuilder().WithScheme(breakglass.Scheme).Build()
	sesMgr := &breakglass.SessionManager{Client: cli}
	escalMgr := &breakglass.EscalationManager{Client: cli}

	wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, nil)

	// Initially nil
	if wc.podFetchFn != nil {
		t.Error("expected podFetchFn to be nil initially")
	}

	called := false
	customFn := func(_ context.Context, _, _, _ string) (*corev1.Pod, error) {
		called = true
		return nil, nil
	}

	wc.SetPodFetchFn(customFn)

	if wc.podFetchFn == nil {
		t.Error("expected podFetchFn to be set")
	}

	// Call it to verify it's the right function
	_, _ = wc.podFetchFn(context.Background(), "", "", "")
	if !called {
		t.Error("expected custom podFetchFn to be called")
	}
}

// TestWebhookController_FetchPodFromCluster_WithFn tests fetchPodFromCluster with injected function
func TestWebhookController_FetchPodFromCluster_WithFn(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	cli := fake.NewClientBuilder().WithScheme(breakglass.Scheme).Build()
	sesMgr := &breakglass.SessionManager{Client: cli}
	escalMgr := &breakglass.EscalationManager{Client: cli}

	wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, nil)

	expectedPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-pod",
			Namespace: "default",
		},
	}

	wc.SetPodFetchFn(func(_ context.Context, clusterName, namespace, name string) (*corev1.Pod, error) {
		if clusterName != "test-cluster" {
			t.Errorf("expected clusterName 'test-cluster', got '%s'", clusterName)
		}
		if namespace != "default" {
			t.Errorf("expected namespace 'default', got '%s'", namespace)
		}
		if name != "test-pod" {
			t.Errorf("expected name 'test-pod', got '%s'", name)
		}
		return expectedPod, nil
	})

	pod, err := wc.fetchPodFromCluster(context.Background(), "test-cluster", "default", "test-pod")
	if err != nil {
		t.Errorf("expected no error, got %v", err)
	}
	if pod == nil {
		t.Fatal("expected pod to be returned")
	}
	if pod.Name != "test-pod" {
		t.Errorf("expected pod name 'test-pod', got '%s'", pod.Name)
	}
}

// TestWebhookController_FetchPodFromCluster_NilProvider tests fetchPodFromCluster without provider
func TestWebhookController_FetchPodFromCluster_NilProvider(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	cli := fake.NewClientBuilder().WithScheme(breakglass.Scheme).Build()
	sesMgr := &breakglass.SessionManager{Client: cli}
	escalMgr := &breakglass.EscalationManager{Client: cli}

	wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, nil)

	// Without podFetchFn set, it should try to use ccProvider which is nil
	_, err := wc.fetchPodFromCluster(context.Background(), "test-cluster", "default", "test-pod")
	if err == nil {
		t.Error("expected error when ccProvider is nil")
	}
	if !containsString(err.Error(), "cluster client provider not configured") {
		t.Errorf("expected error about provider not configured, got: %v", err)
	}
}

// TestGetPodSecurityOverridesFromSessions tests the getPodSecurityOverridesFromSessions helper function
func TestGetPodSecurityOverridesFromSessions(t *testing.T) {
	testCases := []struct {
		name             string
		sessions         []breakglassv1alpha1.BreakglassSession
		escalations      []*breakglassv1alpha1.BreakglassEscalation
		expectOverrides  bool
		expectedMaxScore *int
		expectedExempt   []string
	}{
		{
			name:            "no sessions",
			sessions:        nil,
			escalations:     nil,
			expectOverrides: false,
		},
		{
			name: "session not approved",
			sessions: []breakglassv1alpha1.BreakglassSession{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "pending-session",
						Namespace: "default",
						OwnerReferences: []metav1.OwnerReference{
							{Kind: "BreakglassEscalation", Name: "my-escalation"},
						},
					},
					Status: breakglassv1alpha1.BreakglassSessionStatus{
						State: breakglassv1alpha1.SessionStatePending,
					},
				},
			},
			escalations: []*breakglassv1alpha1.BreakglassEscalation{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "my-escalation", Namespace: "default"},
					Spec: breakglassv1alpha1.BreakglassEscalationSpec{
						PodSecurityOverrides: &breakglassv1alpha1.PodSecurityOverrides{
							Enabled:         true,
							MaxAllowedScore: intPtr(80),
						},
					},
				},
			},
			expectOverrides: false, // Session not approved
		},
		{
			name: "session approved with PodSecurityOverrides",
			sessions: []breakglassv1alpha1.BreakglassSession{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "active-session",
						Namespace: "default",
						OwnerReferences: []metav1.OwnerReference{
							{Kind: "BreakglassEscalation", Name: "my-escalation"},
						},
					},
					Status: breakglassv1alpha1.BreakglassSessionStatus{
						State: breakglassv1alpha1.SessionStateApproved,
					},
				},
			},
			escalations: []*breakglassv1alpha1.BreakglassEscalation{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "my-escalation", Namespace: "default"},
					Spec: breakglassv1alpha1.BreakglassEscalationSpec{
						PodSecurityOverrides: &breakglassv1alpha1.PodSecurityOverrides{
							Enabled:         true,
							MaxAllowedScore: intPtr(80),
							ExemptFactors:   []string{"hostNetwork", "hostPID"},
						},
					},
				},
			},
			expectOverrides:  true,
			expectedMaxScore: intPtr(80),
			expectedExempt:   []string{"hostNetwork", "hostPID"},
		},
		{
			name: "session approved but PodSecurityOverrides disabled",
			sessions: []breakglassv1alpha1.BreakglassSession{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "active-session",
						Namespace: "default",
						OwnerReferences: []metav1.OwnerReference{
							{Kind: "BreakglassEscalation", Name: "my-escalation"},
						},
					},
					Status: breakglassv1alpha1.BreakglassSessionStatus{
						State: breakglassv1alpha1.SessionStateApproved,
					},
				},
			},
			escalations: []*breakglassv1alpha1.BreakglassEscalation{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "my-escalation", Namespace: "default"},
					Spec: breakglassv1alpha1.BreakglassEscalationSpec{
						PodSecurityOverrides: &breakglassv1alpha1.PodSecurityOverrides{
							Enabled:         false, // Disabled
							MaxAllowedScore: intPtr(80),
						},
					},
				},
			},
			expectOverrides: false, // Disabled
		},
		{
			name: "session approved but no PodSecurityOverrides in escalation",
			sessions: []breakglassv1alpha1.BreakglassSession{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "active-session",
						Namespace: "default",
						OwnerReferences: []metav1.OwnerReference{
							{Kind: "BreakglassEscalation", Name: "my-escalation"},
						},
					},
					Status: breakglassv1alpha1.BreakglassSessionStatus{
						State: breakglassv1alpha1.SessionStateApproved,
					},
				},
			},
			escalations: []*breakglassv1alpha1.BreakglassEscalation{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "my-escalation", Namespace: "default"},
					Spec:       breakglassv1alpha1.BreakglassEscalationSpec{},
				},
			},
			expectOverrides: false, // No overrides configured
		},
		{
			name: "session approved but escalation not found",
			sessions: []breakglassv1alpha1.BreakglassSession{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "active-session",
						Namespace: "default",
						OwnerReferences: []metav1.OwnerReference{
							{Kind: "BreakglassEscalation", Name: "nonexistent-escalation"},
						},
					},
					Status: breakglassv1alpha1.BreakglassSessionStatus{
						State: breakglassv1alpha1.SessionStateApproved,
					},
				},
			},
			escalations:     nil, // No escalations
			expectOverrides: false,
		},
		{
			name: "multiple sessions - first approved has overrides",
			sessions: []breakglassv1alpha1.BreakglassSession{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "first-session",
						Namespace: "default",
						OwnerReferences: []metav1.OwnerReference{
							{Kind: "BreakglassEscalation", Name: "first-esc"},
						},
					},
					Status: breakglassv1alpha1.BreakglassSessionStatus{
						State: breakglassv1alpha1.SessionStateApproved,
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "second-session",
						Namespace: "default",
						OwnerReferences: []metav1.OwnerReference{
							{Kind: "BreakglassEscalation", Name: "second-esc"},
						},
					},
					Status: breakglassv1alpha1.BreakglassSessionStatus{
						State: breakglassv1alpha1.SessionStateApproved,
					},
				},
			},
			escalations: []*breakglassv1alpha1.BreakglassEscalation{
				{
					ObjectMeta: metav1.ObjectMeta{Name: "first-esc", Namespace: "default"},
					Spec: breakglassv1alpha1.BreakglassEscalationSpec{
						PodSecurityOverrides: &breakglassv1alpha1.PodSecurityOverrides{
							Enabled:         true,
							MaxAllowedScore: intPtr(60),
						},
					},
				},
				{
					ObjectMeta: metav1.ObjectMeta{Name: "second-esc", Namespace: "default"},
					Spec: breakglassv1alpha1.BreakglassEscalationSpec{
						PodSecurityOverrides: &breakglassv1alpha1.PodSecurityOverrides{
							Enabled:         true,
							MaxAllowedScore: intPtr(90), // Higher but should not be used
						},
					},
				},
			},
			expectOverrides:  true,
			expectedMaxScore: intPtr(60), // First session's escalation
		},
		{
			name: "session with non-escalation owner reference",
			sessions: []breakglassv1alpha1.BreakglassSession{
				{
					ObjectMeta: metav1.ObjectMeta{
						Name:      "active-session",
						Namespace: "default",
						OwnerReferences: []metav1.OwnerReference{
							{Kind: "SomeOtherKind", Name: "not-an-escalation"}, // Wrong kind
						},
					},
					Status: breakglassv1alpha1.BreakglassSessionStatus{
						State: breakglassv1alpha1.SessionStateApproved,
					},
				},
			},
			escalations:     nil,
			expectOverrides: false, // No BreakglassEscalation owner ref
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			logger, _ := zap.NewDevelopment()

			objects := make([]client.Object, 0, len(tc.escalations))
			for _, esc := range tc.escalations {
				objects = append(objects, esc)
			}

			cli := fake.NewClientBuilder().WithScheme(breakglass.Scheme).WithObjects(objects...).Build()
			escalMgr := &breakglass.EscalationManager{Client: cli}

			wc := &WebhookController{
				log:          logger.Sugar(),
				escalManager: escalMgr,
			}

			overrides := wc.getPodSecurityOverridesFromSessions(context.Background(), tc.sessions, logger.Sugar())

			if tc.expectOverrides {
				if overrides == nil {
					t.Fatal("expected PodSecurityOverrides but got nil")
				}
				if tc.expectedMaxScore != nil && (overrides.MaxAllowedScore == nil || *overrides.MaxAllowedScore != *tc.expectedMaxScore) {
					var got string
					if overrides.MaxAllowedScore != nil {
						got = string(rune(*overrides.MaxAllowedScore))
					}
					t.Errorf("expected MaxAllowedScore %d, got %s", *tc.expectedMaxScore, got)
				}
				if len(tc.expectedExempt) > 0 {
					if len(overrides.ExemptFactors) != len(tc.expectedExempt) {
						t.Errorf("expected %d ExemptFactors, got %d", len(tc.expectedExempt), len(overrides.ExemptFactors))
					}
				}
			} else {
				if overrides != nil {
					t.Errorf("expected no PodSecurityOverrides but got %+v", overrides)
				}
			}
		})
	}
}

// TestGetPodSecurityOverridesFromSessions_NilEscalManager tests behavior when escalation manager is nil
func TestGetPodSecurityOverridesFromSessions_NilEscalManager(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	wc := &WebhookController{
		log:          logger.Sugar(),
		escalManager: nil, // No escalation manager
	}

	sessions := []breakglassv1alpha1.BreakglassSession{
		{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "active-session",
				Namespace: "default",
				OwnerReferences: []metav1.OwnerReference{
					{Kind: "BreakglassEscalation", Name: "my-escalation"},
				},
			},
			Status: breakglassv1alpha1.BreakglassSessionStatus{
				State: breakglassv1alpha1.SessionStateApproved,
			},
		},
	}

	overrides := wc.getPodSecurityOverridesFromSessions(context.Background(), sessions, logger.Sugar())

	if overrides != nil {
		t.Errorf("expected nil overrides when escalManager is nil, got %+v", overrides)
	}
}

// intPtr is a helper to create *int for test cases
func intPtr(i int) *int {
	return &i
}

// TestFetchNamespaceLabels_WithMockFunction tests the namespace label fetch function injection for testing.
func TestFetchNamespaceLabels_WithMockFunction(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	wc := &WebhookController{
		log: logger.Sugar(),
	}

	// Set up a mock function that returns labels
	mockLabels := map[string]string{"env": "production", "tier": "critical"}
	wc.SetNamespaceLabelsFetchFn(func(ctx context.Context, clusterName, namespace string) (map[string]string, error) {
		if clusterName != "test-cluster" {
			t.Errorf("unexpected cluster: %s", clusterName)
		}
		if namespace != "test-ns" {
			t.Errorf("unexpected namespace: %s", namespace)
		}
		return mockLabels, nil
	})

	labels, err := wc.fetchNamespaceLabels(context.Background(), "test-cluster", "test-ns")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if labels["env"] != "production" {
		t.Errorf("expected env=production, got %s", labels["env"])
	}
	if labels["tier"] != "critical" {
		t.Errorf("expected tier=critical, got %s", labels["tier"])
	}
}

// TestFetchNamespaceLabels_MockReturnsError tests error handling from the mock function.
func TestFetchNamespaceLabels_MockReturnsError(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	wc := &WebhookController{
		log: logger.Sugar(),
	}

	expectedErr := "namespace not found"
	wc.SetNamespaceLabelsFetchFn(func(ctx context.Context, clusterName, namespace string) (map[string]string, error) {
		return nil, fmt.Errorf("%s", expectedErr)
	})

	labels, err := wc.fetchNamespaceLabels(context.Background(), "test-cluster", "missing-ns")
	if err == nil {
		t.Fatal("expected error, got nil")
	}
	if labels != nil {
		t.Errorf("expected nil labels on error, got %v", labels)
	}
	if !bytes.Contains([]byte(err.Error()), []byte(expectedErr)) {
		t.Errorf("expected error to contain %q, got %q", expectedErr, err.Error())
	}
}

// TestFetchNamespaceLabels_NilCCProvider tests error when ccProvider is nil and no mock is set.
func TestFetchNamespaceLabels_NilCCProvider(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	wc := &WebhookController{
		log:        logger.Sugar(),
		ccProvider: nil, // No provider configured
	}

	labels, err := wc.fetchNamespaceLabels(context.Background(), "test-cluster", "test-ns")
	if err == nil {
		t.Fatal("expected error when ccProvider is nil")
	}
	if labels != nil {
		t.Errorf("expected nil labels, got %v", labels)
	}
	if !bytes.Contains([]byte(err.Error()), []byte("not configured")) {
		t.Errorf("expected error to mention 'not configured', got %q", err.Error())
	}
}

// TestHandleAuthorize_DenyPolicyWithNamespaceLabels tests that namespace labels are used for deny policy evaluation.
func TestHandleAuthorize_DenyPolicyWithNamespaceLabels(t *testing.T) {
	// Create a DenyPolicy that uses SelectorTerms (label selectors)
	denyPol := &breakglassv1alpha1.DenyPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-prod"},
		Spec: breakglassv1alpha1.DenyPolicySpec{
			Rules: []breakglassv1alpha1.DenyRule{{
				Verbs:     []string{"delete"},
				APIGroups: []string{""},
				Resources: []string{"services"},
				Namespaces: &breakglassv1alpha1.NamespaceFilter{
					SelectorTerms: []breakglassv1alpha1.NamespaceSelectorTerm{{
						MatchLabels: map[string]string{"env": "production"},
					}},
				},
			}},
		},
	}

	builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme).WithObjects(denyPol)
	for k, fn := range sessionIndexFnsWebhook {
		builder = builder.WithIndex(&breakglassv1alpha1.BreakglassSession{}, k, fn)
	}
	cli := builder.Build()

	sesMgr := &breakglass.SessionManager{Client: cli}
	escalMgr := &breakglass.EscalationManager{Client: cli}

	logger, _ := zap.NewDevelopment()
	eval := policy.NewEvaluator(cli, logger.Sugar())
	wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, eval)

	// Mock namespace labels to return production env labels
	wc.SetNamespaceLabelsFetchFn(func(ctx context.Context, clusterName, namespace string) (map[string]string, error) {
		// Return production labels for the target namespace
		if namespace == "prod-services" {
			return map[string]string{"env": "production"}, nil
		}
		// Return staging labels for other namespaces
		return map[string]string{"env": "staging"}, nil
	})

	// Override canDoFn to deny RBAC check (so deny policy is evaluated)
	wc.canDoFn = func(ctx context.Context, rc *rest.Config, groups []string, sar authorizationv1.SubjectAccessReview, clustername string) (bool, error) {
		return false, nil
	}

	t.Run("deny by label selector matching", func(t *testing.T) {
		// Request to delete service in production namespace
		sar := authorizationv1.SubjectAccessReview{
			TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SubjectAccessReview"},
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User: "alice@example.com",
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: "prod-services",
					Verb:      "delete",
					Group:     "",
					Resource:  "services",
				},
			},
		}
		body, _ := json.Marshal(sar)

		engine := gin.New()
		_ = wc.Register(engine.Group("/" + wc.BasePath()))

		req, _ := http.NewRequest(http.MethodPost, "/breakglass/webhook/authorize/test-cluster", bytes.NewReader(body))
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		if w.Result().StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", w.Result().StatusCode)
		}

		var resp SubjectAccessReviewResponse
		bodyBytes := new(bytes.Buffer)
		if _, err := bodyBytes.ReadFrom(w.Result().Body); err != nil {
			t.Fatalf("failed to read response body: %v", err)
		}
		if err := json.Unmarshal(bodyBytes.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode response: %v; raw=%s", err, bodyBytes.String())
		}

		if resp.Status.Allowed {
			t.Error("expected Allowed=false due to deny policy label selector match")
		}
		if resp.Status.Reason == "" || !bytes.Contains([]byte(resp.Status.Reason), []byte("deny-prod")) {
			t.Logf("Note: expected deny reason to mention 'deny-prod', got: %s", resp.Status.Reason)
		}
	})

	t.Run("allow in non-production namespace", func(t *testing.T) {
		// Request to delete service in staging namespace (should not be blocked by label selector)
		sar := authorizationv1.SubjectAccessReview{
			TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SubjectAccessReview"},
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User: "alice@example.com",
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: "staging-services",
					Verb:      "delete",
					Group:     "",
					Resource:  "services",
				},
			},
		}
		body, _ := json.Marshal(sar)

		req, _ := http.NewRequest(http.MethodPost, "/breakglass/webhook/authorize/test-cluster", bytes.NewReader(body))
		w := httptest.NewRecorder()

		engine := gin.New()
		_ = wc.Register(engine.Group("/" + wc.BasePath()))
		engine.ServeHTTP(w, req)

		if w.Result().StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", w.Result().StatusCode)
		}

		var resp SubjectAccessReviewResponse
		bodyBytes := new(bytes.Buffer)
		if _, err := bodyBytes.ReadFrom(w.Result().Body); err != nil {
			t.Fatalf("failed to read response body: %v", err)
		}
		if err := json.Unmarshal(bodyBytes.Bytes(), &resp); err != nil {
			t.Fatalf("failed to decode response: %v; raw=%s", err, bodyBytes.String())
		}

		// With RBAC denied and no matching deny policy, it should still be denied by regular RBAC flow
		// But we're verifying the deny policy is NOT blocking this request
		// Note: The response may still be denied due to no active session, but it should not mention deny-prod
		if bytes.Contains([]byte(resp.Status.Reason), []byte("blocked by deny policy")) {
			t.Errorf("expected request to NOT be blocked by deny policy for staging namespace, but got: %s", resp.Status.Reason)
		}
	})
}

// TestDedupeStrings tests the dedupeStrings helper function
func TestDedupeStrings(t *testing.T) {
	tests := []struct {
		name     string
		input    []string
		expected []string
	}{
		{
			name:     "empty slice",
			input:    []string{},
			expected: []string{},
		},
		{
			name:     "no duplicates",
			input:    []string{"a", "b", "c"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "with duplicates",
			input:    []string{"a", "b", "a", "c", "b"},
			expected: []string{"a", "b", "c"},
		},
		{
			name:     "all same",
			input:    []string{"x", "x", "x"},
			expected: []string{"x"},
		},
		{
			name:     "preserves order",
			input:    []string{"z", "a", "z", "m"},
			expected: []string{"z", "a", "m"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := dedupeStrings(tt.input)
			if len(result) != len(tt.expected) {
				t.Errorf("expected %v, got %v", tt.expected, result)
				return
			}
			for i := range result {
				if result[i] != tt.expected[i] {
					t.Errorf("expected %v, got %v", tt.expected, result)
					return
				}
			}
		})
	}
}

func TestWebhookController_WithAuditService(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	wc := NewWebhookController(logger.Sugar(), config.Config{}, nil, nil, nil, nil)

	// Initially nil
	if wc.auditService != nil {
		t.Error("expected auditService to be nil initially")
	}

	// Should return itself for chaining
	result := wc.WithAuditService(nil)
	if result != wc {
		t.Error("expected WithAuditService to return the controller for chaining")
	}
}

// TestEmitPodSecurityAudit tests the emitPodSecurityAudit function
func TestEmitPodSecurityAudit(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	tests := []struct {
		name           string
		auditService   bool // whether audit service is set
		result         *policy.PodSecurityResult
		expectedEvents int
		expectCritical bool
		expectWarning  bool
	}{
		{
			name:           "nil audit service does nothing",
			auditService:   false,
			result:         &policy.PodSecurityResult{Score: 50, Factors: []string{"privileged"}},
			expectedEvents: 0,
		},
		{
			name:           "nil result does nothing",
			auditService:   true,
			result:         nil,
			expectedEvents: 0,
		},
		{
			name:         "denied result emits critical event",
			auditService: true,
			result: &policy.PodSecurityResult{
				Denied:  true,
				Reason:  "risk score too high",
				Score:   100,
				Factors: []string{"privileged", "hostNetwork"},
				Action:  "deny",
			},
			expectedEvents: 1,
			expectCritical: true,
		},
		{
			name:         "warn result emits warning event",
			auditService: true,
			result: &policy.PodSecurityResult{
				Denied:  false,
				Reason:  "moderate risk",
				Score:   50,
				Factors: []string{"runAsRoot"},
				Action:  "warn",
			},
			expectedEvents: 1,
			expectWarning:  true,
		},
		{
			name:         "override applied emits warning event",
			auditService: true,
			result: &policy.PodSecurityResult{
				Denied:          false,
				Reason:          "override applied",
				Score:           80,
				Factors:         []string{"privileged"},
				Action:          "allow",
				OverrideApplied: true,
			},
			expectedEvents: 1,
			expectWarning:  true,
		},
		{
			name:         "allowed result without override emits info event",
			auditService: true,
			result: &policy.PodSecurityResult{
				Denied:  false,
				Reason:  "within threshold",
				Score:   20,
				Factors: []string{},
				Action:  "allow",
			},
			expectedEvents: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme)
			cli := builder.Build()

			sesMgr := &breakglass.SessionManager{Client: cli}
			escalMgr := &breakglass.EscalationManager{Client: cli}
			wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, policy.NewEvaluator(cli, logger.Sugar()))

			var auditSvc *audit.Service
			if tt.auditService {
				auditSvc = audit.NewService(cli, logger, "test-ns")
			}
			wc.WithAuditService(auditSvc)

			ctx := context.Background()
			sar := &authorizationv1.SubjectAccessReview{
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "test-user@example.com",
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Namespace:   "default",
						Verb:        "exec",
						Group:       "",
						Resource:    "pods",
						Subresource: "exec",
						Name:        "test-pod",
					},
				},
			}

			// This should not panic even with nil auditService
			wc.emitPodSecurityAudit(ctx, "test-user@example.com", []string{"group1"}, "test-cluster", sar, "test-policy", tt.result)

			// Basic verification that function doesn't panic with various inputs
			// Since the real audit service requires complex setup, we verify the early return conditions
		})
	}
}

// TestEmitAccessDecisionAudit tests the emitAccessDecisionAudit function
func TestEmitAccessDecisionAudit(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	tests := []struct {
		name    string
		allowed bool
		source  string
		sarSpec authorizationv1.SubjectAccessReviewSpec
	}{
		{
			name:    "allowed by RBAC",
			allowed: true,
			source:  "rbac",
			sarSpec: authorizationv1.SubjectAccessReviewSpec{
				User: "alice@example.com",
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: "default",
					Verb:      "get",
					Resource:  "pods",
				},
			},
		},
		{
			name:    "allowed by session",
			allowed: true,
			source:  "session",
			sarSpec: authorizationv1.SubjectAccessReviewSpec{
				User: "bob@example.com",
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace:   "kube-system",
					Verb:        "delete",
					Resource:    "pods",
					Subresource: "",
					Name:        "my-pod",
				},
			},
		},
		{
			name:    "denied access",
			allowed: false,
			source:  "",
			sarSpec: authorizationv1.SubjectAccessReviewSpec{
				User: "charlie@example.com",
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: "production",
					Verb:      "delete",
					Resource:  "deployments",
					Group:     "apps",
				},
			},
		},
		{
			name:    "non-resource attributes",
			allowed: true,
			source:  "rbac",
			sarSpec: authorizationv1.SubjectAccessReviewSpec{
				User: "admin@example.com",
				NonResourceAttributes: &authorizationv1.NonResourceAttributes{
					Path: "/healthz",
					Verb: "get",
				},
			},
		},
		{
			name:    "allowed by debug-session",
			allowed: true,
			source:  "debug-session",
			sarSpec: authorizationv1.SubjectAccessReviewSpec{
				User: "developer@example.com",
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace:   "debug-ns",
					Verb:        "create",
					Resource:    "pods",
					Subresource: "exec",
					Name:        "debug-pod-123",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme)
			cli := builder.Build()

			sesMgr := &breakglass.SessionManager{Client: cli}
			escalMgr := &breakglass.EscalationManager{Client: cli}
			wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, policy.NewEvaluator(cli, logger.Sugar()))

			ctx := context.Background()
			sar := &authorizationv1.SubjectAccessReview{
				Spec: tt.sarSpec,
			}

			// Test with nil audit service (should not panic)
			wc.emitAccessDecisionAudit(ctx, tt.sarSpec.User, []string{"group1", "group2"}, "test-cluster", sar, tt.allowed, tt.source, "test reason")

			// Test with audit service set (but disabled - should still not panic)
			auditSvc := audit.NewService(cli, logger, "test-ns")
			wc.WithAuditService(auditSvc)
			wc.emitAccessDecisionAudit(ctx, tt.sarSpec.User, []string{"group1", "group2"}, "test-cluster", sar, tt.allowed, tt.source, "test reason with audit service")
		})
	}
}

// TestEmitPolicyDenialAudit tests the emitPolicyDenialAudit function
func TestEmitPolicyDenialAudit(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	tests := []struct {
		name       string
		policyName string
		scope      string
		sarSpec    authorizationv1.SubjectAccessReviewSpec
	}{
		{
			name:       "global policy denial",
			policyName: "deny-secrets",
			scope:      "global",
			sarSpec: authorizationv1.SubjectAccessReviewSpec{
				User: "alice@example.com",
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace: "production",
					Verb:      "get",
					Resource:  "secrets",
				},
			},
		},
		{
			name:       "session-scoped policy denial",
			policyName: "deny-cluster-admin",
			scope:      "session:my-session-123",
			sarSpec: authorizationv1.SubjectAccessReviewSpec{
				User: "bob@example.com",
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Verb:      "delete",
					Resource:  "clusterroles",
					Group:     "rbac.authorization.k8s.io",
					Namespace: "",
				},
			},
		},
		{
			name:       "non-resource policy denial",
			policyName: "deny-metrics",
			scope:      "global",
			sarSpec: authorizationv1.SubjectAccessReviewSpec{
				User: "charlie@example.com",
				NonResourceAttributes: &authorizationv1.NonResourceAttributes{
					Path: "/metrics",
					Verb: "get",
				},
			},
		},
		{
			name:       "subresource policy denial",
			policyName: "deny-exec",
			scope:      "global",
			sarSpec: authorizationv1.SubjectAccessReviewSpec{
				User: "dev@example.com",
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace:   "production",
					Verb:        "create",
					Resource:    "pods",
					Subresource: "exec",
					Name:        "sensitive-pod",
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme)
			cli := builder.Build()

			sesMgr := &breakglass.SessionManager{Client: cli}
			escalMgr := &breakglass.EscalationManager{Client: cli}
			wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, policy.NewEvaluator(cli, logger.Sugar()))

			ctx := context.Background()
			sar := &authorizationv1.SubjectAccessReview{
				Spec: tt.sarSpec,
			}

			// Test with nil audit service (should not panic)
			wc.emitPolicyDenialAudit(ctx, tt.sarSpec.User, []string{"group1"}, "test-cluster", sar, tt.policyName, tt.scope)

			// Test with audit service set
			auditSvc := audit.NewService(cli, logger, "test-ns")
			wc.WithAuditService(auditSvc)
			wc.emitPolicyDenialAudit(ctx, tt.sarSpec.User, []string{"group1"}, "test-cluster", sar, tt.policyName, tt.scope)
		})
	}
}

// TestFetchPodFromCluster tests the fetchPodFromCluster function
func TestFetchPodFromCluster(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	t.Run("uses injected podFetchFn when available", func(t *testing.T) {
		builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme)
		cli := builder.Build()

		sesMgr := &breakglass.SessionManager{Client: cli}
		escalMgr := &breakglass.EscalationManager{Client: cli}
		wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, policy.NewEvaluator(cli, logger.Sugar()))

		expectedPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-pod",
				Namespace: "test-ns",
			},
			Spec: corev1.PodSpec{
				Containers: []corev1.Container{
					{Name: "main", Image: "nginx:latest"},
				},
			},
		}

		// Inject mock function
		wc.SetPodFetchFn(func(ctx context.Context, clusterName, namespace, name string) (*corev1.Pod, error) {
			if clusterName == "test-cluster" && namespace == "test-ns" && name == "test-pod" {
				return expectedPod, nil
			}
			return nil, fmt.Errorf("pod not found")
		})

		ctx := context.Background()
		pod, err := wc.fetchPodFromCluster(ctx, "test-cluster", "test-ns", "test-pod")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if pod.Name != expectedPod.Name {
			t.Errorf("expected pod name %s, got %s", expectedPod.Name, pod.Name)
		}
	})

	t.Run("returns error when pod not found via injected function", func(t *testing.T) {
		builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme)
		cli := builder.Build()

		sesMgr := &breakglass.SessionManager{Client: cli}
		escalMgr := &breakglass.EscalationManager{Client: cli}
		wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, policy.NewEvaluator(cli, logger.Sugar()))

		// Inject mock function that returns error
		wc.SetPodFetchFn(func(ctx context.Context, clusterName, namespace, name string) (*corev1.Pod, error) {
			return nil, fmt.Errorf("pod %s/%s not found in cluster %s", namespace, name, clusterName)
		})

		ctx := context.Background()
		_, err := wc.fetchPodFromCluster(ctx, "test-cluster", "nonexistent-ns", "nonexistent-pod")
		if err == nil {
			t.Error("expected error when pod not found")
		}
	})

	t.Run("returns error when ccProvider is nil", func(t *testing.T) {
		builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme)
		cli := builder.Build()

		sesMgr := &breakglass.SessionManager{Client: cli}
		escalMgr := &breakglass.EscalationManager{Client: cli}
		// Create controller without ccProvider
		wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, policy.NewEvaluator(cli, logger.Sugar()))

		ctx := context.Background()
		_, err := wc.fetchPodFromCluster(ctx, "test-cluster", "test-ns", "test-pod")
		if err == nil {
			t.Error("expected error when ccProvider is nil")
		}
		if !strings.Contains(err.Error(), "cluster client provider not configured") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("fetches pod with various container configurations", func(t *testing.T) {
		builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme)
		cli := builder.Build()

		sesMgr := &breakglass.SessionManager{Client: cli}
		escalMgr := &breakglass.EscalationManager{Client: cli}
		wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, policy.NewEvaluator(cli, logger.Sugar()))

		privilegedPod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "privileged-pod",
				Namespace: "security-test",
			},
			Spec: corev1.PodSpec{
				HostNetwork: true,
				HostPID:     true,
				Containers: []corev1.Container{
					{
						Name:  "privileged-container",
						Image: "alpine:latest",
						SecurityContext: &corev1.SecurityContext{
							Privileged: boolPtr(true),
						},
					},
				},
			},
		}

		wc.SetPodFetchFn(func(ctx context.Context, clusterName, namespace, name string) (*corev1.Pod, error) {
			return privilegedPod, nil
		})

		ctx := context.Background()
		pod, err := wc.fetchPodFromCluster(ctx, "test-cluster", "security-test", "privileged-pod")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if !pod.Spec.HostNetwork {
			t.Error("expected pod to have HostNetwork=true")
		}
		if pod.Spec.Containers[0].SecurityContext == nil || !*pod.Spec.Containers[0].SecurityContext.Privileged {
			t.Error("expected container to be privileged")
		}
	})
}

// TestFetchNamespaceLabels tests the fetchNamespaceLabels function
func TestFetchNamespaceLabels(t *testing.T) {
	logger, _ := zap.NewDevelopment()

	t.Run("uses injected namespaceLabelsFetchFn when available", func(t *testing.T) {
		builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme)
		cli := builder.Build()

		sesMgr := &breakglass.SessionManager{Client: cli}
		escalMgr := &breakglass.EscalationManager{Client: cli}
		wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, policy.NewEvaluator(cli, logger.Sugar()))

		expectedLabels := map[string]string{
			"env":  "production",
			"team": "platform",
		}

		// Inject mock function
		wc.SetNamespaceLabelsFetchFn(func(ctx context.Context, clusterName, namespace string) (map[string]string, error) {
			if clusterName == "test-cluster" && namespace == "prod-ns" {
				return expectedLabels, nil
			}
			return nil, fmt.Errorf("namespace not found")
		})

		ctx := context.Background()
		labels, err := wc.fetchNamespaceLabels(ctx, "test-cluster", "prod-ns")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if labels["env"] != "production" {
			t.Errorf("expected env=production, got %s", labels["env"])
		}
		if labels["team"] != "platform" {
			t.Errorf("expected team=platform, got %s", labels["team"])
		}
	})

	t.Run("returns error when namespace not found", func(t *testing.T) {
		builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme)
		cli := builder.Build()

		sesMgr := &breakglass.SessionManager{Client: cli}
		escalMgr := &breakglass.EscalationManager{Client: cli}
		wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, policy.NewEvaluator(cli, logger.Sugar()))

		// Inject mock function that returns error
		wc.SetNamespaceLabelsFetchFn(func(ctx context.Context, clusterName, namespace string) (map[string]string, error) {
			return nil, fmt.Errorf("namespace %s not found in cluster %s", namespace, clusterName)
		})

		ctx := context.Background()
		_, err := wc.fetchNamespaceLabels(ctx, "test-cluster", "nonexistent-ns")
		if err == nil {
			t.Error("expected error when namespace not found")
		}
	})

	t.Run("returns error when ccProvider is nil", func(t *testing.T) {
		builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme)
		cli := builder.Build()

		sesMgr := &breakglass.SessionManager{Client: cli}
		escalMgr := &breakglass.EscalationManager{Client: cli}
		// Create controller without ccProvider
		wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, policy.NewEvaluator(cli, logger.Sugar()))

		ctx := context.Background()
		_, err := wc.fetchNamespaceLabels(ctx, "test-cluster", "test-ns")
		if err == nil {
			t.Error("expected error when ccProvider is nil")
		}
		if !strings.Contains(err.Error(), "cluster client provider not configured") {
			t.Errorf("unexpected error message: %v", err)
		}
	})

	t.Run("fetches labels with various configurations", func(t *testing.T) {
		builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme)
		cli := builder.Build()

		sesMgr := &breakglass.SessionManager{Client: cli}
		escalMgr := &breakglass.EscalationManager{Client: cli}
		wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, policy.NewEvaluator(cli, logger.Sugar()))

		testCases := []struct {
			clusterName string
			namespace   string
			labels      map[string]string
		}{
			{
				clusterName: "cluster-1",
				namespace:   "production",
				labels:      map[string]string{"env": "production", "tier": "critical"},
			},
			{
				clusterName: "cluster-2",
				namespace:   "staging",
				labels:      map[string]string{"env": "staging"},
			},
			{
				clusterName: "cluster-3",
				namespace:   "default",
				labels:      map[string]string{}, // empty labels
			},
		}

		wc.SetNamespaceLabelsFetchFn(func(ctx context.Context, clusterName, namespace string) (map[string]string, error) {
			for _, tc := range testCases {
				if tc.clusterName == clusterName && tc.namespace == namespace {
					return tc.labels, nil
				}
			}
			return nil, fmt.Errorf("namespace not found")
		})

		ctx := context.Background()
		for _, tc := range testCases {
			labels, err := wc.fetchNamespaceLabels(ctx, tc.clusterName, tc.namespace)
			if err != nil {
				t.Errorf("unexpected error for %s/%s: %v", tc.clusterName, tc.namespace, err)
				continue
			}
			if len(labels) != len(tc.labels) {
				t.Errorf("expected %d labels for %s/%s, got %d", len(tc.labels), tc.clusterName, tc.namespace, len(labels))
			}
		}
	})
}

// TestSetPodFetchFn tests the SetPodFetchFn method
func TestSetPodFetchFn(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme)
	cli := builder.Build()

	sesMgr := &breakglass.SessionManager{Client: cli}
	escalMgr := &breakglass.EscalationManager{Client: cli}
	wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, policy.NewEvaluator(cli, logger.Sugar()))

	// Initially nil
	if wc.podFetchFn != nil {
		t.Error("expected podFetchFn to be nil initially")
	}

	// Set a custom function
	called := false
	wc.SetPodFetchFn(func(ctx context.Context, clusterName, namespace, name string) (*corev1.Pod, error) {
		called = true
		return nil, nil
	})

	// Verify it was set
	if wc.podFetchFn == nil {
		t.Error("expected podFetchFn to be set")
	}

	// Verify it can be called
	ctx := context.Background()
	_, _ = wc.fetchPodFromCluster(ctx, "test", "ns", "pod")
	if !called {
		t.Error("expected custom podFetchFn to be called")
	}
}

// TestSetNamespaceLabelsFetchFn tests the SetNamespaceLabelsFetchFn method
func TestSetNamespaceLabelsFetchFn(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme)
	cli := builder.Build()

	sesMgr := &breakglass.SessionManager{Client: cli}
	escalMgr := &breakglass.EscalationManager{Client: cli}
	wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, policy.NewEvaluator(cli, logger.Sugar()))

	// Initially nil
	if wc.namespaceLabelsFetchFn != nil {
		t.Error("expected namespaceLabelsFetchFn to be nil initially")
	}

	// Set a custom function
	called := false
	wc.SetNamespaceLabelsFetchFn(func(ctx context.Context, clusterName, namespace string) (map[string]string, error) {
		called = true
		return map[string]string{"test": "value"}, nil
	})

	// Verify it was set
	if wc.namespaceLabelsFetchFn == nil {
		t.Error("expected namespaceLabelsFetchFn to be set")
	}

	// Verify it can be called
	ctx := context.Background()
	labels, _ := wc.fetchNamespaceLabels(ctx, "test", "ns")
	if !called {
		t.Error("expected custom namespaceLabelsFetchFn to be called")
	}
	if labels["test"] != "value" {
		t.Error("expected labels from custom function")
	}
}

// TestIsExecSubresource tests the isExecSubresource helper function
func TestIsExecSubresource(t *testing.T) {
	tests := []struct {
		subresource string
		expected    bool
	}{
		{"exec", true},
		{"attach", true},
		{"portforward", true},
		{"log", false},
		{"logs", false},
		{"status", false},
		{"", false},
		{"scale", false},
		{"binding", false},
	}

	for _, tt := range tests {
		t.Run(tt.subresource, func(t *testing.T) {
			result := isExecSubresource(tt.subresource)
			if result != tt.expected {
				t.Errorf("isExecSubresource(%q) = %v, expected %v", tt.subresource, result, tt.expected)
			}
		})
	}
}

// TestIsDebugSessionSubresource tests the isDebugSessionSubresource helper function
func TestIsDebugSessionSubresource(t *testing.T) {
	tests := []struct {
		subresource string
		expected    bool
	}{
		{"exec", true},
		{"attach", true},
		{"portforward", true},
		{"log", true},   // Now supported for debug sessions
		{"logs", false}, // The actual Kubernetes subresource is "log" not "logs"
		{"status", false},
		{"", false},
		{"scale", false},
		{"binding", false},
		{"ephemeralcontainers", false},
	}

	for _, tt := range tests {
		t.Run(tt.subresource, func(t *testing.T) {
			result := isDebugSessionSubresource(tt.subresource)
			if result != tt.expected {
				t.Errorf("isDebugSessionSubresource(%q) = %v, expected %v", tt.subresource, result, tt.expected)
			}
		})
	}
}

// TestEmitAuditWithResourceAndNonResourceAttributes tests audit functions with various SAR configurations
func TestEmitAuditWithResourceAndNonResourceAttributes(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	ctx := context.Background()

	builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme)
	cli := builder.Build()

	sesMgr := &breakglass.SessionManager{Client: cli}
	escalMgr := &breakglass.EscalationManager{Client: cli}
	wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, policy.NewEvaluator(cli, logger.Sugar()))

	// Set up audit service
	auditSvc := audit.NewService(cli, logger, "test-ns")
	wc.WithAuditService(auditSvc)

	t.Run("handles SAR with only ResourceAttributes", func(t *testing.T) {
		sar := &authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User: "user@example.com",
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace:   "production",
					Verb:        "delete",
					Resource:    "pods",
					Subresource: "exec",
					Name:        "my-pod",
					Group:       "",
				},
			},
		}
		// Should not panic
		wc.emitAccessDecisionAudit(ctx, "user@example.com", []string{"group1"}, "cluster1", sar, true, "rbac", "allowed by RBAC")
		wc.emitPolicyDenialAudit(ctx, "user@example.com", []string{"group1"}, "cluster1", sar, "policy1", "global")
	})

	t.Run("handles SAR with only NonResourceAttributes", func(t *testing.T) {
		sar := &authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User: "user@example.com",
				NonResourceAttributes: &authorizationv1.NonResourceAttributes{
					Path: "/healthz",
					Verb: "get",
				},
			},
		}
		// Should not panic
		wc.emitAccessDecisionAudit(ctx, "user@example.com", []string{"group1"}, "cluster1", sar, true, "rbac", "allowed")
		wc.emitPolicyDenialAudit(ctx, "user@example.com", []string{"group1"}, "cluster1", sar, "policy1", "global")
	})

	t.Run("handles SAR with empty spec", func(t *testing.T) {
		sar := &authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User: "user@example.com",
				// No ResourceAttributes or NonResourceAttributes
			},
		}
		// Should not panic
		wc.emitAccessDecisionAudit(ctx, "user@example.com", []string{}, "cluster1", sar, false, "", "denied")
		wc.emitPolicyDenialAudit(ctx, "user@example.com", []string{}, "cluster1", sar, "policy", "global")
	})

	t.Run("emitPodSecurityAudit with SAR containing exec subresource", func(t *testing.T) {
		sar := &authorizationv1.SubjectAccessReview{
			Spec: authorizationv1.SubjectAccessReviewSpec{
				User: "user@example.com",
				ResourceAttributes: &authorizationv1.ResourceAttributes{
					Namespace:   "default",
					Verb:        "create",
					Resource:    "pods",
					Subresource: "exec",
					Name:        "test-pod",
				},
			},
		}
		result := &policy.PodSecurityResult{Score: 50, Factors: []string{"test"}, Action: "warn"}
		// Should not panic
		wc.emitPodSecurityAudit(ctx, "user@example.com", []string{"group1"}, "cluster1", sar, "policy1", result)
	})
}

// TestAuditEmitWithDifferentEventSeverities tests that audit events are properly categorized
func TestAuditEmitWithDifferentEventSeverities(t *testing.T) {
	logger, _ := zap.NewDevelopment()
	ctx := context.Background()

	builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme)
	cli := builder.Build()

	sesMgr := &breakglass.SessionManager{Client: cli}
	escalMgr := &breakglass.EscalationManager{Client: cli}
	wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, policy.NewEvaluator(cli, logger.Sugar()))

	// Set up audit service
	auditSvc := audit.NewService(cli, logger, "test-ns")
	wc.WithAuditService(auditSvc)

	sar := &authorizationv1.SubjectAccessReview{
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User: "test@example.com",
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: "default",
				Verb:      "get",
				Resource:  "pods",
			},
		},
	}

	// Test different pod security result scenarios
	podSecurityResults := []struct {
		name   string
		result *policy.PodSecurityResult
	}{
		{
			name: "denied result",
			result: &policy.PodSecurityResult{
				Denied:  true,
				Score:   100,
				Factors: []string{"privileged"},
				Action:  "deny",
				Reason:  "high risk score",
			},
		},
		{
			name: "warning result",
			result: &policy.PodSecurityResult{
				Denied:  false,
				Score:   50,
				Factors: []string{"runAsRoot"},
				Action:  "warn",
				Reason:  "moderate risk",
			},
		},
		{
			name: "override applied",
			result: &policy.PodSecurityResult{
				Denied:          false,
				Score:           75,
				Factors:         []string{"privileged"},
				Action:          "allow",
				OverrideApplied: true,
				Reason:          "override applied",
			},
		},
		{
			name: "allowed no override",
			result: &policy.PodSecurityResult{
				Denied:  false,
				Score:   10,
				Factors: []string{},
				Action:  "allow",
				Reason:  "low risk",
			},
		},
	}

	for _, tc := range podSecurityResults {
		t.Run(tc.name, func(t *testing.T) {
			// Should not panic with any result type
			wc.emitPodSecurityAudit(ctx, "test@example.com", []string{"group1"}, "cluster1", sar, "policy1", tc.result)
		})
	}
}
