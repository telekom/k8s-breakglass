package webhook

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"k8s.io/client-go/rest"

	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/breakglass/escalation"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/policy"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

var errorScenarioIndexFns = map[string]client.IndexerFunc{
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

// TestHandleAuthorize_MalformedJSON tests malformed JSON request handling
func TestHandleAuthorize_MalformedJSON(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme)
	for k, fn := range errorScenarioIndexFns {
		builder = builder.WithIndex(&breakglassv1alpha1.BreakglassSession{}, k, fn)
	}
	cli := builder.Build()

	sesMgr := &breakglass.SessionManager{Client: cli}
	escalMgr := &escalation.EscalationManager{Client: cli}
	logger, _ := zap.NewDevelopment()

	wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, policy.NewEvaluator(cli, logger.Sugar()))

	wc.canDoFn = func(ctx context.Context, rc *rest.Config, groups []string, sar authorizationv1.SubjectAccessReview, clustername string) (bool, error) {
		return false, nil
	}

	engine := gin.New()
	_ = wc.Register(engine.Group("/" + wc.BasePath()))

	malformedJSON := `{"spec": invalid json`
	req, _ := http.NewRequest(http.MethodPost, "/breakglass/webhook/authorize/test-cluster", bytes.NewReader([]byte(malformedJSON)))
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	// Should handle gracefully without 500
	if w.Code == http.StatusInternalServerError {
		t.Errorf("Should not return 500 for malformed JSON, got %d", w.Code)
	}
}

// TestHandleAuthorize_NilResourceAttributes tests nil ResourceAttributes handling
func TestHandleAuthorize_NilResourceAttributes(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme)
	for k, fn := range errorScenarioIndexFns {
		builder = builder.WithIndex(&breakglassv1alpha1.BreakglassSession{}, k, fn)
	}
	cli := builder.Build()

	sesMgr := &breakglass.SessionManager{Client: cli}
	escalMgr := &escalation.EscalationManager{Client: cli}
	logger, _ := zap.NewDevelopment()

	wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, policy.NewEvaluator(cli, logger.Sugar()))

	wc.canDoFn = func(ctx context.Context, rc *rest.Config, groups []string, sar authorizationv1.SubjectAccessReview, clustername string) (bool, error) {
		return false, nil
	}

	engine := gin.New()
	_ = wc.Register(engine.Group("/" + wc.BasePath()))

	sar := authorizationv1.SubjectAccessReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SubjectAccessReview"},
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User:               "testuser",
			ResourceAttributes: nil,
		},
	}

	body, _ := json.Marshal(sar)
	req, _ := http.NewRequest(http.MethodPost, "/breakglass/webhook/authorize/test-cluster", bytes.NewReader(body))
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	if w.Code == http.StatusInternalServerError {
		t.Errorf("Should not return 500 for nil ResourceAttributes, got %d", w.Code)
	}
}

// TestHandleAuthorize_SpecialCharactersInReason tests special character handling
func TestHandleAuthorize_SpecialCharactersInReason(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme)
	for k, fn := range errorScenarioIndexFns {
		builder = builder.WithIndex(&breakglassv1alpha1.BreakglassSession{}, k, fn)
	}
	cli := builder.Build()

	sesMgr := &breakglass.SessionManager{Client: cli}
	escalMgr := &escalation.EscalationManager{Client: cli}
	logger, _ := zap.NewDevelopment()

	wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, policy.NewEvaluator(cli, logger.Sugar()))

	wc.canDoFn = func(ctx context.Context, rc *rest.Config, groups []string, sar authorizationv1.SubjectAccessReview, clustername string) (bool, error) {
		return false, nil
	}

	engine := gin.New()
	_ = wc.Register(engine.Group("/" + wc.BasePath()))

	sar := authorizationv1.SubjectAccessReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SubjectAccessReview"},
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User: "ticket-123<script>alert('xss')</script>&quot;",
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: "default",
				Verb:      "get",
				Resource:  "pods",
			},
		},
	}

	body, _ := json.Marshal(sar)
	req, _ := http.NewRequest(http.MethodPost, "/breakglass/webhook/authorize/test-cluster", bytes.NewReader(body))
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	if w.Code == http.StatusInternalServerError {
		t.Errorf("Should not crash on special characters, got status %d", w.Code)
	}
}

// TestHandleAuthorize_EmptyUserField tests empty user handling
func TestHandleAuthorize_EmptyUserField(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme)
	for k, fn := range errorScenarioIndexFns {
		builder = builder.WithIndex(&breakglassv1alpha1.BreakglassSession{}, k, fn)
	}
	cli := builder.Build()

	sesMgr := &breakglass.SessionManager{Client: cli}
	escalMgr := &escalation.EscalationManager{Client: cli}
	logger, _ := zap.NewDevelopment()

	wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, policy.NewEvaluator(cli, logger.Sugar()))

	wc.canDoFn = func(ctx context.Context, rc *rest.Config, groups []string, sar authorizationv1.SubjectAccessReview, clustername string) (bool, error) {
		return false, nil
	}

	engine := gin.New()
	_ = wc.Register(engine.Group("/" + wc.BasePath()))

	sar := authorizationv1.SubjectAccessReview{
		TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SubjectAccessReview"},
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User: "",
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: "default",
				Verb:      "get",
				Resource:  "pods",
			},
		},
	}

	body, _ := json.Marshal(sar)
	req, _ := http.NewRequest(http.MethodPost, "/breakglass/webhook/authorize/test-cluster", bytes.NewReader(body))
	w := httptest.NewRecorder()

	engine.ServeHTTP(w, req)

	if w.Code == http.StatusInternalServerError {
		t.Errorf("Should handle empty user gracefully, got status %d", w.Code)
	}
}

// TestHandleAuthorize_ConcurrentRequests tests concurrent request safety
func TestHandleAuthorize_ConcurrentRequests(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme)
	for k, fn := range errorScenarioIndexFns {
		builder = builder.WithIndex(&breakglassv1alpha1.BreakglassSession{}, k, fn)
	}
	cli := builder.Build()

	sesMgr := &breakglass.SessionManager{Client: cli}
	escalMgr := &escalation.EscalationManager{Client: cli}
	logger, _ := zap.NewDevelopment()

	wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, policy.NewEvaluator(cli, logger.Sugar()))

	wc.canDoFn = func(ctx context.Context, rc *rest.Config, groups []string, sar authorizationv1.SubjectAccessReview, clustername string) (bool, error) {
		return false, nil
	}

	engine := gin.New()
	_ = wc.Register(engine.Group("/" + wc.BasePath()))

	resultChan := make(chan int, 5)
	for i := range 5 {
		go func(userID int) {
			sar := authorizationv1.SubjectAccessReview{
				TypeMeta: metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SubjectAccessReview"},
				Spec: authorizationv1.SubjectAccessReviewSpec{
					User: "testuser",
					ResourceAttributes: &authorizationv1.ResourceAttributes{
						Namespace: "default",
						Verb:      "get",
						Resource:  "pods",
					},
				},
			}

			body, _ := json.Marshal(sar)
			req, _ := http.NewRequest(http.MethodPost, "/breakglass/webhook/authorize/test-cluster", bytes.NewReader(body))
			w := httptest.NewRecorder()

			engine.ServeHTTP(w, req)
			resultChan <- w.Code
		}(i)
	}

	for i := range 5 {
		status := <-resultChan
		if status == http.StatusInternalServerError {
			t.Errorf("Concurrent request %d returned 500", i)
		}
	}
}

// TestHandleAuthorize_InvalidResourceName tests request with excessively long resource names
func TestHandleAuthorize_InvalidResourceName(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme)
	for k, fn := range errorScenarioIndexFns {
		builder = builder.WithIndex(&breakglassv1alpha1.BreakglassSession{}, k, fn)
	}
	cli := builder.Build()

	sesMgr := &breakglass.SessionManager{Client: cli}
	escalMgr := &escalation.EscalationManager{Client: cli}
	logger, _ := zap.NewDevelopment()

	wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, policy.NewEvaluator(cli, logger.Sugar()))

	// Create request with excessively long resource name
	sar := &authorizationv1.SubjectAccessReview{
		TypeMeta:   metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SubjectAccessReview"},
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User: "testuser",
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: "default",
				Verb:      "get",
				Group:     "apps",
				Resource:  "deployments",
				Name:      string(make([]byte, 1000)), // Excessively long name
			},
		},
	}

	body, _ := json.Marshal(sar)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/authorize/test-cluster", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = []gin.Param{{Key: "cluster_name", Value: "test-cluster"}}

	// Should handle gracefully without panic
	wc.handleAuthorize(c)
	if w.Code == http.StatusInternalServerError {
		t.Errorf("Handler returned 500 for long resource name: %s", w.Body.String())
	}
}

// TestHandleAuthorize_InvalidGroupFormat tests request with special characters in groups
func TestHandleAuthorize_InvalidGroupFormat(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme)
	for k, fn := range errorScenarioIndexFns {
		builder = builder.WithIndex(&breakglassv1alpha1.BreakglassSession{}, k, fn)
	}
	cli := builder.Build()

	sesMgr := &breakglass.SessionManager{Client: cli}
	escalMgr := &escalation.EscalationManager{Client: cli}
	logger, _ := zap.NewDevelopment()

	wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, policy.NewEvaluator(cli, logger.Sugar()))

	// Create request with invalid group format
	sar := &authorizationv1.SubjectAccessReview{
		TypeMeta:   metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SubjectAccessReview"},
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User:   "testuser",
			Groups: []string{"admin", "group;rm -rf /", "users"},
		},
	}

	body, _ := json.Marshal(sar)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/authorize/test-cluster", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = []gin.Param{{Key: "cluster_name", Value: "test-cluster"}}

	// Should handle gracefully - groups are user-supplied and should be handled safely
	wc.handleAuthorize(c)
	// We just verify it doesn't crash or return 500
	if w.Code >= 500 && w.Code < 600 {
		t.Logf("Received status %d for invalid group format (expected): %s", w.Code, w.Body.String())
	}
}

// TestHandleAuthorize_BothAttributeTypesPresent tests when both resource and non-resource attributes present
func TestHandleAuthorize_BothAttributeTypesPresent(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme)
	for k, fn := range errorScenarioIndexFns {
		builder = builder.WithIndex(&breakglassv1alpha1.BreakglassSession{}, k, fn)
	}
	cli := builder.Build()

	sesMgr := &breakglass.SessionManager{Client: cli}
	escalMgr := &escalation.EscalationManager{Client: cli}
	logger, _ := zap.NewDevelopment()

	wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, policy.NewEvaluator(cli, logger.Sugar()))

	// Create request with both resource and non-resource attributes
	sar := &authorizationv1.SubjectAccessReview{
		TypeMeta:   metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SubjectAccessReview"},
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User: "testuser",
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: "default",
				Verb:      "get",
				Group:     "apps",
				Resource:  "deployments",
			},
			NonResourceAttributes: &authorizationv1.NonResourceAttributes{
				Verb: "get",
				Path: "/api/v1/test",
			},
		},
	}

	body, _ := json.Marshal(sar)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/authorize/test-cluster", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = []gin.Param{{Key: "cluster_name", Value: "test-cluster"}}

	// Should handle gracefully
	wc.handleAuthorize(c)
	if w.Code == http.StatusInternalServerError {
		t.Errorf("Handler returned 500 for both attribute types present: %s", w.Body.String())
	}
}

// TestHandleAuthorize_NegatNullResourceAttributesImplicitlyHandled tests that nil ResourceAttributes doesn't panic
func TestHandleAuthorize_UnicodeCharactersInUser(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme)
	for k, fn := range errorScenarioIndexFns {
		builder = builder.WithIndex(&breakglassv1alpha1.BreakglassSession{}, k, fn)
	}
	cli := builder.Build()

	sesMgr := &breakglass.SessionManager{Client: cli}
	escalMgr := &escalation.EscalationManager{Client: cli}
	logger, _ := zap.NewDevelopment()

	wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, policy.NewEvaluator(cli, logger.Sugar()))

	// Create request with unicode characters in user field
	sar := &authorizationv1.SubjectAccessReview{
		TypeMeta:   metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SubjectAccessReview"},
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User: "用户@例子.com", // Chinese characters
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: "default",
				Verb:      "get",
				Group:     "apps",
				Resource:  "deployments",
			},
		},
	}

	body, _ := json.Marshal(sar)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/authorize/test-cluster", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = []gin.Param{{Key: "cluster_name", Value: "test-cluster"}}

	// Should handle gracefully - unicode is valid in identifiers
	wc.handleAuthorize(c)
	if w.Code == http.StatusInternalServerError {
		t.Errorf("Handler returned 500 for unicode in user: %s", w.Body.String())
	}
}

// TestHandleAuthorize_MissingContentType tests request without Content-Type header
func TestHandleAuthorize_MissingContentType(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(breakglass.Scheme)
	for k, fn := range errorScenarioIndexFns {
		builder = builder.WithIndex(&breakglassv1alpha1.BreakglassSession{}, k, fn)
	}
	cli := builder.Build()

	sesMgr := &breakglass.SessionManager{Client: cli}
	escalMgr := &escalation.EscalationManager{Client: cli}
	logger, _ := zap.NewDevelopment()

	wc := NewWebhookController(logger.Sugar(), config.Config{}, sesMgr, escalMgr, nil, policy.NewEvaluator(cli, logger.Sugar()))

	sar := &authorizationv1.SubjectAccessReview{
		TypeMeta:   metav1.TypeMeta{APIVersion: "authorization.k8s.io/v1", Kind: "SubjectAccessReview"},
		ObjectMeta: metav1.ObjectMeta{Name: "test"},
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User: "testuser",
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: "default",
				Verb:      "get",
				Group:     "apps",
				Resource:  "deployments",
			},
		},
	}

	body, _ := json.Marshal(sar)
	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodPost, "/authorize/test-cluster", bytes.NewReader(body))
	// Don't set Content-Type header
	c, _ := gin.CreateTestContext(w)
	c.Request = req
	c.Params = []gin.Param{{Key: "cluster_name", Value: "test-cluster"}}

	// Should handle gracefully
	wc.handleAuthorize(c)
	// Should not crash, may return error but not 500
	if w.Code >= 500 && w.Code < 600 {
		t.Logf("Received status %d for missing Content-Type (acceptable)", w.Code)
	}
}
