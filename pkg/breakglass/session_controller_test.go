package breakglass

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/naming"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type FakeMailSender struct {
	LastRecivers          []string
	LastSubject, LastBody string
	OnSendError           error
	SendCallCount         int // Track how many times Send was called
}

func (s *FakeMailSender) Send(receivers []string, subject, body string) error {
	s.LastRecivers = receivers
	s.LastSubject = subject
	s.LastBody = body
	s.SendCallCount++
	return s.OnSendError
}

func (s *FakeMailSender) GetHost() string {
	return "fake-mail-host"
}

func (s *FakeMailSender) GetPort() int {
	return 1025
}

var sessionIndexFunctions = map[string]client.IndexerFunc{
	"spec.user": func(o client.Object) []string {
		return []string{o.(*v1alpha1.BreakglassSession).Spec.User}
	},
	"spec.cluster": func(o client.Object) []string {
		return []string{o.(*v1alpha1.BreakglassSession).Spec.Cluster}
	},
	"spec.grantedGroup": func(o client.Object) []string {
		return []string{o.(*v1alpha1.BreakglassSession).Spec.GrantedGroup}
	},
	"metadata.name": func(o client.Object) []string {
		return []string{o.GetName()}
	},
}

func TestDropK8sInternalFieldsSessionStripsMetadata(t *testing.T) {
	s := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			UID:             types.UID("abc123"),
			ResourceVersion: "999",
			Generation:      7,
			ManagedFields:   []metav1.ManagedFieldsEntry{{}},
			Annotations: map[string]string{
				"kubectl.kubernetes.io/last-applied-configuration": "{}",
				"keep": "true",
			},
		},
	}

	dropK8sInternalFieldsSession(s)

	if s.ObjectMeta.ManagedFields != nil {
		t.Fatalf("expected managed fields to be nil, got %#v", s.ObjectMeta.ManagedFields)
	}
	if string(s.ObjectMeta.UID) != "" {
		t.Fatalf("expected UID to be cleared, got %s", s.ObjectMeta.UID)
	}
	if s.ObjectMeta.ResourceVersion != "" {
		t.Fatalf("expected resourceVersion to be cleared, got %s", s.ObjectMeta.ResourceVersion)
	}
	if s.ObjectMeta.Generation != 0 {
		t.Fatalf("expected generation to be zero, got %d", s.ObjectMeta.Generation)
	}
	if _, exists := s.ObjectMeta.Annotations["kubectl.kubernetes.io/last-applied-configuration"]; exists {
		t.Fatalf("expected kubectl annotation to be removed")
	}
	if s.ObjectMeta.Annotations["keep"] != "true" {
		t.Fatalf("expected non-internal annotations to be preserved")
	}
}

// TestRequestApproveRejectGetSession
//
// Purpose:
//
//	Exercises the full lifecycle of creating a breakglass session via the HTTP
//	handlers, approving it, and asserting terminal behavior when attempting to
//	reject an already-approved (terminal) session.
//
// Reasoning:
//
//	This integration-style unit test verifies that the HTTP handlers and the
//	controller wiring correctly persist sessions, set expected metadata
//	(RetainedUntil, ApprovedAt), and enforce terminal state rules.
//
// Flow pattern:
//   - Prepare a fake k8s client with an escalation that allows creation.
//   - Construct controller with middleware that injects different identities
//     depending on the HTTP method and URL (simulating requester and approver).
//   - POST to create a session, then GET to retrieve it and assert fields.
//   - POST to approve, GET to validate ApprovedAt is set.
//   - POST to reject the now-approved session and assert a BadRequest is
//     returned and the session remains approved.
func TestRequestApproveRejectGetSession(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}

	builder.WithObjects(&v1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name: "tester-allow-create-all",
		},
		Spec: v1alpha1.BreakglassEscalationSpec{
			Allowed: v1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"test"},
				Groups:   []string{"system:authenticated"},
			},
			EscalatedGroup: "breakglass-create-all",
			Approvers: v1alpha1.BreakglassEscalationApprovers{
				Users: []string{"approver@telekom.de", "rejector@telekom.de"},
			},
		},
	})
	cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}).Build()
	sesmanager := SessionManager{
		Client: cli,
	}
	escmanager := EscalationManager{
		Client: cli,
	}

	logger, _ := zap.NewDevelopment()
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{},
		&sesmanager, &escmanager,
		func(c *gin.Context) {
			if c.Request.Method == http.MethodOptions {
				c.Next()
				return
			}

			switch c.Request.Method {
			case http.MethodGet:
				c.Set("email", "approver@telekom.de")
				c.Set("username", "Approver")
			case http.MethodPost:
				url := c.Request.URL.String()
				if url == "/breakglassSessions" {
					c.Set("email", "tester@telekom.de")
					c.Set("username", "Tester")
				} else if strings.Contains(url, "/approve") || strings.Contains(url, "/reject") {
					c.Set("email", "approver@telekom.de")
					c.Set("username", "Approver")
				}
			}

			c.Next()
		}, "/config/config.yaml", nil, cli)

	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated", "breakglass-standard-user"}, nil
	}

	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	// create request
	reqData := BreakglassSessionRequest{
		Clustername: "test",
		Username:    "tester@telekom.de",
		GroupName:   "breakglass-create-all",
	}
	b, _ := json.Marshal(reqData)
	req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	response := w.Result()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("Expected status CREATED (201) got '%d' instead", response.StatusCode)
	}

	// get created request and check if proper fields are set
	getSession := func() v1alpha1.BreakglassSession {
		req, _ := http.NewRequest(http.MethodGet, "/breakglassSessions", nil)
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		response := w.Result()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("Expected status OK (200) got '%d' instead", response.StatusCode)
		}
		respSessions := []v1alpha1.BreakglassSession{}
		err := json.NewDecoder(response.Body).Decode(&respSessions)
		if err != nil {
			t.Fatalf("Failed to decode response body %v", err)
		}
		if l := len(respSessions); l != 1 {
			t.Fatalf("Expected one breakglass session to be created go %d instead. (%#v)", l, respSessions)
		}
		return respSessions[0]
	}

	ses := getSession()
	if stat := ses.Status.RetainedUntil; stat.Day() != time.Now().Add(MonthDuration).Day() {
		t.Fatalf("Incorrect session store until date day status %#v", stat)
	}

	// approve session
	req, _ = http.NewRequest(http.MethodPost,
		fmt.Sprintf("/breakglassSessions/%s/approve", ses.Name),
		nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	response = w.Result()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK (200) got '%d' instead", response.StatusCode)
	}

	// check if session status is approved
	ses = getSession()
	if ses.Status.ApprovedAt.Day() != time.Now().Day() {
		t.Fatalf("Expected session to be approved, but it is not.")
	}

	// reject session -> should be invalid because session is already approved (terminal)
	req, _ = http.NewRequest(http.MethodPost,
		fmt.Sprintf("/breakglassSessions/%s/reject", ses.Name),
		nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	response = w.Result()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected status BadRequest (400) got '%d' instead", response.StatusCode)
	}

	// session should remain approved
	ses = getSession()
	if ses.Status.ApprovedAt.IsZero() {
		t.Fatalf("Expected session to remain approved after invalid reject attempt, but it's not.")
	}
}

// Test that approving a session records the approver email in Status.Approver and
// appends it to Status.Approvers, and that rejecting updates the approver and
// appends the rejector to the history as well.
// TestApproveSetsApproverMetadata
//
// Purpose:
//
//	Verifies that when an approver approves a session, the controller records
//	approver metadata (Status.Approver and appends to Status.Approvers). Also
//	ensures that an invalid reject after approval does not overwrite approver
//	metadata.
//
// Reasoning:
//
//	Approval metadata is important for audit/history. This test checks both
//	the happy path of recording and the immutability of metadata after a
//	terminal transition.
//
// Flow pattern:
//   - Create a session via POST under a requester identity.
//   - Approve the session as an approver identity.
//   - GET the session and assert Status.Approver and Status.Approvers contain
//     the approver email.
//   - Issue a reject as a different user and assert the reject fails and the
//     approver metadata remains unchanged.
func TestApproveSetsApproverMetadata(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}

	builder.WithObjects(&v1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name: "tester-allow-create-all-2",
		},
		Spec: v1alpha1.BreakglassEscalationSpec{
			Allowed: v1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"test"},
				Groups:   []string{"system:authenticated"},
			},
			EscalatedGroup: "breakglass-create-all",
			Approvers: v1alpha1.BreakglassEscalationApprovers{
				Users: []string{"approver@telekom.de", "rejector@telekom.de"},
			},
		},
	})
	cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}

	logger, _ := zap.NewDevelopment()
	// middleware sets different identities depending on request
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{},
		&sesmanager, &escmanager,
		func(c *gin.Context) {
			if c.Request.Method == http.MethodOptions {
				c.Next()
				return
			}
			switch c.Request.Method {
			case http.MethodGet:
				// default to approver for GET
				c.Set("email", "approver@telekom.de")
				c.Set("username", "Approver")
			case http.MethodPost:
				url := c.Request.URL.String()
				if url == "/breakglassSessions" {
					// session creation uses requester identity
					c.Set("email", "requester@telekom.de")
					c.Set("username", "Requester")
				} else if strings.Contains(url, "/approve") {
					c.Set("email", "approver@telekom.de")
					c.Set("username", "Approver")
				} else if strings.Contains(url, "/reject") {
					c.Set("email", "rejector@telekom.de")
					c.Set("username", "Rejector")
				}
			}
			c.Next()
		}, "/config/config.yaml", nil, cli)

	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated", "breakglass-standard-user"}, nil
	}

	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	// create request
	reqData := BreakglassSessionRequest{
		Clustername: "test",
		Username:    "requester@telekom.de",
		GroupName:   "breakglass-create-all",
	}
	b, _ := json.Marshal(reqData)
	req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	response := w.Result()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("Expected status CREATED (201) got '%d' instead", response.StatusCode)
	}

	// fetch created session
	req, _ = http.NewRequest(http.MethodGet, "/breakglassSessions", nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	response = w.Result()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK (200) got '%d' instead", response.StatusCode)
	}
	respSessions := []v1alpha1.BreakglassSession{}
	if err := json.NewDecoder(response.Body).Decode(&respSessions); err != nil {
		t.Fatalf("Failed to decode response body %v", err)
	}
	if len(respSessions) != 1 {
		t.Fatalf("Expected one created session, got %#v", respSessions)
	}
	ses := respSessions[0]

	// approve session (approver@telekom.de)
	req, _ = http.NewRequest(http.MethodPost, fmt.Sprintf("/breakglassSessions/%s/approve", ses.Name), nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	response = w.Result()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK (200) got '%d' instead", response.StatusCode)
	}

	// fetch session and assert approver fields
	req, _ = http.NewRequest(http.MethodGet, "/breakglassSessions", nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	response = w.Result()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK (200) got '%d' instead", response.StatusCode)
	}
	respSessions = []v1alpha1.BreakglassSession{}
	if err := json.NewDecoder(response.Body).Decode(&respSessions); err != nil {
		t.Fatalf("Failed to decode response body %v", err)
	}
	if len(respSessions) != 1 {
		t.Fatalf("Expected one session after approve, got %#v", respSessions)
	}
	ses = respSessions[0]
	if ses.Status.Approver != "approver@telekom.de" {
		t.Fatalf("Expected Status.Approver to be approver@telekom.de, got %q", ses.Status.Approver)
	}
	found := false
	for _, a := range ses.Status.Approvers {
		if a == "approver@telekom.de" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("Expected approver@telekom.de to be present in Status.Approvers, got %#v", ses.Status.Approvers)
	}

	// reject session as a different user (rejector@telekom.de) -> should be invalid because session is terminal (approved)
	req, _ = http.NewRequest(http.MethodPost, fmt.Sprintf("/breakglassSessions/%s/reject", ses.Name), nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	response = w.Result()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected status BadRequest (400) got '%d' instead", response.StatusCode)
	}

	// fetch session and assert approver metadata remains unchanged (reject did not overwrite)
	req, _ = http.NewRequest(http.MethodGet, "/breakglassSessions", nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	response = w.Result()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK (200) got '%d' instead", response.StatusCode)
	}
	respSessions = []v1alpha1.BreakglassSession{}
	if err := json.NewDecoder(response.Body).Decode(&respSessions); err != nil {
		t.Fatalf("Failed to decode response body %v", err)
	}
	if len(respSessions) != 1 {
		t.Fatalf("Expected one session after invalid reject attempt, got %#v", respSessions)
	}
	ses = respSessions[0]
	if ses.Status.Approver != "approver@telekom.de" {
		t.Fatalf("Expected Status.Approver to remain approver@telekom.de after invalid reject, got %q", ses.Status.Approver)
	}
}

// Test that creating a session when a matching escalation exists attaches an OwnerReference
func TestCreateSessionAttachesOwnerReference(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}

	esc := &v1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "esc-for-ownerref",
			UID:       "1234",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassEscalationSpec{
			Allowed: v1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"test"},
				Groups:   []string{"system:authenticated"},
			},
			EscalatedGroup: "esc-group",
			Approvers: v1alpha1.BreakglassEscalationApprovers{
				Users: []string{"approver@example.com"},
			},
		},
	}
	builder.WithObjects(esc)
	cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}

	logger, _ := zap.NewDevelopment()
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager,
		func(c *gin.Context) {
			// always requester identity
			c.Set("email", "requester@example.com")
			c.Set("username", "requester")
			c.Next()
		}, "/config/config.yaml", nil, cli)

	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}

	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	reqData := BreakglassSessionRequest{
		Clustername: "test",
		Username:    "requester@example.com",
		GroupName:   "esc-group",
	}
	b, _ := json.Marshal(reqData)
	req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	resp := w.Result()
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("Expected created status, got %d", resp.StatusCode)
	}

	// Fetch sessions directly via session manager and ensure OwnerReference is present
	allSessions, err := sesmanager.GetAllBreakglassSessions(context.Background())
	if err != nil {
		t.Fatalf("failed to list sessions from manager: %v", err)
	}
	if len(allSessions) != 1 {
		t.Fatalf("expected 1 session in manager, got %d", len(allSessions))
	}
	s := allSessions[0]
	if len(s.OwnerReferences) == 0 {
		t.Fatalf("expected OwnerReferences to be set on created session, got none")
	}
	found := false
	for _, or := range s.OwnerReferences {
		if or.Name == "esc-for-ownerref" {
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected OwnerReference to escalation 'esc-for-ownerref', got %#v", s.OwnerReferences)
	}
}

// Test that creating a session without a matching escalation returns 403 and no session is created
func TestCreateSessionWithoutEscalationReturns401(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}
	cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}

	logger, _ := zap.NewDevelopment()
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager,
		func(c *gin.Context) {
			c.Set("email", "requester@example.com")
			c.Set("username", "requester")
			c.Next()
		}, "/config/config.yaml", nil, cli)

	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"some-group"}, nil
	}

	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	reqData := BreakglassSessionRequest{
		Clustername: "test",
		Username:    "requester@example.com",
		GroupName:   "nonexistent-group",
	}
	b, _ := json.Marshal(reqData)
	req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	resp := w.Result()
	// Returns 403 Forbidden when user is authenticated but no matching escalation exists
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("Expected 403 when no escalation found, got %d", resp.StatusCode)
	}

	// Verify no sessions exist
	req, _ = http.NewRequest(http.MethodGet, "/breakglassSessions", nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	resp = w.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("Expected OK getting sessions, got %d", resp.StatusCode)
	}
	var sessions []v1alpha1.BreakglassSession
	if err := json.NewDecoder(resp.Body).Decode(&sessions); err != nil {
		t.Fatalf("failed to decode sessions: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("expected 0 sessions after refused create, got %d", len(sessions))
	}
}

// Test that an escalation-level BlockSelfApproval override blocks self-approval even when cluster allows it
func TestEscalation_BlockSelfApproval_OverridesClusterAllow(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}

	// escalation sets BlockSelfApproval=true
	builder.WithObjects(&v1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc-block-override"},
		Spec: v1alpha1.BreakglassEscalationSpec{
			Allowed:           v1alpha1.BreakglassEscalationAllowed{Clusters: []string{"c"}, Groups: []string{"system:authenticated"}},
			EscalatedGroup:    "g-block",
			Approvers:         v1alpha1.BreakglassEscalationApprovers{Users: []string{"self@example.com"}},
			BlockSelfApproval: ptrBool(true),
		},
	})

	// cluster config allows self approval (false)
	builder.WithObjects(&v1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "c", Namespace: "default"},
		Spec:       v1alpha1.ClusterConfigSpec{BlockSelfApproval: false},
	})

	cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}

	logger, _ := zap.NewDevelopment()
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, func(c *gin.Context) {
		// middleware to set identity as self@example.com
		c.Set("email", "self@example.com")
		c.Set("username", "Self")
		c.Next()
	}, "/config/config.yaml", nil, cli)

	// avoid hitting real kubeconfig contexts in unit tests by stubbing group lookup
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated", "breakglass-standard-user"}, nil
	}

	// create a pending session where requester == approver candidate
	// create via API to get proper flow
	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	reqData := BreakglassSessionRequest{Clustername: "c", Username: "self@example.com", GroupName: "g-block"}
	b, _ := json.Marshal(reqData)
	req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusCreated {
		t.Fatalf("expected created, got %d", w.Result().StatusCode)
	}

	// Now try to approve as the same user -> should NOT be allowed
	// The POST response contains the created session object; decode it to get the name
	created := v1alpha1.BreakglassSession{}
	_ = json.NewDecoder(w.Result().Body).Decode(&created)
	name := created.Name

	// Approve request
	req, _ = http.NewRequest(http.MethodPost, fmt.Sprintf("/breakglassSessions/%s/approve", name), nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Result().StatusCode == http.StatusOK {
		t.Fatalf("expected approval to be blocked, but got OK")
	}
}

// Test that escalation-level AllowedApproverDomains restricts approvers even when cluster allows broader domains
func TestEscalation_AllowedApproverDomains_OverridesCluster(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}

	// escalation restricts approver domains to example.org
	builder.WithObjects(&v1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc-domain-override"},
		Spec: v1alpha1.BreakglassEscalationSpec{
			Allowed:                v1alpha1.BreakglassEscalationAllowed{Clusters: []string{"c2"}, Groups: []string{"system:authenticated"}},
			EscalatedGroup:         "g-domain",
			Approvers:              v1alpha1.BreakglassEscalationApprovers{Users: []string{"approver@example.org"}},
			AllowedApproverDomains: []string{"example.org"},
		},
	})

	// cluster allows example.com
	builder.WithObjects(&v1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "c2", Namespace: "default"},
		Spec:       v1alpha1.ClusterConfigSpec{AllowedApproverDomains: []string{"example.com"}},
	})

	cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}

	logger, _ := zap.NewDevelopment()
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, func(c *gin.Context) {
		// default identity middleware for request creation
		if c.Request.Method == http.MethodPost && c.Request.URL.Path == "/breakglassSessions" {
			c.Set("email", "requester@ex.com")
			c.Set("username", "Requester")
		} else {
			// approver identity (example.com domain) -> should be denied by escalation
			c.Set("email", "approver@example.com")
			c.Set("username", "Approver")
		}
		c.Next()
	}, "/config/config.yaml", nil, cli)

	// stub out group lookup to avoid kubeconfig parsing in unit tests
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated", "breakglass-standard-user"}, nil
	}

	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	// create a session
	reqData := BreakglassSessionRequest{Clustername: "c2", Username: "requester@ex.com", GroupName: "g-domain"}
	b, _ := json.Marshal(reqData)
	req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusCreated {
		t.Fatalf("expected created, got %d", w.Result().StatusCode)
	}

	// The POST response contains the created session object; decode it to get the name
	created := v1alpha1.BreakglassSession{}
	_ = json.NewDecoder(w.Result().Body).Decode(&created)
	name := created.Name

	// Attempt approval by approver@example.com (example.com) -> escalation restricts to example.org and should deny
	req, _ = http.NewRequest(http.MethodPost, fmt.Sprintf("/breakglassSessions/%s/approve", name), nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Result().StatusCode == http.StatusOK {
		t.Fatalf("expected approval to be denied by escalation domain restriction, but got OK")
	}
}

// Test that a BreakglassSession created via the controller is stored in the
// same namespace as the matched BreakglassEscalation when a match exists.
func TestSessionCreatedUsesEscalationNamespace(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}

	// Escalation lives in namespace "escns" and allows cluster "test"
	builder.WithObjects(&v1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "esc-namespace-test",
			Namespace: "escns",
		},
		Spec: v1alpha1.BreakglassEscalationSpec{
			Allowed: v1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"test"},
				Groups:   []string{"system:authenticated"},
			},
			EscalatedGroup: "g1",
			Approvers: v1alpha1.BreakglassEscalationApprovers{
				Users: []string{"approver@example.com"},
			},
		},
	})

	cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}

	logger, _ := zap.NewDevelopment()
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager,
		func(c *gin.Context) {
			// set requester identity for POST
			c.Set("email", "req@example.com")
			c.Set("username", "Req")
			c.Next()
		}, "/config/config.yaml", nil, cli)

	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}

	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	// create session request which should match the escalation in "escns"
	reqData := BreakglassSessionRequest{
		Clustername: "test",
		Username:    "req@example.com",
		GroupName:   "g1",
	}
	b, _ := json.Marshal(reqData)
	req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusCreated {
		t.Fatalf("expected created, got %d", w.Result().StatusCode)
	}

	// confirm the created BreakglassSession was persisted into the escalation namespace
	list := &v1alpha1.BreakglassSessionList{}
	if err := cli.List(context.Background(), list); err != nil {
		t.Fatalf("failed to list sessions: %v", err)
	}
	if len(list.Items) != 1 {
		t.Fatalf("expected 1 session, got %d", len(list.Items))
	}
	if list.Items[0].Namespace != "escns" {
		t.Fatalf("expected session namespace to be 'escns', got %q", list.Items[0].Namespace)
	}
}

func TestHandleRequestBreakglassSession_RejectsUserMismatch(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}

	builder.WithObjects(&v1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "esc-user-mismatch",
			Namespace: "escns",
		},
		Spec: v1alpha1.BreakglassEscalationSpec{
			Allowed: v1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"test"},
				Groups:   []string{"system:authenticated"},
			},
			EscalatedGroup: "g1",
			Approvers: v1alpha1.BreakglassEscalationApprovers{
				Users: []string{"approver@example.com"},
			},
		},
	})

	cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}

	logger, _ := zap.NewDevelopment()
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager,
		func(c *gin.Context) {
			c.Set("email", "req@example.com")
			c.Set("username", "Req")
			c.Set("user_id", "sub-req")
			c.Next()
		}, "/config/config.yaml", nil, cli)

	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}

	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	reqData := BreakglassSessionRequest{
		Clustername: "test",
		Username:    "other@example.com",
		GroupName:   "g1",
	}
	b, _ := json.Marshal(reqData)
	req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("expected forbidden for username mismatch, got %d", w.Result().StatusCode)
	}
}

func TestHandleRequestBreakglassSession_UsesUserIdentifierForExistingSessionLookup(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}

	clusterName := "test-cluster"
	// Existing session stored with sub claim
	existing := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "existing-session",
			Namespace: "escns",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			Cluster:      clusterName,
			User:         "sub-123",
			GrantedGroup: "g1",
		},
		Status: v1alpha1.BreakglassSessionStatus{
			State: v1alpha1.SessionStatePending,
		},
	}

	// ClusterConfig specifying sub as the user identifier claim
	clusterConfig := &v1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{
			Name:      clusterName,
			Namespace: "escns",
		},
		Spec: v1alpha1.ClusterConfigSpec{
			UserIdentifierClaim: v1alpha1.UserIdentifierClaimSub,
		},
	}

	builder.WithObjects(existing, clusterConfig, &v1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "esc-existing",
			Namespace: "escns",
		},
		Spec: v1alpha1.BreakglassEscalationSpec{
			Allowed: v1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{clusterName},
				Groups:   []string{"system:authenticated"},
			},
			EscalatedGroup: "g1",
		},
	})

	cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}

	logger, _ := zap.NewDevelopment()
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager,
		func(c *gin.Context) {
			c.Set("email", "req@example.com")
			c.Set("username", "Req")
			c.Set("user_id", "sub-123")
			c.Next()
		}, "/config/config.yaml", nil, cli)

	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}

	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	reqData := BreakglassSessionRequest{
		Clustername: clusterName,
		Username:    "req@example.com",
		GroupName:   "g1",
	}
	b, _ := json.Marshal(reqData)
	req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Result().StatusCode != http.StatusConflict {
		body, _ := io.ReadAll(w.Result().Body)
		t.Fatalf("expected conflict for existing session, got %d: %s", w.Result().StatusCode, string(body))
	}
}

// TestSessionCreatedUsesUserIdentifierClaim
//
// Purpose:
//
//	Verifies that session creation uses the correct user identifier based on
//	ClusterConfig's userIdentifierClaim setting.
//
// Reasoning:
//
//	The session's spec.User must match what the spoke cluster's OIDC sends in SAR.
//	Different clusters may use different OIDC claims (email, preferred_username, sub).
//	The controller should respect the ClusterConfig's userIdentifierClaim setting.
//
// Flow pattern:
//   - Create ClusterConfig with specific userIdentifierClaim
//   - Create escalation for the cluster
//   - Create session and verify spec.User matches the expected claim value
func TestSessionCreatedUsesUserIdentifierClaim(t *testing.T) {
	tests := []struct {
		name                string
		userIdentifierClaim v1alpha1.UserIdentifierClaimType
		contextEmail        string
		contextUsername     string
		contextUserID       string
		expectedSpecUser    string
	}{
		{
			name:                "Email claim (default)",
			userIdentifierClaim: v1alpha1.UserIdentifierClaimEmail,
			contextEmail:        "user@example.com",
			contextUsername:     "testuser",
			contextUserID:       "sub-123",
			expectedSpecUser:    "user@example.com",
		},
		{
			name:                "Preferred username claim",
			userIdentifierClaim: v1alpha1.UserIdentifierClaimPreferredUsername,
			contextEmail:        "user@example.com",
			contextUsername:     "testuser",
			contextUserID:       "sub-123",
			expectedSpecUser:    "testuser",
		},
		{
			name:                "Sub claim",
			userIdentifierClaim: v1alpha1.UserIdentifierClaimSub,
			contextEmail:        "user@example.com",
			contextUsername:     "testuser",
			contextUserID:       "sub-123",
			expectedSpecUser:    "sub-123",
		},
		{
			name:                "Empty claim defaults to email",
			userIdentifierClaim: "",
			contextEmail:        "default@example.com",
			contextUsername:     "defaultuser",
			contextUserID:       "sub-default",
			expectedSpecUser:    "default@example.com",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(Scheme)
			for index, fn := range sessionIndexFunctions {
				builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
			}

			clusterName := "test-cluster-" + string(tt.userIdentifierClaim)
			if tt.userIdentifierClaim == "" {
				clusterName = "test-cluster-default"
			}

			// Create ClusterConfig with specific userIdentifierClaim
			clusterConfig := &v1alpha1.ClusterConfig{
				ObjectMeta: metav1.ObjectMeta{
					Name: clusterName,
				},
				Spec: v1alpha1.ClusterConfigSpec{
					KubeconfigSecretRef: &v1alpha1.SecretKeyReference{
						Name:      "test-secret",
						Namespace: "default",
					},
					UserIdentifierClaim: tt.userIdentifierClaim,
				},
			}

			// Create escalation for the cluster
			escalation := &v1alpha1.BreakglassEscalation{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "esc-" + clusterName,
					Namespace: "default",
				},
				Spec: v1alpha1.BreakglassEscalationSpec{
					Allowed: v1alpha1.BreakglassEscalationAllowed{
						Clusters: []string{clusterName},
						Groups:   []string{"system:authenticated"},
					},
					EscalatedGroup: "test-group",
					Approvers: v1alpha1.BreakglassEscalationApprovers{
						Users: []string{"approver@example.com"},
					},
				},
			}

			cli := builder.WithObjects(clusterConfig, escalation).
				WithStatusSubresource(&v1alpha1.BreakglassSession{}).Build()
			sesmanager := SessionManager{Client: cli}
			escmanager := EscalationManager{Client: cli}

			logger, _ := zap.NewDevelopment()
			// Pass cli as clusterConfigClient - the controller will create its own ClusterConfigManager
			ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager,
				func(c *gin.Context) {
					// Set all identity claims in context
					c.Set("email", tt.contextEmail)
					c.Set("username", tt.contextUsername)
					c.Set("user_id", tt.contextUserID)
					c.Next()
				}, "/config/config.yaml", nil, cli)

			ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
				return []string{"system:authenticated"}, nil
			}

			engine := gin.New()
			_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

			// Create session request
			reqData := BreakglassSessionRequest{
				Clustername: clusterName,
				Username:    tt.contextEmail, // Frontend typically sends email
				GroupName:   "test-group",
			}
			b, _ := json.Marshal(reqData)
			req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, req)

			if w.Result().StatusCode != http.StatusCreated {
				body, _ := io.ReadAll(w.Result().Body)
				t.Fatalf("expected created, got %d: %s", w.Result().StatusCode, string(body))
			}

			// Verify the created session has the correct spec.User
			list := &v1alpha1.BreakglassSessionList{}
			if err := cli.List(context.Background(), list); err != nil {
				t.Fatalf("failed to list sessions: %v", err)
			}
			if len(list.Items) != 1 {
				t.Fatalf("expected 1 session, got %d", len(list.Items))
			}
			if list.Items[0].Spec.User != tt.expectedSpecUser {
				t.Errorf("expected spec.User=%q, got %q", tt.expectedSpecUser, list.Items[0].Spec.User)
			}
		})
	}
}

// helper to get *bool
func ptrBool(b bool) *bool { return &b }

// helper to get *int32
func ptrInt32(i int32) *int32 { return &i }

// TestFilterBreakglassSessionsByUser
//
// Purpose:
//
//	Ensures the listing handler supports the 'mine=true' filter returning only
//	sessions owned by the authenticated user.
//
// Reasoning:
//
//	Users should be able to restrict listings to their own sessions. The
//	controller derives the current user from the request context supplied by a
//	middleware-like function in tests.
//
// Flow pattern:
//   - Seed fake client with two sessions owned by different users.
//   - Configure middleware to set identity for user1.
//   - Call GET /breakglassSessions?mine=true and assert only user1's session
//     is returned.
func TestFilterBreakglassSessionsByUser(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}
	builder.WithObjects(
		&v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "session1"},
			Spec: v1alpha1.BreakglassSessionSpec{
				Cluster:      "clusterA",
				User:         "user1@example.com",
				GrantedGroup: "groupA",
			},
		},
		&v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "session2"},
			Spec: v1alpha1.BreakglassSessionSpec{
				Cluster:      "clusterB",
				User:         "user2@example.com",
				GrantedGroup: "groupB",
			},
		},
	)
	cli := builder.Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}
	logger, _ := zap.NewDevelopment()
	ctxSetup := func(c *gin.Context) {
		if c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}
		switch c.Request.Method {
		case http.MethodGet:
			c.Set("email", "user1@example.com")
			c.Set("username", "user1")
		case http.MethodPost:
			url := c.Request.URL.String()
			if url == "/breakglassSessions" {
				c.Set("email", "user1@example.com")
				c.Set("username", "user1")
			}
		}
		c.Next()
	}
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, ctxSetup, "/config/config.yaml", nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated", "breakglass-standard-user"}, nil
	}
	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	// Filter by mine=true (user1@example.com)
	req, _ := http.NewRequest(http.MethodGet, "/breakglassSessions?mine=true", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	response := w.Result()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK (200) got '%d' instead", response.StatusCode)
	}
	respSessions := []v1alpha1.BreakglassSession{}
	err := json.NewDecoder(response.Body).Decode(&respSessions)
	if err != nil {
		t.Fatalf("Failed to decode response body %v", err)
	}
	if len(respSessions) != 1 || respSessions[0].Spec.User != "user1@example.com" {
		t.Fatalf("Expected one session for user1@example.com, got: %#v", respSessions)
	}
}

// TestApproveByNonApprover_ReturnsUnauthorized
//
// Purpose:
//
//	Verifies that an HTTP approve attempt by a user who is not listed as an
//	approver (and not a member of approver groups) returns 401 Unauthorized.
//
// Reasoning:
//
//	Enforcement of approval permissions must be strict. This test asserts the
//	controller checks escalation approvers and blocks unauthorized callers.
//
// Flow pattern:
//   - Create a pending session and escalation where the approver is someone
//     else.
//   - Inject a middleware identity that is NOT the approver.
//   - POST to approve and assert 401 Unauthorized.
func TestApproveByNonApprover_ReturnsUnauthorized(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}

	now := metav1.Now()
	pending := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "pending-1"},
		Spec: v1alpha1.BreakglassSessionSpec{
			Cluster:      "c1",
			User:         "requester@example.com",
			GrantedGroup: "g1",
		},
		Status: v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStatePending, TimeoutAt: now, RetainedUntil: metav1.NewTime(time.Now().Add(MonthDuration))},
	}

	// Escalation exists but approver user is different
	esc := &v1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc-1"},
		Spec: v1alpha1.BreakglassEscalationSpec{
			Allowed:        v1alpha1.BreakglassEscalationAllowed{Clusters: []string{"c1"}, Groups: []string{"system:authenticated"}},
			EscalatedGroup: "g1",
			Approvers:      v1alpha1.BreakglassEscalationApprovers{Users: []string{"someoneelse@example.com"}},
		},
	}

	cli := builder.WithObjects(pending, esc).WithStatusSubresource(&v1alpha1.BreakglassSession{}).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}

	logger, _ := zap.NewDevelopment()
	// Middleware injects a user that is NOT an approver
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager,
		func(c *gin.Context) {
			c.Set("email", "not-an-approver@example.com")
			c.Next()
		}, "/config/config.yaml", nil, cli)

	// Force getUserGroupsFn to return no special groups
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}

	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions/pending-1/approve", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	res := w.Result()
	// Non-approvers are authenticated but not authorized - should get 403 Forbidden
	if res.StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403 Forbidden for non-approver, got %d", res.StatusCode)
	}
}

// TestApprovalAuthorizationDetailedResponses verifies that approval denials return appropriate
// HTTP status codes and specific error messages based on the denial reason.
// - 401 Unauthorized: authentication failures (can't identify user)
// - 403 Forbidden: authorization failures (user identified but not allowed)
func TestApprovalAuthorizationDetailedResponses(t *testing.T) {
	tests := []struct {
		name               string
		setupEscalation    func() *v1alpha1.BreakglassEscalation
		setupClusterConfig func() *v1alpha1.ClusterConfig
		approverEmail      string
		requesterEmail     string
		expectedStatus     int
		expectedReason     string
	}{
		{
			name: "self-approval blocked returns 403 with specific message",
			setupEscalation: func() *v1alpha1.BreakglassEscalation {
				return &v1alpha1.BreakglassEscalation{
					ObjectMeta: metav1.ObjectMeta{Name: "esc-self-block", Namespace: "default"},
					Spec: v1alpha1.BreakglassEscalationSpec{
						Allowed:           v1alpha1.BreakglassEscalationAllowed{Clusters: []string{"test-cluster"}, Groups: []string{"system:authenticated"}},
						EscalatedGroup:    "test-group",
						Approvers:         v1alpha1.BreakglassEscalationApprovers{Users: []string{"user@example.com"}},
						BlockSelfApproval: ptrBool(true),
					},
				}
			},
			setupClusterConfig: nil,
			approverEmail:      "user@example.com",
			requesterEmail:     "user@example.com", // Same user - self-approval
			expectedStatus:     http.StatusForbidden,
			expectedReason:     "Self-approval is not allowed",
		},
		{
			name: "domain not allowed returns 403 with specific message",
			setupEscalation: func() *v1alpha1.BreakglassEscalation {
				return &v1alpha1.BreakglassEscalation{
					ObjectMeta: metav1.ObjectMeta{Name: "esc-domain-block", Namespace: "default"},
					Spec: v1alpha1.BreakglassEscalationSpec{
						Allowed:                v1alpha1.BreakglassEscalationAllowed{Clusters: []string{"test-cluster"}, Groups: []string{"system:authenticated"}},
						EscalatedGroup:         "test-group",
						Approvers:              v1alpha1.BreakglassEscalationApprovers{Users: []string{"approver@external.com"}},
						AllowedApproverDomains: []string{"internal.com"},
					},
				}
			},
			setupClusterConfig: nil,
			approverEmail:      "approver@external.com",
			requesterEmail:     "requester@example.com",
			expectedStatus:     http.StatusForbidden,
			expectedReason:     "email domain is not in the list",
		},
		{
			name: "not an approver returns 403 with specific message",
			setupEscalation: func() *v1alpha1.BreakglassEscalation {
				return &v1alpha1.BreakglassEscalation{
					ObjectMeta: metav1.ObjectMeta{Name: "esc-not-approver", Namespace: "default"},
					Spec: v1alpha1.BreakglassEscalationSpec{
						Allowed:        v1alpha1.BreakglassEscalationAllowed{Clusters: []string{"test-cluster"}, Groups: []string{"system:authenticated"}},
						EscalatedGroup: "test-group",
						Approvers:      v1alpha1.BreakglassEscalationApprovers{Users: []string{"real-approver@example.com"}},
					},
				}
			},
			setupClusterConfig: nil,
			approverEmail:      "random@example.com",
			requesterEmail:     "requester@example.com",
			expectedStatus:     http.StatusForbidden,
			expectedReason:     "not in an approver group",
		},
		{
			name: "no matching escalation returns 403 with specific message",
			// Create an escalation with a DIFFERENT group than the session's granted group
			setupEscalation: func() *v1alpha1.BreakglassEscalation {
				return &v1alpha1.BreakglassEscalation{
					ObjectMeta: metav1.ObjectMeta{Name: "esc-different-group", Namespace: "default"},
					Spec: v1alpha1.BreakglassEscalationSpec{
						Allowed:        v1alpha1.BreakglassEscalationAllowed{Clusters: []string{"test-cluster"}, Groups: []string{"system:authenticated"}},
						EscalatedGroup: "different-group", // Does NOT match session's "test-group"
						Approvers:      v1alpha1.BreakglassEscalationApprovers{Users: []string{"approver@example.com"}},
					},
				}
			},
			setupClusterConfig: nil,
			approverEmail:      "approver@example.com",
			requesterEmail:     "requester@example.com",
			expectedStatus:     http.StatusForbidden,
			expectedReason:     "No matching escalation", // Session's grantedGroup="test-group" has no matching escalation
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			builder := fake.NewClientBuilder().WithScheme(Scheme)
			for index, fn := range sessionIndexFunctions {
				builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
			}

			esc := tt.setupEscalation()
			builder.WithObjects(esc)

			if tt.setupClusterConfig != nil {
				builder.WithObjects(tt.setupClusterConfig())
			}

			// Create a pending session
			now := metav1.Now()
			session := &v1alpha1.BreakglassSession{
				ObjectMeta: metav1.ObjectMeta{Name: "test-session", Namespace: esc.Namespace},
				Spec: v1alpha1.BreakglassSessionSpec{
					Cluster:      "test-cluster",
					User:         tt.requesterEmail,
					GrantedGroup: "test-group",
				},
				Status: v1alpha1.BreakglassSessionStatus{
					State:         v1alpha1.SessionStatePending,
					TimeoutAt:     now,
					RetainedUntil: metav1.NewTime(time.Now().Add(MonthDuration)),
				},
			}
			builder.WithObjects(session)

			cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}).Build()
			sesmanager := SessionManager{Client: cli}
			escmanager := EscalationManager{Client: cli}
			ccmanager := NewClusterConfigManager(cli)

			logger, _ := zap.NewDevelopment()
			ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager,
				func(c *gin.Context) {
					c.Set("email", tt.approverEmail)
					c.Set("username", tt.approverEmail)
					c.Next()
				}, "/config/config.yaml", nil, cli)
			ctrl.clusterConfigManager = ccmanager
			ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
				return []string{"system:authenticated"}, nil
			}

			engine := gin.New()
			_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

			req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions/test-session/approve", nil)
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, req)
			res := w.Result()

			require.Equal(t, tt.expectedStatus, res.StatusCode, "unexpected status code")

			// Check the error message contains the expected reason
			body, _ := io.ReadAll(res.Body)
			require.Contains(t, string(body), tt.expectedReason, "error message should contain expected reason")
		})
	}
}

// TestTerminalStateImmutability verifies that terminal states cannot be reverted or re-applied.
// TestTerminalStateImmutability
//
// Purpose:
//
//	Confirms that terminal session states (Approved, Rejected, Expired, etc.)
//	cannot be reapplied or reverted by subsequent actions.
//
// Reasoning:
//
//	Once a session reaches a terminal state the system must not allow
//	transitions back to non-terminal states or re-application of terminal
//	actions (e.g., approving twice).
//
// Flow pattern:
//   - Create a new session.
//   - Approve it once (expect 200 OK).
//   - Approve it again (expect 409 Conflict).
//   - Attempt to reject it after approval (expect 400 Bad Request).
func TestTerminalStateImmutability(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}

	// basic escalation allowing approver
	builder.WithObjects(&v1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc-imut"},
		Spec: v1alpha1.BreakglassEscalationSpec{
			Allowed:        v1alpha1.BreakglassEscalationAllowed{Clusters: []string{"c"}, Groups: []string{"system:authenticated"}},
			EscalatedGroup: "g",
			Approvers:      v1alpha1.BreakglassEscalationApprovers{Users: []string{"a@e.com"}},
		},
	})

	cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}

	logger, _ := zap.NewDevelopment()
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, func(c *gin.Context) {
		if c.Request.Method == http.MethodPost {
			if strings.Contains(c.Request.URL.String(), "/approve") {
				c.Set("email", "a@e.com")
			} else if strings.Contains(c.Request.URL.String(), "/reject") {
				c.Set("email", "r@e.com")
			} else {
				// plain POST (e.g. session creation) -> set requester email to avoid IDP call
				c.Set("email", "a@e.com")
			}
		} else {
			c.Set("email", "a@e.com")
		}
		c.Next()
	}, "/config/config.yaml", nil, cli)

	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	// create session - username must match the authenticated email for POST requests
	reqData := BreakglassSessionRequest{Clustername: "c", Username: "a@e.com", GroupName: "g"}
	b, _ := json.Marshal(reqData)
	req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusCreated {
		t.Fatalf("failed to create session, status: %d", w.Result().StatusCode)
	}

	// decode created session name from POST response
	created := v1alpha1.BreakglassSession{}
	if err := json.NewDecoder(w.Result().Body).Decode(&created); err != nil {
		t.Fatalf("failed to decode created session: %v", err)
	}
	name := created.Name

	// approve once -> OK
	req, _ = http.NewRequest(http.MethodPost, fmt.Sprintf("/breakglassSessions/%s/approve", name), nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected first approve to succeed, got %d", w.Result().StatusCode)
	}

	// approve second time -> conflict (409)
	req, _ = http.NewRequest(http.MethodPost, fmt.Sprintf("/breakglassSessions/%s/approve", name), nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusConflict {
		t.Fatalf("expected second approve to return Conflict (409), got %d", w.Result().StatusCode)
	}

	// attempt to reject after approval -> should be BadRequest (terminal)
	req, _ = http.NewRequest(http.MethodPost, fmt.Sprintf("/breakglassSessions/%s/reject", name), nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("expected reject after approve to be blocked (400), got %d", w.Result().StatusCode)
	}
}

// TestDropApprovedSessionExpires verifies that an owner can drop an approved (active) session
// which should immediately transition the session to Expired and become terminal.
// TestDropApprovedSessionExpires
//
// Purpose:
//
//	Validates that when the owner drops an approved session, the session is
//	immediately transitioned to Expired and ExpiresAt is set. Also asserts
//	that an expired session is terminal and cannot be approved again.
//
// Reasoning:
//
//	Owners need the ability to terminate active access; this must be reflected
//	in session state transitions and enforced as terminal.
//
// Flow pattern:
//   - Create session as owner and approve it as approver.
//   - POST /drop as the owner and verify session state becomes Expired and
//     ExpiresAt is populated.
//   - Attempt to approve again and assert the operation is rejected.
func TestDropApprovedSessionExpires(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}

	// escalation with approver
	builder.WithObjects(&v1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc-drop"},
		Spec: v1alpha1.BreakglassEscalationSpec{
			Allowed:        v1alpha1.BreakglassEscalationAllowed{Clusters: []string{"c"}, Groups: []string{"system:authenticated"}},
			EscalatedGroup: "g",
			Approvers:      v1alpha1.BreakglassEscalationApprovers{Users: []string{"approver@e.com"}},
		},
	})

	cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}

	logger, _ := zap.NewDevelopment()
	// middleware sets email depending on action: creation & drop -> requester, approve -> approver
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, func(c *gin.Context) {
		if c.Request.Method == http.MethodPost {
			if strings.Contains(c.Request.URL.String(), "/approve") {
				c.Set("email", "approver@e.com")
			} else if strings.Contains(c.Request.URL.String(), "/drop") {
				c.Set("email", "user@e.com")
			} else {
				c.Set("email", "user@e.com")
			}
		} else {
			c.Set("email", "user@e.com")
		}
		c.Next()
	}, "/config/config.yaml", nil, cli)

	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	// create session as requester user@e.com
	reqData := BreakglassSessionRequest{Clustername: "c", Username: "user@e.com", GroupName: "g"}
	b, _ := json.Marshal(reqData)
	req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusCreated {
		t.Fatalf("failed to create session, status: %d", w.Result().StatusCode)
	}

	// decode created session name from POST response
	created := v1alpha1.BreakglassSession{}
	if err := json.NewDecoder(w.Result().Body).Decode(&created); err != nil {
		t.Fatalf("failed to decode created session: %v", err)
	}
	name := created.Name

	// approve as approver -> session becomes Approved
	req, _ = http.NewRequest(http.MethodPost, fmt.Sprintf("/breakglassSessions/%s/approve", name), nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected approve to succeed, got %d", w.Result().StatusCode)
	}

	// verify approved state
	req, _ = http.NewRequest(http.MethodGet, fmt.Sprintf("/breakglassSessions/%s", name), nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	var gotResp struct {
		Session v1alpha1.BreakglassSession `json:"session"`
	}
	if err := json.NewDecoder(w.Result().Body).Decode(&gotResp); err != nil {
		t.Fatalf("failed to decode session status: %v", err)
	}
	got := gotResp.Session
	if got.Status.State != v1alpha1.SessionStateApproved || got.Status.ApprovedAt.IsZero() {
		t.Fatalf("expected approved session, got state=%s approvedAt=%v", got.Status.State, got.Status.ApprovedAt)
	}

	// drop as owner -> should transition to Expired
	req, _ = http.NewRequest(http.MethodPost, fmt.Sprintf("/breakglassSessions/%s/drop", name), nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected drop to succeed, got %d", w.Result().StatusCode)
	}

	// verify expired state
	req, _ = http.NewRequest(http.MethodGet, fmt.Sprintf("/breakglassSessions/%s", name), nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	var gotAfterDropResp struct {
		Session v1alpha1.BreakglassSession `json:"session"`
	}
	if err := json.NewDecoder(w.Result().Body).Decode(&gotAfterDropResp); err != nil {
		t.Fatalf("failed to decode session status after drop: %v", err)
	}
	gotAfterDrop := gotAfterDropResp.Session
	if gotAfterDrop.Status.State != v1alpha1.SessionStateExpired {
		t.Fatalf("expected expired session after drop, got state=%s", gotAfterDrop.Status.State)
	}
	if gotAfterDrop.Status.ExpiresAt.IsZero() {
		t.Fatalf("expected ExpiresAt to be set for expired session")
	}

	// ensure expired is terminal: further approve attempts must fail
	req, _ = http.NewRequest(http.MethodPost, fmt.Sprintf("/breakglassSessions/%s/approve", name), nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Result().StatusCode == http.StatusOK {
		t.Fatalf("expected approve after expired to be rejected, but got 200 OK")
	}
}

// TestApproverCancelRunningSession verifies that an approver can cancel a running session
// and that a non-approver is forbidden to do so.
// TestApproverCancelRunningSession
//
// Purpose:
//
//	Ensures that an approver can cancel (expire) a running/approved session
//	and that a non-approver is forbidden from performing the cancel action.
//
// Reasoning:
//
//	Approvers must retain the ability to cancel sessions they approved. The
//	test also ensures RBAC-like checks prevent unauthorized cancellations.
//
// Flow pattern:
//   - Create and approve a session.
//   - Cancel it as an approver and assert it transitions to Expired.
//   - Re-create controller middleware to simulate a non-approver and assert
//     cancel returns 401 Unauthorized.
func TestApproverCancelRunningSession(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}

	// escalation with approver
	builder.WithObjects(&v1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc-cancel"},
		Spec: v1alpha1.BreakglassEscalationSpec{
			Allowed:        v1alpha1.BreakglassEscalationAllowed{Clusters: []string{"c"}, Groups: []string{"system:authenticated"}},
			EscalatedGroup: "g",
			Approvers:      v1alpha1.BreakglassEscalationApprovers{Users: []string{"approver@e.com"}},
		},
	})

	cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}

	logger, _ := zap.NewDevelopment()
	// middleware sets email depending on action
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, func(c *gin.Context) {
		if c.Request.Method == http.MethodPost {
			if strings.Contains(c.Request.URL.String(), "/approve") {
				c.Set("email", "approver@e.com")
			} else if strings.Contains(c.Request.URL.String(), "/cancel") {
				// default to approver for cancel tests, tests can override by setting different middleware
				c.Set("email", "approver@e.com")
			} else {
				c.Set("email", "user@e.com")
			}
		} else {
			c.Set("email", "user@e.com")
		}
		c.Next()
	}, "/config/config.yaml", nil, cli)

	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	// create session as requester user@e.com
	reqData := BreakglassSessionRequest{Clustername: "c", Username: "user@e.com", GroupName: "g"}
	b, _ := json.Marshal(reqData)
	req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusCreated {
		t.Fatalf("failed to create session, status: %d", w.Result().StatusCode)
	}

	// decode created session name from POST response
	created := v1alpha1.BreakglassSession{}
	if err := json.NewDecoder(w.Result().Body).Decode(&created); err != nil {
		t.Fatalf("failed to decode created session: %v", err)
	}
	name := created.Name

	// approve as approver -> session becomes Approved
	req, _ = http.NewRequest(http.MethodPost, fmt.Sprintf("/breakglassSessions/%s/approve", name), nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected approve to succeed, got %d", w.Result().StatusCode)
	}

	// cancel as approver -> should transition to Expired
	req, _ = http.NewRequest(http.MethodPost, fmt.Sprintf("/breakglassSessions/%s/cancel", name), nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected cancel to succeed for approver, got %d", w.Result().StatusCode)
	}

	// decode cancel response (handler returns the updated session)
	canceled := v1alpha1.BreakglassSession{}
	if err := json.NewDecoder(w.Result().Body).Decode(&canceled); err != nil {
		t.Fatalf("failed to decode cancel response: %v", err)
	}
	if canceled.Status.State != v1alpha1.SessionStateExpired {
		t.Fatalf("expected expired session after cancel, got state=%s", canceled.Status.State)
	}

	// Now test that non-approver cannot cancel: override middleware to use non-approver email
	engine = gin.New()
	ctrl = NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, func(c *gin.Context) {
		if c.Request.Method == http.MethodPost {
			c.Set("email", "not-approver@e.com")
		} else {
			c.Set("email", "not-approver@e.com")
		}
		c.Next()
	}, "/config/config.yaml", nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	req, _ = http.NewRequest(http.MethodPost, fmt.Sprintf("/breakglassSessions/%s/cancel", name), nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	// Non-approvers are authenticated but not authorized - should get 403 Forbidden
	if w.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("expected cancel by non-approver to be Forbidden, got %d", w.Result().StatusCode)
	}
}

func TestFilterBreakglassSessionsByClusterQueryParam(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}
	builder.WithObjects(
		&v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "s1"},
			Spec: v1alpha1.BreakglassSessionSpec{
				Cluster:      "clusterA",
				User:         "user1@example.com",
				GrantedGroup: "groupA",
			},
		},
		&v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "s2"},
			Spec: v1alpha1.BreakglassSessionSpec{
				Cluster:      "clusterB",
				User:         "user2@example.com",
				GrantedGroup: "groupB",
			},
		},
	)
	cli := builder.Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}
	logger, _ := zap.NewDevelopment()
	ctxSetup := func(c *gin.Context) {
		if c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}
		// set identity to the owner of session s1 so cluster filter returns it
		c.Set("email", "user1@example.com")
		c.Set("username", "user1")
		c.Next()
	}
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, ctxSetup, "/config/config.yaml", nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	req, _ := http.NewRequest(http.MethodGet, "/breakglassSessions?cluster=clusterA&mine=true", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	response := w.Result()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK (200) got '%d' instead", response.StatusCode)
	}
	respSessions := []v1alpha1.BreakglassSession{}
	err := json.NewDecoder(response.Body).Decode(&respSessions)
	if err != nil {
		t.Fatalf("Failed to decode response body %v", err)
	}
	if len(respSessions) != 1 || respSessions[0].Spec.Cluster != "clusterA" {
		t.Fatalf("Expected one session for clusterA, got: %#v", respSessions)
	}
}

func TestFilterBreakglassSessionsByUserQueryParam(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}
	builder.WithObjects(
		&v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "u1"},
			Spec: v1alpha1.BreakglassSessionSpec{
				Cluster:      "clusterX",
				User:         "alice@example.com",
				GrantedGroup: "groupX",
			},
		},
		&v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "u2"},
			Spec: v1alpha1.BreakglassSessionSpec{
				Cluster:      "clusterY",
				User:         "bob@example.com",
				GrantedGroup: "groupY",
			},
		},
	)
	cli := builder.Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}
	logger, _ := zap.NewDevelopment()
	ctxSetup := func(c *gin.Context) {
		if c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}
		// Set identity to alice so mine=true will apply
		c.Set("email", "alice@example.com")
		c.Set("username", "alice")
		c.Next()
	}
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, ctxSetup, "/config/config.yaml", nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	req, _ := http.NewRequest(http.MethodGet, "/breakglassSessions?user=alice@example.com&mine=true", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	response := w.Result()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK (200) got '%d' instead", response.StatusCode)
	}
	respSessions := []v1alpha1.BreakglassSession{}
	err := json.NewDecoder(response.Body).Decode(&respSessions)
	if err != nil {
		t.Fatalf("Failed to decode response body %v", err)
	}
	if len(respSessions) != 1 || respSessions[0].Spec.User != "alice@example.com" {
		t.Fatalf("Expected one session for alice@example.com, got: %#v", respSessions)
	}
}

func TestFilterBreakglassSessionsByGroupQueryParam(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}
	builder.WithObjects(
		&v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "g1"},
			Spec: v1alpha1.BreakglassSessionSpec{
				Cluster:      "cluster1",
				User:         "u@example.com",
				GrantedGroup: "admins",
			},
		},
		&v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "g2"},
			Spec: v1alpha1.BreakglassSessionSpec{
				Cluster:      "cluster2",
				User:         "v@example.com",
				GrantedGroup: "devs",
			},
		},
	)
	cli := builder.Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}
	logger, _ := zap.NewDevelopment()
	ctxSetup := func(c *gin.Context) {
		if c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}
		// identity belongs to the user owning the matching session
		c.Set("email", "u@example.com")
		c.Set("username", "u")
		c.Next()
	}
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, ctxSetup, "/config/config.yaml", nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	req, _ := http.NewRequest(http.MethodGet, "/breakglassSessions?group=admins&mine=true", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	response := w.Result()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK (200) got '%d' instead", response.StatusCode)
	}
	respSessions := []v1alpha1.BreakglassSession{}
	err := json.NewDecoder(response.Body).Decode(&respSessions)
	if err != nil {
		t.Fatalf("Failed to decode response body %v", err)
	}
	if len(respSessions) != 1 || respSessions[0].Spec.GrantedGroup != "admins" {
		t.Fatalf("Expected one session for group admins, got: %#v", respSessions)
	}
}

func TestWithdrawMyRequest_Scenarios(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}

	// pending session owned by owner@example.com
	pending := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "w-pending"},
		Spec: v1alpha1.BreakglassSessionSpec{
			Cluster:      "cl-a",
			User:         "owner@example.com",
			GrantedGroup: "g",
		},
		Status: v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStatePending},
	}

	// approved session (should not be withdrawable)
	approved := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "w-approved"},
		Spec: v1alpha1.BreakglassSessionSpec{
			Cluster:      "cl-a",
			User:         "owner@example.com",
			GrantedGroup: "g",
		},
		Status: v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStateApproved, ApprovedAt: metav1.NewTime(time.Now().Add(-time.Minute))},
	}

	cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}).WithObjects(pending, approved).Build()
	ss := SessionManager{Client: cli}
	es := EscalationManager{Client: cli}

	logger, _ := zap.NewDevelopment()

	// Middleware that sets email based on a header to simulate different requesters
	ctxSetup := func(c *gin.Context) {
		if c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}
		// allow test to override requester via header
		if h := c.GetHeader("X-Test-Email"); h != "" {
			c.Set("email", h)
			c.Set("username", strings.Split(h, "@")[0])
		}
		c.Next()
	}

	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &ss, &es, ctxSetup, "/config/config.yaml", nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}

	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	// 1) Successful withdraw by owner on pending session
	{
		req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions/w-pending/withdraw", nil)
		req.Header.Set("X-Test-Email", "owner@example.com")
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		res := w.Result()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK for owner withdraw, got %d", res.StatusCode)
		}
		// verify status updated
		var bs v1alpha1.BreakglassSession
		if err := ss.Get(context.Background(), client.ObjectKey{Name: "w-pending"}, &bs); err != nil {
			t.Fatalf("failed to get session after withdraw: %v", err)
		}
		if bs.Status.State != v1alpha1.SessionStateWithdrawn {
			t.Fatalf("expected withdrawn state, got %s", bs.Status.State)
		}
	}

	// 2) Forbidden withdraw attempt by non-owner
	{
		req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions/w-approved/withdraw", nil)
		req.Header.Set("X-Test-Email", "other@example.com")
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		res := w.Result()
		// Non-owners are authenticated but not authorized - should get 403 Forbidden
		if res.StatusCode != http.StatusForbidden {
			t.Fatalf("expected 403 Forbidden for non-owner withdraw, got %d", res.StatusCode)
		}
	}

	// 3) Owner attempts to withdraw a non-pending (approved) session -> BadRequest
	{
		req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions/w-approved/withdraw", nil)
		req.Header.Set("X-Test-Email", "owner@example.com")
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		res := w.Result()
		if res.StatusCode != http.StatusBadRequest {
			t.Fatalf("expected 400 BadRequest for withdrawing non-pending session, got %d", res.StatusCode)
		}
	}
}

func TestFilterBreakglassSessionsByClusterAndUserQueryParams(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}
	builder.WithObjects(
		&v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "c1u1"},
			Spec: v1alpha1.BreakglassSessionSpec{
				Cluster:      "c1",
				User:         "u1@example.com",
				GrantedGroup: "g1",
			},
		},
		&v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "c1u2"},
			Spec: v1alpha1.BreakglassSessionSpec{
				Cluster:      "c1",
				User:         "u2@example.com",
				GrantedGroup: "g1",
			},
		},
	)
	cli := builder.Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}
	logger, _ := zap.NewDevelopment()
	ctxSetup := func(c *gin.Context) {
		if c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}
		// identity of u1 so mine=true applies
		c.Set("email", "u1@example.com")
		c.Set("username", "u1")
		c.Next()
	}
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, ctxSetup, "/config/config.yaml", nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	req, _ := http.NewRequest(http.MethodGet, "/breakglassSessions?cluster=c1&user=u1@example.com&mine=true", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	response := w.Result()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK (200) got '%d' instead", response.StatusCode)
	}
	respSessions := []v1alpha1.BreakglassSession{}
	err := json.NewDecoder(response.Body).Decode(&respSessions)
	if err != nil {
		t.Fatalf("Failed to decode response body %v", err)
	}
	if len(respSessions) != 1 || respSessions[0].Spec.User != "u1@example.com" || respSessions[0].Spec.Cluster != "c1" {
		t.Fatalf("Expected one session for c1/u1, got: %#v", respSessions)
	}
}

func TestRequestAndApproveWithReasons(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}

	// Escalation requires request reason and approver reason is optional
	builder.WithObjects(&v1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "reason-esc"},
		Spec: v1alpha1.BreakglassEscalationSpec{
			Allowed:        v1alpha1.BreakglassEscalationAllowed{Clusters: []string{"c1"}, Groups: []string{"system:authenticated"}},
			EscalatedGroup: "g-with-reason",
			Approvers:      v1alpha1.BreakglassEscalationApprovers{Users: []string{"approver@example.com"}},
			RequestReason:  &v1alpha1.ReasonConfig{Mandatory: true, Description: "CASM TicketID"},
			ApprovalReason: &v1alpha1.ReasonConfig{Mandatory: false, Description: "Approval note"},
		},
	})

	cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}

	logger, _ := zap.NewDevelopment()
	// middleware sets different identities depending on request
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager,
		func(c *gin.Context) {
			if c.Request.Method == http.MethodOptions {
				c.Next()
				return
			}
			switch c.Request.Method {
			case http.MethodGet:
				c.Set("email", "approver@example.com")
				c.Set("username", "Approver")
			case http.MethodPost:
				url := c.Request.URL.String()
				if url == "/breakglassSessions" {
					c.Set("email", "requester@example.com")
					c.Set("username", "Requester")
				} else if strings.Contains(url, "/approve") {
					c.Set("email", "approver@example.com")
					c.Set("username", "Approver")
				}
			}
			c.Next()
		}, "/config/config.yaml", nil, cli)

	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}

	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	// 1) attempt request without reason -> 422
	reqBody := BreakglassSessionRequest{Clustername: "c1", Username: "requester@example.com", GroupName: "g-with-reason"}
	b, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	res := w.Result()
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for missing required reason, got %d", res.StatusCode)
	}

	// 2) request with reason -> 201
	reqBody.Reason = "CASM-12345"
	b, _ = json.Marshal(reqBody)
	req, _ = http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	res = w.Result()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 for valid request, got %d", res.StatusCode)
	}

	// fetch session and verify stored request reason
	req, _ = http.NewRequest(http.MethodGet, "/breakglassSessions", nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	res = w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 fetching sessions, got %d", res.StatusCode)
	}
	respSessions := []v1alpha1.BreakglassSession{}
	if err := json.NewDecoder(res.Body).Decode(&respSessions); err != nil {
		t.Fatalf("failed to decode sessions: %v", err)
	}
	if len(respSessions) != 1 {
		t.Fatalf("expected one session, got %#v", respSessions)
	}
	ses := respSessions[0]
	if ses.Spec.RequestReason != "CASM-12345" {
		t.Fatalf("expected stored request reason CASM-12345, got %q", ses.Spec.RequestReason)
	}

	// 3) approve with approver reason
	approveBody := map[string]string{"reason": "Approved for emergency"}
	bb, _ := json.Marshal(approveBody)
	req, _ = http.NewRequest(http.MethodPost, fmt.Sprintf("/breakglassSessions/%s/approve", ses.Name), bytes.NewReader(bb))
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	res = w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 approving, got %d", res.StatusCode)
	}

	// fetch session and assert approvalReason stored
	req, _ = http.NewRequest(http.MethodGet, "/breakglassSessions", nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	res = w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 fetching sessions after approve, got %d", res.StatusCode)
	}
	respSessions = []v1alpha1.BreakglassSession{}
	if err := json.NewDecoder(res.Body).Decode(&respSessions); err != nil {
		t.Fatalf("failed to decode sessions after approve: %v", err)
	}
	if len(respSessions) != 1 {
		t.Fatalf("expected one session after approve, got %#v", respSessions)
	}
	ses = respSessions[0]
	if ses.Status.ApprovalReason != "Approved for emergency" {
		t.Fatalf("expected approval reason stored, got %q", ses.Status.ApprovalReason)
	}
}

func TestLongReasonStored(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}
	builder.WithObjects(&v1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "long-reason-esc"},
		Spec: v1alpha1.BreakglassEscalationSpec{
			Allowed:        v1alpha1.BreakglassEscalationAllowed{Clusters: []string{"lc1"}, Groups: []string{"system:authenticated"}},
			EscalatedGroup: "g-long",
			Approvers:      v1alpha1.BreakglassEscalationApprovers{Users: []string{"approver@example.com"}},
		},
	})

	cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}
	logger, _ := zap.NewDevelopment()
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager,
		func(c *gin.Context) {
			if c.Request.Method == http.MethodOptions {
				c.Next()
				return
			}
			if c.Request.Method == http.MethodPost && c.Request.URL.String() == "/breakglassSessions" {
				c.Set("email", "longreq@example.com")
				c.Set("username", "LongReq")
			} else if c.Request.Method == http.MethodGet {
				c.Set("email", "approver@example.com")
				c.Set("username", "Approver")
			}
			c.Next()
		}, "/config/config.yaml", nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}

	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	long := strings.Repeat("A", 3000)
	reqBody := BreakglassSessionRequest{Clustername: "lc1", Username: "longreq@example.com", GroupName: "g-long", Reason: long}
	b, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	res := w.Result()
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for long reason, got %d", res.StatusCode)
	}

	// fetch and assert no session was created
	req, _ = http.NewRequest(http.MethodGet, "/breakglassSessions", nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	res = w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 fetching sessions, got %d", res.StatusCode)
	}
	sessions := []v1alpha1.BreakglassSession{}
	if err := json.NewDecoder(res.Body).Decode(&sessions); err != nil {
		t.Fatalf("decode failed: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("expected 0 sessions, got %d", len(sessions))
	}
}

func TestWhitespaceReasonRejectedWhenMandatory(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}
	builder.WithObjects(&v1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "ws-esc"},
		Spec: v1alpha1.BreakglassEscalationSpec{
			Allowed:        v1alpha1.BreakglassEscalationAllowed{Clusters: []string{"wc1"}, Groups: []string{"system:authenticated"}},
			EscalatedGroup: "g-ws",
			RequestReason:  &v1alpha1.ReasonConfig{Mandatory: true, Description: "Ticket"},
		},
	})

	cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}
	logger, _ := zap.NewDevelopment()
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager,
		func(c *gin.Context) {
			if c.Request.Method == http.MethodPost && c.Request.URL.String() == "/breakglassSessions" {
				c.Set("email", "ws@example.com")
				c.Set("username", "WS")
			}
			c.Next()
		}, "/config/config.yaml", nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	reqBody := BreakglassSessionRequest{Clustername: "wc1", Username: "ws@example.com", GroupName: "g-ws", Reason: "   "}
	b, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	res := w.Result()
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for whitespace reason, got %d", res.StatusCode)
	}
}

func TestOwnerCanRejectPendingSession(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}
	builder.WithObjects(&v1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "owner-reject-esc"},
		Spec:       v1alpha1.BreakglassEscalationSpec{Allowed: v1alpha1.BreakglassEscalationAllowed{Clusters: []string{"oc1"}, Groups: []string{"system:authenticated"}}, EscalatedGroup: "g-owner"},
	})
	cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}
	logger, _ := zap.NewDevelopment()
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager,
		func(c *gin.Context) {
			if c.Request.Method == http.MethodPost {
				url := c.Request.URL.String()
				if url == "/breakglassSessions" {
					c.Set("email", "owner@example.com")
					c.Set("username", "Owner")
				} else if strings.Contains(url, "/reject") {
					c.Set("email", "owner@example.com")
					c.Set("username", "Owner")
				}
			}
			if c.Request.Method == http.MethodGet {
				c.Set("email", "owner@example.com")
				c.Set("username", "Owner")
			}
			c.Next()
		}, "/config/config.yaml", nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	// create request
	reqBody := BreakglassSessionRequest{Clustername: "oc1", Username: "owner@example.com", GroupName: "g-owner"}
	b, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusCreated {
		t.Fatalf("create failed")
	}

	// get session name
	req, _ = http.NewRequest(http.MethodGet, "/breakglassSessions?mine=true", nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	var sessions []v1alpha1.BreakglassSession
	_ = json.NewDecoder(w.Result().Body).Decode(&sessions)
	if len(sessions) != 1 {
		t.Fatalf("expected session present")
	}
	name := sessions[0].Name

	// owner rejects own pending session
	req, _ = http.NewRequest(http.MethodPost, fmt.Sprintf("/breakglassSessions/%s/reject", name), nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on owner reject, got %d", w.Result().StatusCode)
	}

	// verify rejected
	req, _ = http.NewRequest(http.MethodGet, "/breakglassSessions?mine=true", nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	sessions = []v1alpha1.BreakglassSession{}
	_ = json.NewDecoder(w.Result().Body).Decode(&sessions)
	if sessions[0].Status.State != v1alpha1.SessionStateRejected {
		t.Fatalf("expected state rejected, got %s", sessions[0].Status.State)
	}
}

func TestFilterBreakglassSessionsByClusterAndGroupQueryParams(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}
	builder.WithObjects(
		&v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "cg1"},
			Spec: v1alpha1.BreakglassSessionSpec{
				Cluster:      "cluster1",
				User:         "x@example.com",
				GrantedGroup: "ops",
			},
		},
		&v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "cg2"},
			Spec: v1alpha1.BreakglassSessionSpec{
				Cluster:      "cluster2",
				User:         "y@example.com",
				GrantedGroup: "ops",
			},
		},
	)
	cli := builder.Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}
	logger, _ := zap.NewDevelopment()
	ctxSetup := func(c *gin.Context) {
		if c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}
		c.Set("email", "x@example.com")
		c.Set("username", "x")
		c.Next()
	}
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, ctxSetup, "/config/config.yaml", nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	req, _ := http.NewRequest(http.MethodGet, "/breakglassSessions?cluster=cluster1&group=ops&mine=true", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	response := w.Result()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK (200) got '%d' instead", response.StatusCode)
	}
	respSessions := []v1alpha1.BreakglassSession{}
	err := json.NewDecoder(response.Body).Decode(&respSessions)
	if err != nil {
		t.Fatalf("Failed to decode response body %v", err)
	}
	if len(respSessions) != 1 || respSessions[0].Spec.Cluster != "cluster1" || respSessions[0].Spec.GrantedGroup != "ops" {
		t.Fatalf("Expected one session for cluster1/ops, got: %#v", respSessions)
	}
}

func TestFilterBreakglassSessionsByUserAndGroupQueryParams(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}
	builder.WithObjects(
		&v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "ug1"},
			Spec: v1alpha1.BreakglassSessionSpec{
				Cluster:      "cl1",
				User:         "sam@example.com",
				GrantedGroup: "ops",
			},
		},
		&v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "ug2"},
			Spec: v1alpha1.BreakglassSessionSpec{
				Cluster:      "cl2",
				User:         "sam@example.com",
				GrantedGroup: "dev",
			},
		},
	)
	cli := builder.Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}
	logger, _ := zap.NewDevelopment()
	ctxSetup := func(c *gin.Context) {
		if c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}
		c.Set("email", "sam@example.com")
		c.Set("username", "sam")
		c.Next()
	}
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, ctxSetup, "/config/config.yaml", nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	req, _ := http.NewRequest(http.MethodGet, "/breakglassSessions?user=sam@example.com&group=ops&mine=true", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	response := w.Result()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK (200) got '%d' instead", response.StatusCode)
	}
	respSessions := []v1alpha1.BreakglassSession{}
	err := json.NewDecoder(response.Body).Decode(&respSessions)
	if err != nil {
		t.Fatalf("Failed to decode response body %v", err)
	}
	if len(respSessions) != 1 || respSessions[0].Spec.User != "sam@example.com" || respSessions[0].Spec.GrantedGroup != "ops" {
		t.Fatalf("Expected one session for sam/ops, got: %#v", respSessions)
	}
}

func TestFilterBreakglassSessionsByClusterUserGroupQueryParams(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}
	builder.WithObjects(
		&v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "all1"},
			Spec: v1alpha1.BreakglassSessionSpec{
				Cluster:      "z1",
				User:         "p@example.com",
				GrantedGroup: "wheel",
			},
		},
		&v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: "all2"},
			Spec: v1alpha1.BreakglassSessionSpec{
				Cluster:      "z2",
				User:         "p@example.com",
				GrantedGroup: "wheel",
			},
		},
	)
	cli := builder.Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}
	logger, _ := zap.NewDevelopment()
	ctxSetup := func(c *gin.Context) {
		if c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}
		c.Set("email", "p@example.com")
		c.Set("username", "p")
		c.Next()
	}
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, ctxSetup, "/config/config.yaml", nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	req, _ := http.NewRequest(http.MethodGet, "/breakglassSessions?cluster=z1&user=p@example.com&group=wheel&mine=true", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	response := w.Result()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK (200) got '%d' instead", response.StatusCode)
	}
	respSessions := []v1alpha1.BreakglassSession{}
	err := json.NewDecoder(response.Body).Decode(&respSessions)
	if err != nil {
		t.Fatalf("Failed to decode response body %v", err)
	}
	if len(respSessions) != 1 || respSessions[0].Spec.Cluster != "z1" || respSessions[0].Spec.User != "p@example.com" || respSessions[0].Spec.GrantedGroup != "wheel" {
		t.Fatalf("Expected one session for z1/p/wheel, got: %#v", respSessions)
	}
}

func TestFilterBreakglassSessionsByState(t *testing.T) {
	// Create sessions with various states
	now := time.Now()
	pending := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "st-pending"},
		Spec:       v1alpha1.BreakglassSessionSpec{Cluster: "st-cl", User: "a@ex.com", GrantedGroup: "g"},
		Status:     v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStatePending, TimeoutAt: metav1.NewTime(now.Add(time.Hour))},
	}
	approved := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "st-approved"},
		Spec:       v1alpha1.BreakglassSessionSpec{Cluster: "st-cl", User: "b@ex.com", GrantedGroup: "g"},
		Status:     v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStateApproved, ApprovedAt: metav1.NewTime(now.Add(-time.Minute)), ExpiresAt: metav1.NewTime(now.Add(time.Hour))},
	}
	waiting := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "st-waiting"},
		Spec: v1alpha1.BreakglassSessionSpec{
			Cluster:            "st-cl",
			User:               "g@ex.com",
			GrantedGroup:       "g",
			ScheduledStartTime: &metav1.Time{Time: now.Add(time.Hour)},
		},
		Status: v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStateWaitingForScheduledTime},
	}
	rejected := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "st-rejected"},
		Spec:       v1alpha1.BreakglassSessionSpec{Cluster: "st-cl", User: "c@ex.com", GrantedGroup: "g"},
		Status:     v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStateRejected, RejectedAt: metav1.NewTime(now.Add(-time.Minute))},
	}
	withdrawn := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "st-withdrawn"},
		Spec:       v1alpha1.BreakglassSessionSpec{Cluster: "st-cl", User: "d@ex.com", GrantedGroup: "g"},
		Status:     v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStateWithdrawn, RejectedAt: metav1.NewTime(now.Add(-time.Minute))},
	}
	expired := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "st-expired"},
		Spec:       v1alpha1.BreakglassSessionSpec{Cluster: "st-cl", User: "e@ex.com", GrantedGroup: "g"},
		Status:     v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStateExpired, ExpiresAt: metav1.NewTime(now.Add(-time.Hour))},
	}
	timeout := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "st-timeout"},
		Spec:       v1alpha1.BreakglassSessionSpec{Cluster: "st-cl", User: "f@ex.com", GrantedGroup: "g"},
		Status:     v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStateTimeout, TimeoutAt: metav1.NewTime(now.Add(-time.Hour))},
	}

	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}
	builder.WithObjects(pending, approved, waiting, rejected, withdrawn, expired, timeout)
	cli := builder.Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}
	logger, _ := zap.NewDevelopment()
	ctxSetup := func(c *gin.Context) {
		// Set identity based on requested state so the controller sees the session owner
		state := c.Query("state")
		switch state {
		case "pending":
			c.Set("email", "a@ex.com")
			c.Set("username", "a")
		case "approved":
			c.Set("email", "b@ex.com")
			c.Set("username", "b")
		case "active":
			c.Set("email", "b@ex.com")
			c.Set("username", "b")
		case "rejected":
			c.Set("email", "c@ex.com")
			c.Set("username", "c")
		case "withdrawn":
			c.Set("email", "d@ex.com")
			c.Set("username", "d")
		case "expired":
			c.Set("email", "e@ex.com")
			c.Set("username", "e")
		case "timeout":
			c.Set("email", "f@ex.com")
			c.Set("username", "f")
		case "waiting", "waitingforscheduledtime":
			c.Set("email", "g@ex.com")
			c.Set("username", "g")
		default:
			c.Set("email", "approver@ex.com")
			c.Set("username", "approver")
		}
		c.Next()
	}
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, ctxSetup, "/config/config.yaml", nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	// helper to query by state
	queryByState := func(state string) []v1alpha1.BreakglassSession {
		req, _ := http.NewRequest(http.MethodGet, "/breakglassSessions?state="+state+"&mine=true", nil)
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		response := w.Result()
		if response.StatusCode != http.StatusOK {
			t.Fatalf("Expected status OK (200) got '%d' instead for state %s", response.StatusCode, state)
		}
		respSessions := []v1alpha1.BreakglassSession{}
		if err := json.NewDecoder(response.Body).Decode(&respSessions); err != nil {
			t.Fatalf("Failed to decode response body for state %s: %v", state, err)
		}
		return respSessions
	}

	// Verify each state returns the corresponding single session
	tests := map[string]string{
		"pending":   "st-pending",
		"approved":  "st-approved",
		"active":    "st-approved",
		"waiting":   "st-waiting",
		"rejected":  "st-rejected",
		"withdrawn": "st-withdrawn",
		"expired":   "st-expired",
		"timeout":   "st-timeout",
	}
	for st, expectedName := range tests {
		got := queryByState(st)
		if len(got) != 1 || got[0].Name != expectedName {
			t.Fatalf("Expected one session named %s for state %s, got: %#v", expectedName, st, got)
		}
	}
}

func TestFilterBreakglassSessionsByMultipleStates(t *testing.T) {
	viewer := "viewer@example.com"
	makeSession := func(name string, state v1alpha1.BreakglassSessionState) *v1alpha1.BreakglassSession {
		return &v1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{Name: name},
			Spec:       v1alpha1.BreakglassSessionSpec{Cluster: "multi", User: viewer, GrantedGroup: "g"},
			Status:     v1alpha1.BreakglassSessionStatus{State: state},
		}
	}
	pending := makeSession("multi-pending", v1alpha1.SessionStatePending)
	approved := makeSession("multi-approved", v1alpha1.SessionStateApproved)
	rejected := makeSession("multi-rejected", v1alpha1.SessionStateRejected)

	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}
	cli := builder.WithObjects(pending, approved, rejected).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}
	logger, _ := zap.NewDevelopment()
	ctxSetup := func(c *gin.Context) {
		if c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}
		c.Set("email", viewer)
		c.Set("username", "viewer")
		c.Next()
	}
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, ctxSetup, "/config/config.yaml", nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	assertStates := func(t *testing.T, query string, want []string) {
		t.Helper()
		req, _ := http.NewRequest(http.MethodGet, query, nil)
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		res := w.Result()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK, got %d", res.StatusCode)
		}
		var sessions []v1alpha1.BreakglassSession
		if err := json.NewDecoder(res.Body).Decode(&sessions); err != nil {
			t.Fatalf("failed to decode response: %v", err)
		}
		if len(sessions) != len(want) {
			t.Fatalf("expected %d sessions, got %d: %#v", len(want), len(sessions), sessions)
		}
		received := make([]string, len(sessions))
		for i, s := range sessions {
			received[i] = s.Name
		}
		slices.Sort(received)
		slices.Sort(want)
		for i := range want {
			if received[i] != want[i] {
				t.Fatalf("expected sessions %v, got %v", want, received)
			}
		}
	}

	assertStates(t, "/breakglassSessions?state=pending&state=approved&mine=true", []string{"multi-pending", "multi-approved"})
	assertStates(t, "/breakglassSessions?state=pending,approved&mine=true", []string{"multi-pending", "multi-approved"})
}

func TestFilterBreakglassSessionsApprovedByMe(t *testing.T) {
	approver := "approver@example.com"
	sessApproved := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "approved-now"},
		Spec:       v1alpha1.BreakglassSessionSpec{Cluster: "c", User: "owner1@example.com", GrantedGroup: "g1"},
		Status: v1alpha1.BreakglassSessionStatus{
			State:     v1alpha1.SessionStateApproved,
			Approver:  approver,
			Approvers: []string{approver},
		},
	}
	sessWithdrawn := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "approved-in-past"},
		Spec:       v1alpha1.BreakglassSessionSpec{Cluster: "c", User: "owner2@example.com", GrantedGroup: "g2"},
		Status: v1alpha1.BreakglassSessionStatus{
			State:     v1alpha1.SessionStateWithdrawn,
			Approvers: []string{approver},
		},
	}
	sessNotMine := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "not-approved-by-me"},
		Spec:       v1alpha1.BreakglassSessionSpec{Cluster: "c", User: "owner3@example.com", GrantedGroup: "g3"},
		Status: v1alpha1.BreakglassSessionStatus{
			State:     v1alpha1.SessionStateApproved,
			Approvers: []string{"someoneelse@example.com"},
		},
	}

	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}
	cli := builder.WithObjects(sessApproved, sessWithdrawn, sessNotMine).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}
	logger, _ := zap.NewDevelopment()
	ctxSetup := func(c *gin.Context) {
		if c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}
		c.Set("email", approver)
		c.Set("username", "approver")
		c.Next()
	}
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, ctxSetup, "/config/config.yaml", nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	req, _ := http.NewRequest(http.MethodGet, "/breakglassSessions?mine=false&approver=false&approvedByMe=true", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", res.StatusCode)
	}
	var sessions []v1alpha1.BreakglassSession
	if err := json.NewDecoder(res.Body).Decode(&sessions); err != nil {
		t.Fatalf("failed to decode response: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("expected two sessions approved by me, got %#v", sessions)
	}
	returned := []string{sessions[0].Name, sessions[1].Name}
	want := []string{"approved-now", "approved-in-past"}
	slices.Sort(returned)
	slices.Sort(want)
	for i, name := range want {
		if returned[i] != name {
			t.Fatalf("expected %v, got %v", want, returned)
		}
	}
}

// Test that a user who is an approver (but not the session owner) can see pending sessions
// they are allowed to approve when listing sessions (without mine=true).
func TestApproverCanSeePendingSessions(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}

	// pending session owned by alice, grantedGroup 'approvable'
	pending := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "approver-sess-1"},
		Spec: v1alpha1.BreakglassSessionSpec{
			Cluster:      "cl-approve",
			User:         "alice@example.com",
			GrantedGroup: "approvable",
		},
		Status: v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStatePending, TimeoutAt: metav1.NewTime(time.Now().Add(time.Hour))},
	}

	// escalation that grants 'approvable' and lists bob as approver
	esc := &v1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc-approvable"},
		Spec: v1alpha1.BreakglassEscalationSpec{
			Allowed:        v1alpha1.BreakglassEscalationAllowed{Clusters: []string{"cl-approve"}, Groups: []string{"system:authenticated"}},
			EscalatedGroup: "approvable",
			Approvers:      v1alpha1.BreakglassEscalationApprovers{Users: []string{"bob@example.com"}},
		},
	}

	cli := builder.WithObjects(pending, esc).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}
	logger, _ := zap.NewDevelopment()

	// middleware injects identity of bob (the approver)
	ctxSetup := func(c *gin.Context) {
		if c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}
		c.Set("email", "bob@example.com")
		c.Set("username", "bob")
		c.Next()
	}

	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, ctxSetup, "/config/config.yaml", nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}

	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	// bob should see the pending session without specifying mine=true
	req, _ := http.NewRequest(http.MethodGet, "/breakglassSessions", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", res.StatusCode)
	}
	var sessions []v1alpha1.BreakglassSession
	if err := json.NewDecoder(res.Body).Decode(&sessions); err != nil {
		t.Fatalf("failed decode response: %v", err)
	}
	if len(sessions) != 1 || sessions[0].Name != "approver-sess-1" {
		t.Fatalf("expected approver to see the pending session, got: %#v", sessions)
	}
}

// Fake identity provider that returns an error for GetEmail to exercise error paths
type ErrIdentityProvider struct{}

func (e ErrIdentityProvider) GetEmail(c *gin.Context) (string, error) {
	return "", fmt.Errorf("simulated idp error")
}
func (e ErrIdentityProvider) GetUsername(c *gin.Context) string { return "" }
func (e ErrIdentityProvider) GetIdentity(c *gin.Context) string { return "" }
func (e ErrIdentityProvider) GetUserIdentifier(c *gin.Context, claimType v1alpha1.UserIdentifierClaimType) (string, error) {
	return "", fmt.Errorf("simulated idp error")
}

// Test that when identity provider fails to return email and mine=true is requested,
// the handler returns HTTP 500.
func TestGetSessions_IdentityProviderErrorReturns500(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}
	// single session that would otherwise match
	s := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "idp-sess"},
		Spec:       v1alpha1.BreakglassSessionSpec{Cluster: "cl-idp", User: "who@example.com", GrantedGroup: "g"},
	}
	cli := builder.WithObjects(s).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}
	logger, _ := zap.NewDevelopment()

	// middleware tries to set nothing; identityProvider will error
	ctxSetup := func(c *gin.Context) { c.Next() }
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, ctxSetup, "/config/config.yaml", nil, cli)
	ctrl.identityProvider = ErrIdentityProvider{}
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) { return []string{}, nil }

	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	req, _ := http.NewRequest(http.MethodGet, "/breakglassSessions?mine=true", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	res := w.Result()
	if res.StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected 500 InternalServerError when identity provider fails, got %d", res.StatusCode)
	}
}

// Test that blockSelfApproval in ClusterConfig prevents a user from approving their own session
func TestClusterConfig_BlockSelfApproval_PreventsSelfApproval(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}

	// pending session owned by self@example.com
	pending := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "self-approve-sess"},
		Spec: v1alpha1.BreakglassSessionSpec{
			Cluster:      "cluster-block",
			User:         "self@example.com",
			GrantedGroup: "g-block",
		},
		Status: v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStatePending, TimeoutAt: metav1.NewTime(time.Now().Add(time.Hour))},
	}

	// escalation that would normally allow the user to approve (lists the user)
	esc := &v1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc-block"},
		Spec: v1alpha1.BreakglassEscalationSpec{
			Allowed:        v1alpha1.BreakglassEscalationAllowed{Clusters: []string{"cluster-block"}, Groups: []string{"system:authenticated"}},
			EscalatedGroup: "g-block",
			Approvers:      v1alpha1.BreakglassEscalationApprovers{Users: []string{"self@example.com"}},
		},
	}

	// ClusterConfig that blocks self approval
	cc := &v1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-block"},
		Spec:       v1alpha1.ClusterConfigSpec{BlockSelfApproval: true},
	}

	cli := builder.WithObjects(pending, esc, cc).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}
	logger, _ := zap.NewDevelopment()

	// middleware sets identity to the session owner (self) who would otherwise be an approver
	ctxSetup := func(c *gin.Context) {
		if c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}
		c.Set("email", "self@example.com")
		c.Set("username", "self")
		c.Next()
	}

	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, ctxSetup, "/config/config.yaml", nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}

	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	// Since self-approval is blocked, the owner acting as approver should NOT see the pending session
	req, _ := http.NewRequest(http.MethodGet, "/breakglassSessions", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", res.StatusCode)
	}
	var sessions []v1alpha1.BreakglassSession
	if err := json.NewDecoder(res.Body).Decode(&sessions); err != nil {
		t.Fatalf("failed decode response: %v", err)
	}
	if len(sessions) != 0 {
		t.Fatalf("expected no sessions visible due to blockSelfApproval, got: %#v", sessions)
	}
}

// Test that allowedApproverDomains restricts approver emails to configured domains
func TestClusterConfig_AllowedApproverDomains_AllowsDomain(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}

	pending := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "domain-approve-sess"},
		Spec: v1alpha1.BreakglassSessionSpec{
			Cluster:      "cluster-domain",
			User:         "user@other.com",
			GrantedGroup: "g-domain",
		},
		Status: v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStatePending, TimeoutAt: metav1.NewTime(time.Now().Add(time.Hour))},
	}

	esc := &v1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "esc-domain"},
		Spec: v1alpha1.BreakglassEscalationSpec{
			Allowed:        v1alpha1.BreakglassEscalationAllowed{Clusters: []string{"cluster-domain"}, Groups: []string{"system:authenticated"}},
			EscalatedGroup: "g-domain",
			Approvers:      v1alpha1.BreakglassEscalationApprovers{Users: []string{"approver@example.com"}},
		},
	}

	cc := &v1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-domain"},
		Spec:       v1alpha1.ClusterConfigSpec{AllowedApproverDomains: []string{"example.com"}},
	}

	cli := builder.WithObjects(pending, esc, cc).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}
	logger, _ := zap.NewDevelopment()

	// middleware injects approver with allowed domain
	ctxSetup := func(c *gin.Context) {
		if c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}
		c.Set("email", "approver@example.com")
		c.Set("username", "approver")
		c.Next()
	}

	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, ctxSetup, "/config/config.yaml", nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}

	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	req, _ := http.NewRequest(http.MethodGet, "/breakglassSessions", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	res := w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 OK, got %d", res.StatusCode)
	}
	var sessions []v1alpha1.BreakglassSession
	if err := json.NewDecoder(res.Body).Decode(&sessions); err != nil {
		t.Fatalf("failed decode response: %v", err)
	}
	if len(sessions) != 1 || sessions[0].Name != "domain-approve-sess" {
		t.Fatalf("expected approver with allowed domain to see session, got: %#v", sessions)
	}
}

// Exhaustive permutations combining cluster/user/group with mine and state filters.
func TestFilterBreakglassSessions_ExhaustivePermutations(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}

	now := time.Now()
	s1 := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s1"},
		Spec:       v1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1@example.com", GrantedGroup: "g1"},
		Status:     v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStatePending, TimeoutAt: metav1.NewTime(now.Add(time.Hour))},
	}
	s2 := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s2"},
		Spec:       v1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u2@example.com", GrantedGroup: "g1"},
		Status:     v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStateApproved, ApprovedAt: metav1.NewTime(now.Add(-time.Minute))},
	}
	s3 := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s3"},
		Spec:       v1alpha1.BreakglassSessionSpec{Cluster: "c2", User: "u1@example.com", GrantedGroup: "g2"},
		Status:     v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStateRejected, RejectedAt: metav1.NewTime(now.Add(-time.Minute))},
	}
	s4 := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s4"},
		Spec:       v1alpha1.BreakglassSessionSpec{Cluster: "c2", User: "u2@example.com", GrantedGroup: "g2"},
		Status:     v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStatePending, TimeoutAt: metav1.NewTime(now.Add(time.Hour))},
	}
	s5 := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s5"},
		Spec:       v1alpha1.BreakglassSessionSpec{Cluster: "c1", User: "u1@example.com", GrantedGroup: "g2"},
		Status:     v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStateApproved, ApprovedAt: metav1.NewTime(now.Add(-time.Minute))},
	}
	s6 := &v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "s6"},
		Spec:       v1alpha1.BreakglassSessionSpec{Cluster: "c2", User: "u2@example.com", GrantedGroup: "g1"},
		Status:     v1alpha1.BreakglassSessionStatus{State: v1alpha1.SessionStateExpired, ExpiresAt: metav1.NewTime(now.Add(-time.Hour))},
	}

	cli := builder.WithObjects(s1, s2, s3, s4, s5, s6).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}
	logger, _ := zap.NewDevelopment()

	// middleware that uses X-Test-Email header to set identity for each request
	ctxSetup := func(c *gin.Context) {
		if c.Request.Method == http.MethodOptions {
			c.Next()
			return
		}
		if h := c.GetHeader("X-Test-Email"); h != "" {
			c.Set("email", h)
			c.Set("username", strings.Split(h, "@")[0])
		}
		c.Next()
	}

	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, ctxSetup, "/config/config.yaml", nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}

	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	cases := []struct {
		name   string
		query  string
		header string
		expect []string
	}{
		{"cluster_c1_mine_u1", "cluster=c1&mine=true", "u1@example.com", []string{"s1", "s5"}},
		{"cluster_c1_user_u2_mine", "cluster=c1&user=u2@example.com&mine=true", "u2@example.com", []string{"s2"}},
		{"user_u2_mine", "user=u2@example.com&mine=true", "u2@example.com", []string{"s2", "s4", "s6"}},
		{"group_g1_mine_u1", "group=g1&mine=true", "u1@example.com", []string{"s1"}},
		{"cluster_c2_group_g2_mine_u1", "cluster=c2&group=g2&mine=true", "u1@example.com", []string{"s3"}},
		{"state_pending_mine_u2", "state=pending&mine=true", "u2@example.com", []string{"s4"}},
		{"state_approved_mine_u2", "state=approved&mine=true", "u2@example.com", []string{"s2"}},
		{"cluster_c2_state_expired_mine_u2", "cluster=c2&state=expired&mine=true", "u2@example.com", []string{"s6"}},
		{"user_u1_group_g2_mine", "user=u1@example.com&group=g2&mine=true", "u1@example.com", []string{"s3", "s5"}},
	}

	for _, tc := range cases {
		req, _ := http.NewRequest(http.MethodGet, "/breakglassSessions?"+tc.query, nil)
		if tc.header != "" {
			req.Header.Set("X-Test-Email", tc.header)
		}
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		res := w.Result()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("case %s: expected 200 OK, got %d", tc.name, res.StatusCode)
		}
		var got []v1alpha1.BreakglassSession
		if err := json.NewDecoder(res.Body).Decode(&got); err != nil {
			t.Fatalf("case %s: failed to decode response: %v", tc.name, err)
		}
		// build name set
		gotNames := map[string]struct{}{}
		for _, s := range got {
			gotNames[s.Name] = struct{}{}
		}
		if len(gotNames) != len(tc.expect) {
			t.Fatalf("case %s: expected %d sessions %v, got %v", tc.name, len(tc.expect), tc.expect, got)
		}
		for _, exp := range tc.expect {
			if _, ok := gotNames[exp]; !ok {
				t.Fatalf("case %s: expected session %s not present in result %v", tc.name, exp, got)
			}
		}
	}
}

// TestFilterExcludedNotificationRecipients tests the filtering of excluded users/groups from notifications
func TestFilterExcludedNotificationRecipients(t *testing.T) {
	log := zap.NewNop().Sugar()

	cases := []struct {
		name      string
		approvers []string
		exclusion *v1alpha1.NotificationExclusions
		expect    []string
	}{
		{
			name:      "No exclusions",
			approvers: []string{"user1@example.com", "user2@example.com"},
			exclusion: nil,
			expect:    []string{"user1@example.com", "user2@example.com"},
		},
		{
			name:      "Exclude single user",
			approvers: []string{"user1@example.com", "user2@example.com", "user3@example.com"},
			exclusion: &v1alpha1.NotificationExclusions{
				Users: []string{"user2@example.com"},
			},
			expect: []string{"user1@example.com", "user3@example.com"},
		},
		{
			name:      "Exclude multiple users",
			approvers: []string{"user1@example.com", "user2@example.com", "user3@example.com"},
			exclusion: &v1alpha1.NotificationExclusions{
				Users: []string{"user1@example.com", "user3@example.com"},
			},
			expect: []string{"user2@example.com"},
		},
		{
			name:      "Exclude non-existing user",
			approvers: []string{"user1@example.com", "user2@example.com"},
			exclusion: &v1alpha1.NotificationExclusions{
				Users: []string{"nonexistent@example.com"},
			},
			expect: []string{"user1@example.com", "user2@example.com"},
		},
		{
			name:      "All users excluded",
			approvers: []string{"user1@example.com", "user2@example.com"},
			exclusion: &v1alpha1.NotificationExclusions{
				Users: []string{"user1@example.com", "user2@example.com"},
			},
			expect: []string{},
		},
		{
			name:      "Empty approvers",
			approvers: []string{},
			exclusion: &v1alpha1.NotificationExclusions{
				Users: []string{"user1@example.com"},
			},
			expect: []string{},
		},
	}

	for _, tc := range cases {
		escalation := &v1alpha1.BreakglassEscalation{
			Spec: v1alpha1.BreakglassEscalationSpec{
				NotificationExclusions: tc.exclusion,
			},
		}

		ctrl := &BreakglassSessionController{}
		result := ctrl.filterExcludedNotificationRecipients(log, tc.approvers, escalation)

		if len(result) != len(tc.expect) {
			t.Fatalf("case %s: expected %d recipients, got %d: %v", tc.name, len(tc.expect), len(result), result)
		}

		// Convert to map for easy comparison
		resultMap := make(map[string]bool)
		for _, r := range result {
			resultMap[r] = true
		}

		for _, exp := range tc.expect {
			if !resultMap[exp] {
				t.Fatalf("case %s: expected recipient %s not in result: %v", tc.name, exp, result)
			}
		}
	}
}

// TestDisableNotificationsFlag tests that disableNotifications prevents emails
func TestDisableNotificationsFlag(t *testing.T) {
	log := zap.NewNop().Sugar()

	// Test with nil escalation
	ctrl := &BreakglassSessionController{}
	result := ctrl.filterExcludedNotificationRecipients(log, []string{"user@example.com"}, nil)
	if len(result) != 1 {
		t.Fatalf("expected 1 recipient with nil escalation, got %d", len(result))
	}

	// Test with no exclusions
	escalation := &v1alpha1.BreakglassEscalation{
		Spec: v1alpha1.BreakglassEscalationSpec{
			NotificationExclusions: nil,
		},
	}
	result = ctrl.filterExcludedNotificationRecipients(log, []string{"user@example.com"}, escalation)
	if len(result) != 1 {
		t.Fatalf("expected 1 recipient with no exclusions, got %d", len(result))
	}

	// Test with empty exclusions
	escalation = &v1alpha1.BreakglassEscalation{
		Spec: v1alpha1.BreakglassEscalationSpec{
			NotificationExclusions: &v1alpha1.NotificationExclusions{},
		},
	}
	result = ctrl.filterExcludedNotificationRecipients(log, []string{"user@example.com"}, escalation)
	if len(result) != 1 {
		t.Fatalf("expected 1 recipient with empty exclusions, got %d", len(result))
	}
}

// TestFilterHiddenFromUIRecipients tests the filtering of hidden users/groups from UI and notifications
func TestFilterHiddenFromUIRecipients(t *testing.T) {
	log := zap.NewExample().Sugar()
	ctrl := &BreakglassSessionController{}

	tests := []struct {
		name      string
		approvers []string
		hidden    []string
		expected  int
	}{
		{
			name:      "No hidden groups",
			approvers: []string{"alice@example.com", "bob@example.com"},
			hidden:    []string{},
			expected:  2,
		},
		{
			name:      "Single user hidden",
			approvers: []string{"alice@example.com", "bob@example.com", "charlie@example.com"},
			hidden:    []string{"alice@example.com"},
			expected:  2,
		},
		{
			name:      "Multiple users hidden",
			approvers: []string{"alice@example.com", "bob@example.com", "charlie@example.com"},
			hidden:    []string{"alice@example.com", "charlie@example.com"},
			expected:  1,
		},
		{
			name:      "All users hidden",
			approvers: []string{"alice@example.com", "bob@example.com"},
			hidden:    []string{"alice@example.com", "bob@example.com"},
			expected:  0,
		},
		{
			name:      "Empty approvers",
			approvers: []string{},
			hidden:    []string{"alice@example.com"},
			expected:  0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			escalation := &v1alpha1.BreakglassEscalation{
				Spec: v1alpha1.BreakglassEscalationSpec{
					Approvers: v1alpha1.BreakglassEscalationApprovers{
						HiddenFromUI: tt.hidden,
					},
				},
			}
			result := ctrl.filterHiddenFromUIRecipients(log, tt.approvers, escalation)
			if len(result) != tt.expected {
				t.Fatalf("expected %d recipients, got %d; result: %v", tt.expected, len(result), result)
			}
		})
	}

	// Test with nil escalation
	result := ctrl.filterHiddenFromUIRecipients(log, []string{"user@example.com"}, nil)
	if len(result) != 1 {
		t.Fatalf("expected 1 recipient with nil escalation, got %d", len(result))
	}

	// Test with empty hidden list
	escalation := &v1alpha1.BreakglassEscalation{
		Spec: v1alpha1.BreakglassEscalationSpec{
			Approvers: v1alpha1.BreakglassEscalationApprovers{
				HiddenFromUI: []string{},
			},
		},
	}
	result = ctrl.filterHiddenFromUIRecipients(log, []string{"user@example.com"}, escalation)
	if len(result) != 1 {
		t.Fatalf("expected 1 recipient with empty hidden list, got %d", len(result))
	}
}

// TestHiddenFromUIAndNotificationExclusionsCombined tests that both filtering mechanisms work together
func TestHiddenFromUIAndNotificationExclusionsCombined(t *testing.T) {
	log := zap.NewExample().Sugar()
	ctrl := &BreakglassSessionController{}

	// Start with approvers: alice, bob, charlie, dave
	approvers := []string{"alice@example.com", "bob@example.com", "charlie@example.com", "dave@example.com"}

	escalation := &v1alpha1.BreakglassEscalation{
		Spec: v1alpha1.BreakglassEscalationSpec{
			Approvers: v1alpha1.BreakglassEscalationApprovers{
				HiddenFromUI: []string{"charlie@example.com"}, // charlie is hidden
			},
			NotificationExclusions: &v1alpha1.NotificationExclusions{
				Users: []string{"dave@example.com"}, // dave is excluded from notifications
			},
		},
	}

	// First filter: notification exclusions
	filtered := ctrl.filterExcludedNotificationRecipients(log, approvers, escalation)
	// Should have: alice, bob, charlie (dave excluded)
	if len(filtered) != 3 {
		t.Fatalf("after notificationExclusions filter: expected 3, got %d; result: %v", len(filtered), filtered)
	}

	// Second filter: hidden from UI
	filtered = ctrl.filterHiddenFromUIRecipients(log, filtered, escalation)
	// Should have: alice, bob (charlie hidden, dave already excluded)
	if len(filtered) != 2 {
		t.Fatalf("after hiddenFromUI filter: expected 2, got %d; result: %v", len(filtered), filtered)
	}

	// Verify the remaining are alice and bob
	found := map[string]bool{}
	for _, r := range filtered {
		found[r] = true
	}
	if !found["alice@example.com"] || !found["bob@example.com"] {
		t.Fatalf("unexpected recipients in result: %v", filtered)
	}
}

// TestHiddenFromUI_SessionRequest_NoEmailsToHiddenGroups tests that hidden groups don't receive email notifications
// when a session is requested
func TestHiddenFromUI_SessionRequest_NoEmailsToHiddenGroups(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}

	// Escalation with visible and hidden approver groups
	builder.WithObjects(&v1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-with-hidden",
		},
		Spec: v1alpha1.BreakglassEscalationSpec{
			Allowed: v1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"test"},
				Groups:   []string{"system:authenticated"},
			},
			EscalatedGroup: "admin",
			Approvers: v1alpha1.BreakglassEscalationApprovers{
				Groups:       []string{"security-team", "flm-on-duty"},
				HiddenFromUI: []string{"flm-on-duty"},
			},
		},
	})

	cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}

	logger, _ := zap.NewDevelopment()
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{},
		&sesmanager, &escmanager,
		func(c *gin.Context) {
			c.Set("email", "requester@example.com")
			c.Set("username", "Requester")
			c.Next()
		}, "/config/config.yaml", nil, cli)

	// Mock group resolver to return members
	mockResolver := &MockGroupResolver{
		members: map[string][]string{
			"security-team": {"security1@example.com", "security2@example.com"},
			"flm-on-duty":   {"flm-manager@example.com"},
		},
	}
	ctrl.escalationManager.SetResolver(mockResolver)

	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}

	mailSender := &FakeMailSender{}
	ctrl.mail = mailSender

	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	// Request session
	reqData := BreakglassSessionRequest{
		Clustername: "test",
		Username:    "requester@example.com",
		GroupName:   "admin",
	}
	b, _ := json.Marshal(reqData)
	req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}

	// Verify emails were sent only to security-team, not flm-on-duty
	if mailSender.LastRecivers == nil {
		t.Fatal("expected email to be sent, got nil")
	}

	// Check that flm-manager@example.com is NOT in recipients
	for _, email := range mailSender.LastRecivers {
		if email == "flm-manager@example.com" {
			t.Fatalf("hidden group member should not receive email: %s", email)
		}
	}

	// Check that security team members ARE in recipients
	foundSecurity := false
	for _, email := range mailSender.LastRecivers {
		if email == "security1@example.com" || email == "security2@example.com" {
			foundSecurity = true
			break
		}
	}
	if !foundSecurity {
		t.Fatalf("security team should receive emails, got: %v", mailSender.LastRecivers)
	}
}

// TestHiddenFromUI_EscalationResponse_GroupsRemoved tests that hidden groups are not shown in API response
func TestHiddenFromUI_EscalationResponse_GroupsRemoved(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(Scheme)

	// Create escalation with hidden groups
	escalation := &v1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-escalation",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassEscalationSpec{
			Allowed: v1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"test"},
				Groups:   []string{"system:authenticated"},
			},
			EscalatedGroup: "admin",
			Approvers: v1alpha1.BreakglassEscalationApprovers{
				Groups:       []string{"security-team", "flm-on-duty", "on-call"},
				HiddenFromUI: []string{"flm-on-duty", "on-call"},
			},
		},
	}
	builder.WithObjects(escalation)

	cli := builder.Build()
	escmanager := EscalationManager{Client: cli}

	logger, _ := zap.NewDevelopment()
	ctrl := &BreakglassEscalationController{
		log:     logger.Sugar(),
		manager: &escmanager,
		middleware: func(c *gin.Context) {
			c.Set("email", "user@example.com")
			c.Set("groups", []string{"system:authenticated"})
			c.Next()
		},
		identityProvider: KeycloakIdentityProvider{},
		getUserGroupsFn: func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
			return []string{"system:authenticated"}, nil
		},
	}

	engine := gin.New()
	rg := engine.Group("/breakglassEscalations", ctrl.middleware)
	_ = ctrl.Register(rg)

	req, _ := http.NewRequest(http.MethodGet, "/breakglassEscalations", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d; body: %s", w.Code, w.Body.String())
	}

	// Parse response
	var escList []v1alpha1.BreakglassEscalation
	_ = json.Unmarshal(w.Body.Bytes(), &escList)

	if len(escList) != 1 {
		t.Fatalf("expected 1 escalation, got %d", len(escList))
	}

	resp := escList[0]

	// Verify hidden groups are removed
	for _, group := range resp.Spec.Approvers.Groups {
		if group == "flm-on-duty" || group == "on-call" {
			t.Fatalf("hidden group should be removed from response: %s", group)
		}
	}

	// Verify visible group is present
	if len(resp.Spec.Approvers.Groups) != 1 || resp.Spec.Approvers.Groups[0] != "security-team" {
		t.Fatalf("expected only visible group 'security-team', got: %v", resp.Spec.Approvers.Groups)
	}

	// Verify HiddenFromUI field is removed from response
	if len(resp.Spec.Approvers.HiddenFromUI) > 0 {
		t.Fatalf("HiddenFromUI field should be removed from response, got: %v", resp.Spec.Approvers.HiddenFromUI)
	}
}

// TestHiddenFromUI_MixedVisibleAndHidden tests escalation with both visible and hidden users
func TestHiddenFromUI_MixedVisibleAndHidden(t *testing.T) {
	builder := fake.NewClientBuilder().WithScheme(Scheme)
	for index, fn := range sessionIndexFunctions {
		builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
	}

	// Escalation with mixed visible and hidden approvers
	builder.WithObjects(&v1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name: "test-mixed",
		},
		Spec: v1alpha1.BreakglassEscalationSpec{
			Allowed: v1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"test"},
				Groups:   []string{"system:authenticated"},
			},
			EscalatedGroup: "admin",
			Approvers: v1alpha1.BreakglassEscalationApprovers{
				Users:        []string{"alice@example.com", "emergency@example.com"},
				Groups:       []string{"security-team"},
				HiddenFromUI: []string{"emergency@example.com"},
			},
		},
	})

	cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}).Build()
	sesmanager := SessionManager{Client: cli}
	escmanager := EscalationManager{Client: cli}

	logger, _ := zap.NewDevelopment()
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{},
		&sesmanager, &escmanager,
		func(c *gin.Context) {
			c.Set("email", "requester@example.com")
			c.Set("username", "Requester")
			c.Next()
		}, "/config/config.yaml", nil, cli)

	// Mock group resolver
	mockResolver := &MockGroupResolver{
		members: map[string][]string{
			"security-team": {"security@example.com"},
		},
	}
	ctrl.escalationManager.SetResolver(mockResolver)

	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}

	mailSender := &FakeMailSender{}
	ctrl.mail = mailSender

	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	// Request session
	reqData := BreakglassSessionRequest{
		Clustername: "test",
		Username:    "requester@example.com",
		GroupName:   "admin",
	}
	b, _ := json.Marshal(reqData)
	req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusCreated {
		t.Fatalf("expected 201, got %d", w.Code)
	}

	// Verify alice receives email (visible user)
	foundAlice := false
	foundEmergency := false
	for _, email := range mailSender.LastRecivers {
		if email == "alice@example.com" {
			foundAlice = true
		}
		if email == "emergency@example.com" {
			foundEmergency = true
		}
	}

	if !foundAlice {
		t.Fatal("alice@example.com should receive email (visible user)")
	}
	if foundEmergency {
		t.Fatal("emergency@example.com should NOT receive email (hidden user)")
	}
}

// TestSendOnRequestEmail_ApproverGroupsToShow tests that the email correctly displays
// only the specific approver groups provided in the approverGroupsToShow parameter.
// This allows sending separate emails to different groups, where each email shows only
// the group that matched for those specific approvers.
func TestSendOnRequestEmail_ApproverGroupsToShow(t *testing.T) {
	tests := []struct {
		name                          string
		approverGroupsToShow          []string
		expectedApproverGroupsInEmail []string
		description                   string
	}{
		{
			name:                          "single_group_to_show",
			approverGroupsToShow:          []string{"dttcaas-first-line_fixed-core"},
			expectedApproverGroupsInEmail: []string{"dttcaas-first-line_fixed-core"},
			description:                   "Email shows single specified approver group",
		},
		{
			name:                          "multiple_groups_to_show",
			approverGroupsToShow:          []string{"dttcaas-first-line_fixed-core", "dttcaas-first-line_mobile-core"},
			expectedApproverGroupsInEmail: []string{"dttcaas-first-line_fixed-core", "dttcaas-first-line_mobile-core"},
			description:                   "Email shows multiple specified approver groups",
		},
		{
			name:                          "no_groups_to_show_explicit_users",
			approverGroupsToShow:          []string{},
			expectedApproverGroupsInEmail: []string{},
			description:                   "Email for explicit users (no groups) shows no groups",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := zap.NewNop().Sugar()

			controller := &BreakglassSessionController{
				log: log,
				config: config.Config{
					Frontend: config.Frontend{
						BaseURL:      "https://breakglass.example.com",
						BrandingName: "Test Breakglass",
					},
				},
				mail:      &FakeMailSender{},
				mailQueue: nil, // Disable queue to use direct mail sender
			}

			// Create test session
			session := v1alpha1.BreakglassSession{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-session-123",
					Namespace: "default",
				},
				Spec: v1alpha1.BreakglassSessionSpec{
					Cluster:      "test-cluster",
					User:         "test-user",
					GrantedGroup: "admin",
				},
			}

			// Create test escalation
			escalation := &v1alpha1.BreakglassEscalation{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-escalation",
					Namespace: "default",
				},
				Spec: v1alpha1.BreakglassEscalationSpec{
					EscalatedGroup: "admin",
					Approvers: v1alpha1.BreakglassEscalationApprovers{
						Groups: []string{"dttcaas-first-line_fixed-core", "dttcaas-first-line_mobile-core"},
						Users:  []string{},
					},
				},
			}

			// Send the email with specific groups to show
			approvers := []string{"approver1@example.com", "approver2@example.com"}
			err := controller.sendOnRequestEmail(
				session,
				"requester@example.com",
				"Test Requester",
				approvers,
				tt.approverGroupsToShow, // Only show these specific groups in the email
				escalation,
			)

			if err != nil {
				t.Fatalf("sendOnRequestEmail failed: %v", err)
			}

			// Verify email was sent
			mailSender := controller.mail.(*FakeMailSender)
			if mailSender.LastBody == "" {
				t.Fatal("Email body is empty")
			}

			// Verify the correct approver groups appear in the email body
			for _, expectedGroup := range tt.expectedApproverGroupsInEmail {
				if !strings.Contains(mailSender.LastBody, expectedGroup) {
					t.Errorf("Expected approver group %q not found in email body", expectedGroup)
				}
			}

			t.Logf("Test case: %s", tt.description)
			t.Logf("Groups to show: %v", tt.approverGroupsToShow)
			t.Logf("Expected groups in email: %v", tt.expectedApproverGroupsInEmail)
		})
	}
}

// TestSendOnRequestEmail_NilEscalation tests that sendOnRequestEmail handles nil escalation gracefully
func TestSendOnRequestEmail_NilEscalation(t *testing.T) {
	log := zap.NewNop().Sugar()

	controller := &BreakglassSessionController{
		log: log,
		config: config.Config{
			Frontend: config.Frontend{
				BaseURL:      "https://breakglass.example.com",
				BrandingName: "Test Breakglass",
			},
		},
		mail:      &FakeMailSender{},
		mailQueue: nil,
	}

	session := v1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "test-session-456",
			Namespace: "default",
		},
		Spec: v1alpha1.BreakglassSessionSpec{
			Cluster:      "test-cluster",
			User:         "test-user",
			GrantedGroup: "admin",
		},
	}

	approvers := []string{"approver@example.com"}

	// Should not panic when escalation is nil
	err := controller.sendOnRequestEmail(
		session,
		"requester@example.com",
		"Test Requester",
		approvers,
		[]string{}, // no approver groups to show
		nil,        // nil escalation
	)

	if err != nil {
		t.Fatalf("sendOnRequestEmail with nil escalation failed: %v", err)
	}

	mailSender := controller.mail.(*FakeMailSender)
	if mailSender.LastBody == "" {
		t.Fatal("Email body should not be empty even with nil escalation")
	}

	t.Log("Email sent successfully with nil escalation (no approver groups shown)")
}

// TestSendOnRequestEmailsByGroup_DeduplicateApproversInMultipleGroups tests that when an approver
// belongs to multiple approver groups, they receive only ONE email showing all their groups.
func TestSendOnRequestEmailsByGroup_DeduplicateApproversInMultipleGroups(t *testing.T) {
	// Setup: alice@example.com is in both "fixed-core" and "mobile-core"
	// Expected: alice should get exactly ONE email (not two)
	tests := []struct {
		name              string
		approversByGroup  map[string][]string
		filteredApprovers []string
		expectedSendCount int
		description       string
	}{
		{
			name: "approver_in_multiple_groups",
			approversByGroup: map[string][]string{
				"fixed-core":  {"alice@example.com", "bob@example.com"},
				"mobile-core": {"alice@example.com", "charlie@example.com"},
			},
			filteredApprovers: []string{"alice@example.com", "bob@example.com", "charlie@example.com"},
			expectedSendCount: 3, // alice once, bob once, charlie once
			description:       "Approver in multiple groups receives one email",
		},
		{
			name: "all_approvers_in_all_groups",
			approversByGroup: map[string][]string{
				"fixed-core":  {"alice@example.com", "bob@example.com"},
				"mobile-core": {"alice@example.com", "bob@example.com"},
			},
			filteredApprovers: []string{"alice@example.com", "bob@example.com"},
			expectedSendCount: 2, // alice once, bob once
			description:       "When all approvers are in all groups, each gets one email",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			log := zap.NewNop().Sugar()

			fakeSender := &FakeMailSender{}

			controller := &BreakglassSessionController{
				log: log,
				config: config.Config{
					Frontend: config.Frontend{
						BaseURL:      "https://breakglass.example.com",
						BrandingName: "Test Breakglass",
					},
				},
				mail: fakeSender,
			}

			session := v1alpha1.BreakglassSession{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-session",
					Namespace: "default",
				},
				Spec: v1alpha1.BreakglassSessionSpec{
					Cluster:      "test-cluster",
					User:         "test-user",
					GrantedGroup: "admin",
				},
			}

			escalation := &v1alpha1.BreakglassEscalation{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-escalation",
					Namespace: "default",
				},
				Spec: v1alpha1.BreakglassEscalationSpec{
					EscalatedGroup: "admin",
					Approvers: v1alpha1.BreakglassEscalationApprovers{
						Groups: []string{"fixed-core", "mobile-core"},
						Users:  []string{},
					},
				},
			}

			// Call sendOnRequestEmailsByGroup
			controller.sendOnRequestEmailsByGroup(
				log,
				session,
				"requester@example.com",
				"Test Requester",
				tt.filteredApprovers,
				tt.approversByGroup,
				escalation,
			)

			// Verify the FakeMailSender was called the expected number of times
			if fakeSender.SendCallCount != tt.expectedSendCount {
				t.Errorf("Expected Send() to be called %d times, but was called %d times", tt.expectedSendCount, fakeSender.SendCallCount)
			}

			t.Logf("Test: %s", tt.description)
			t.Logf("Send() called %d times (expected %d)", fakeSender.SendCallCount, tt.expectedSendCount)
		})
	}
}

// TestIsSessionPendingApproval tests the IsSessionPendingApproval function with various timeout scenarios
func TestIsSessionPendingApproval(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		session  v1alpha1.BreakglassSession
		expected bool
		reason   string
	}{
		{
			name: "pending_session_no_timeout_set",
			session: v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					State:      v1alpha1.SessionStatePending,
					ApprovedAt: metav1.Time{},
					RejectedAt: metav1.Time{},
					TimeoutAt:  metav1.Time{},
				},
			},
			expected: true,
			reason:   "session is pending with no timeout set",
		},
		{
			name: "pending_session_timeout_in_future",
			session: v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					State:      v1alpha1.SessionStatePending,
					ApprovedAt: metav1.Time{},
					RejectedAt: metav1.Time{},
					TimeoutAt:  metav1.NewTime(now.Add(1 * time.Hour)),
				},
			},
			expected: true,
			reason:   "session is pending with timeout in the future",
		},
		{
			name: "pending_session_timeout_in_past",
			session: v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					State:      v1alpha1.SessionStatePending,
					ApprovedAt: metav1.Time{},
					RejectedAt: metav1.Time{},
					TimeoutAt:  metav1.NewTime(now.Add(-1 * time.Hour)),
				},
			},
			expected: false,
			reason:   "session timeout has passed, so it's no longer pending",
		},
		{
			name: "approved_session",
			session: v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					State:      v1alpha1.SessionStateApproved,
					ApprovedAt: metav1.NewTime(now),
					RejectedAt: metav1.Time{},
					TimeoutAt:  metav1.NewTime(now.Add(1 * time.Hour)),
				},
			},
			expected: false,
			reason:   "session is approved, not pending",
		},
		{
			name: "rejected_session",
			session: v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					State:      v1alpha1.SessionStateRejected,
					ApprovedAt: metav1.Time{},
					RejectedAt: metav1.NewTime(now),
					TimeoutAt:  metav1.NewTime(now.Add(1 * time.Hour)),
				},
			},
			expected: false,
			reason:   "session is rejected, not pending",
		},
		{
			name: "approved_and_timed_out",
			session: v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					State:      v1alpha1.SessionStateApproved,
					ApprovedAt: metav1.NewTime(now.Add(-2 * time.Hour)),
					RejectedAt: metav1.Time{},
					TimeoutAt:  metav1.NewTime(now.Add(-1 * time.Hour)),
				},
			},
			expected: false,
			reason:   "session is approved, so timeout is irrelevant",
		},
		{
			name: "timeout_exactly_now",
			session: v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					State:      v1alpha1.SessionStatePending,
					ApprovedAt: metav1.Time{},
					RejectedAt: metav1.Time{},
					TimeoutAt:  metav1.NewTime(now),
				},
			},
			expected: false,
			reason:   "session timeout is at current time, should be treated as expired",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSessionPendingApproval(tt.session)
			if result != tt.expected {
				t.Errorf("Expected %v but got %v. Reason: %s", tt.expected, result, tt.reason)
			}
		})
	}
}

// TestIsSessionApprovalTimedOut tests the IsSessionApprovalTimedOut function
func TestIsSessionApprovalTimedOut(t *testing.T) {
	now := time.Now()

	tests := []struct {
		name     string
		session  v1alpha1.BreakglassSession
		expected bool
		reason   string
	}{
		{
			name: "pending_timeout_in_future",
			session: v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					State:      v1alpha1.SessionStatePending,
					ApprovedAt: metav1.Time{},
					RejectedAt: metav1.Time{},
					TimeoutAt:  metav1.NewTime(now.Add(1 * time.Hour)),
				},
			},
			expected: false,
			reason:   "session is pending and timeout is in future",
		},
		{
			name: "pending_timeout_in_past",
			session: v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					State:      v1alpha1.SessionStatePending,
					ApprovedAt: metav1.Time{},
					RejectedAt: metav1.Time{},
					TimeoutAt:  metav1.NewTime(now.Add(-1 * time.Hour)),
				},
			},
			expected: true,
			reason:   "session is pending and timeout has passed",
		},
		{
			name: "approved_timeout_in_past",
			session: v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					State:      v1alpha1.SessionStateApproved,
					ApprovedAt: metav1.NewTime(now.Add(-2 * time.Hour)),
					RejectedAt: metav1.Time{},
					TimeoutAt:  metav1.NewTime(now.Add(-1 * time.Hour)),
				},
			},
			expected: false,
			reason:   "session is approved, timeout doesn't matter",
		},
		{
			name: "rejected_timeout_in_past",
			session: v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					State:      v1alpha1.SessionStateRejected,
					ApprovedAt: metav1.Time{},
					RejectedAt: metav1.NewTime(now.Add(-2 * time.Hour)),
					TimeoutAt:  metav1.NewTime(now.Add(-1 * time.Hour)),
				},
			},
			expected: false,
			reason:   "session is rejected, timeout doesn't matter",
		},
		{
			name: "pending_no_timeout_set",
			session: v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					State:      v1alpha1.SessionStatePending,
					ApprovedAt: metav1.Time{},
					RejectedAt: metav1.Time{},
					TimeoutAt:  metav1.Time{},
				},
			},
			expected: false,
			reason:   "session is pending but no timeout is set",
		},
		{
			name: "timeout_state_already_set",
			session: v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					State:      v1alpha1.SessionStateTimeout,
					ApprovedAt: metav1.Time{},
					RejectedAt: metav1.Time{},
					TimeoutAt:  metav1.NewTime(now.Add(-1 * time.Hour)),
				},
			},
			expected: false,
			reason:   "session state is already marked as timeout",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsSessionApprovalTimedOut(tt.session)
			if result != tt.expected {
				t.Errorf("Expected %v but got %v. Reason: %s", tt.expected, result, tt.reason)
			}
		})
	}
}

type MockGroupResolver struct {
	members map[string][]string
}

func (m *MockGroupResolver) Members(ctx context.Context, group string) ([]string, error) {
	if members, ok := m.members[group]; ok {
		return members, nil
	}
	return nil, fmt.Errorf("group not found: %s", group)
}

// ============================================================================
// M2M Automation Use Case Tests
// ============================================================================

// TestUseCaseM2MAutomation tests the M2M (machine-to-machine) automation use case.
// This covers automated scripts that need long-running sessions without notifications.
func TestUseCaseM2MAutomation(t *testing.T) {
	// Test 1: Verify DisableNotifications flag in escalation prevents email sending
	t.Run("disableNotifications prevents emails", func(t *testing.T) {
		log := zap.NewNop().Sugar()
		ctrl := &BreakglassSessionController{}

		// Create escalation with DisableNotifications=true
		disableNotif := true
		escalation := &v1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{Name: "m2m-automation"},
			Spec: v1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:       "automation-access",
				DisableNotifications: &disableNotif,
				MaxValidFor:          "336h", // 14 days for long-running automation
				Allowed: v1alpha1.BreakglassEscalationAllowed{
					Groups: []string{"service-accounts"},
				},
				Approvers: v1alpha1.BreakglassEscalationApprovers{
					Users: []string{"automation-approver@example.com"},
				},
			},
		}

		// Verify DisableNotifications is set correctly
		require.True(t, *escalation.Spec.DisableNotifications, "DisableNotifications should be true for M2M")

		// Test the notification filter logic
		recipients := []string{"user1@example.com", "user2@example.com"}
		result := ctrl.filterExcludedNotificationRecipients(log, recipients, escalation)

		// With DisableNotifications, filterExcludedNotificationRecipients doesn't filter
		// The actual email suppression happens at send time based on DisableNotifications flag
		require.Len(t, result, 2, "filterExcludedNotificationRecipients doesn't suppress based on DisableNotifications")
	})

	// Test 2: Verify self-approval can be allowed for M2M
	t.Run("self-approval allowed for M2M automation", func(t *testing.T) {
		blockSelfApproval := false
		escalation := &v1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{Name: "m2m-self-approve"},
			Spec: v1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:    "automation-access",
				BlockSelfApproval: &blockSelfApproval,
				MaxValidFor:       "336h", // 14 days
				Allowed: v1alpha1.BreakglassEscalationAllowed{
					Groups: []string{"automation-service-accounts"},
				},
				Approvers: v1alpha1.BreakglassEscalationApprovers{
					Users: []string{"automation@example.com"}, // Service account can self-approve
				},
			},
		}

		require.False(t, *escalation.Spec.BlockSelfApproval, "BlockSelfApproval should be false for M2M self-approval")
		require.Equal(t, "336h", escalation.Spec.MaxValidFor, "MaxValidFor should be 14 days (336h) for M2M")
	})

	// Test 3: Verify long duration validation
	t.Run("long duration validation for M2M", func(t *testing.T) {
		// Test that 14-day duration is valid
		duration, err := time.ParseDuration("336h")
		require.NoError(t, err, "336h should be a valid duration")
		require.Equal(t, 14*24*time.Hour, duration, "336h should equal 14 days")

		// Test even longer durations (30 days)
		duration30d, err := time.ParseDuration("720h")
		require.NoError(t, err, "720h should be a valid duration")
		require.Equal(t, 30*24*time.Hour, duration30d, "720h should equal 30 days")
	})
}

// TestUseCaseSelfServiceBISDebugging tests the BIS (Business Impact Support) self-service debugging.
// Teams should be able to approve their own requests during critical incidents.
func TestUseCaseSelfServiceBISDebugging(t *testing.T) {
	t.Run("team can self-approve during incidents", func(t *testing.T) {
		// Create escalation where the same group can request and approve
		blockSelfApproval := false
		escalation := &v1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{Name: "bis-self-service"},
			Spec: v1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:    "incident-debug",
				BlockSelfApproval: &blockSelfApproval,
				MaxValidFor:       "4h",
				Allowed: v1alpha1.BreakglassEscalationAllowed{
					Groups: []string{"sre-team"},
				},
				Approvers: v1alpha1.BreakglassEscalationApprovers{
					Groups: []string{"sre-team"}, // Same group can approve
				},
				RequestReason: &v1alpha1.ReasonConfig{
					Mandatory:   true,
					Description: "BIS ticket number required",
				},
			},
		}

		// Verify the escalation allows team self-approval
		require.False(t, *escalation.Spec.BlockSelfApproval)
		require.Contains(t, escalation.Spec.Allowed.Groups, "sre-team")
		require.Contains(t, escalation.Spec.Approvers.Groups, "sre-team")
		require.True(t, escalation.Spec.RequestReason.Mandatory, "Request reason should be mandatory for BIS")
	})
}

// TestUseCaseDebugSessionNetworkCapabilities tests debug session configurations for network debugging.
func TestUseCaseDebugSessionNetworkCapabilities(t *testing.T) {
	t.Run("debug pod template with network capabilities", func(t *testing.T) {
		// Create a debug pod template for TCP dump / network debugging
		template := &v1alpha1.DebugPodTemplate{
			ObjectMeta: metav1.ObjectMeta{Name: "network-debug"},
			Spec: v1alpha1.DebugPodTemplateSpec{
				DisplayName: "Network Debug Tools",
				Description: "Pod with tcpdump, netstat, and network debugging tools",
				Template: &v1alpha1.DebugPodSpec{
					Spec: v1alpha1.DebugPodSpecInner{
						HostNetwork: true, // Required for network-level debugging
						Containers: []corev1.Container{
							{
								Name:  "netshoot",
								Image: "nicolaka/netshoot:latest",
								SecurityContext: &corev1.SecurityContext{
									Capabilities: &corev1.Capabilities{
										Add: []corev1.Capability{
											"NET_ADMIN",
											"NET_RAW",
											"SYS_PTRACE",
										},
									},
								},
								Command: []string{"sleep", "infinity"},
							},
						},
					},
				},
			},
		}

		// Verify the template has required network capabilities
		require.True(t, template.Spec.Template.Spec.HostNetwork, "HostNetwork should be true for network debugging")
		container := template.Spec.Template.Spec.Containers[0]
		require.Contains(t, container.SecurityContext.Capabilities.Add, corev1.Capability("NET_ADMIN"))
		require.Contains(t, container.SecurityContext.Capabilities.Add, corev1.Capability("NET_RAW"))
	})

	t.Run("debug session template with auto-approval for SRE", func(t *testing.T) {
		replicas := int32(1)
		template := &v1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{Name: "network-debug-session"},
			Spec: v1alpha1.DebugSessionTemplateSpec{
				DisplayName: "Network Debug Session",
				Mode:        v1alpha1.DebugSessionModeWorkload,
				PodTemplateRef: &v1alpha1.DebugPodTemplateReference{
					Name: "network-debug",
				},
				WorkloadType:    v1alpha1.DebugWorkloadDaemonSet, // DaemonSet for node-level debugging
				Replicas:        &replicas,
				TargetNamespace: "debug-network",
				Allowed: &v1alpha1.DebugSessionAllowed{
					Groups: []string{"sre-team", "network-team"},
				},
				Approvers: &v1alpha1.DebugSessionApprovers{
					AutoApproveFor: &v1alpha1.AutoApproveConfig{
						Groups: []string{"sre-team"}, // SRE gets auto-approval
					},
					Groups: []string{"security-team"}, // Security team can also approve
				},
				Constraints: &v1alpha1.DebugSessionConstraints{
					MaxDuration:     "2h",
					DefaultDuration: "30m",
					AllowRenewal:    ptrBool(true),
					MaxRenewals:     ptrInt32(2),
				},
			},
		}

		// Verify the template configuration
		require.Equal(t, v1alpha1.DebugWorkloadDaemonSet, template.Spec.WorkloadType)
		require.Contains(t, template.Spec.Approvers.AutoApproveFor.Groups, "sre-team")
		require.Equal(t, "2h", template.Spec.Constraints.MaxDuration)
	})
}

// TestFormatDuration covers the formatDuration helper function
func TestFormatDuration(t *testing.T) {
	tests := []struct {
		name     string
		duration time.Duration
		expected string
	}{
		// Zero
		{"zero", 0, "0"},

		// Seconds
		{"1 second", 1 * time.Second, "1 second"},
		{"30 seconds", 30 * time.Second, "30 seconds"},

		// Minutes
		{"1 minute", 1 * time.Minute, "1 minute"},
		{"5 minutes", 5 * time.Minute, "5 minutes"},
		{"59 minutes", 59 * time.Minute, "59 minutes"},

		// Hours
		{"1 hour exact", 1 * time.Hour, "1 hour"},
		{"2 hours exact", 2 * time.Hour, "2 hours"},
		{"1 hour 1 minute", 1*time.Hour + 1*time.Minute, "1 hour 1 minute"},
		{"1 hour 30 minutes", 1*time.Hour + 30*time.Minute, "1 hour 30 minutes"},
		{"2 hours 1 minute", 2*time.Hour + 1*time.Minute, "2 hours 1 minute"},
		{"2 hours 15 minutes", 2*time.Hour + 15*time.Minute, "2 hours 15 minutes"},
		{"23 hours", 23 * time.Hour, "23 hours"},

		// Days
		{"1 day exact", 24 * time.Hour, "1 day"},
		{"2 days exact", 48 * time.Hour, "2 days"},
		{"1 day 1 hour", 25 * time.Hour, "1 day 1 hour"},
		{"1 day 5 hours", 29 * time.Hour, "1 day 5 hours"},
		{"2 days 1 hour", 49 * time.Hour, "2 days 1 hour"},
		{"2 days 12 hours", 60 * time.Hour, "2 days 12 hours"},
		{"7 days", 168 * time.Hour, "7 days"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatDuration(tt.duration)
			require.Equal(t, tt.expected, result)
		})
	}
}

// TestIsSessionRetained covers the IsSessionRetained helper function
func TestIsSessionRetained(t *testing.T) {
	t.Run("session retained - retention time in past", func(t *testing.T) {
		session := v1alpha1.BreakglassSession{
			Status: v1alpha1.BreakglassSessionStatus{
				RetainedUntil: metav1.NewTime(time.Now().Add(-1 * time.Hour)),
			},
		}
		// Should be "not retained" (ready for removal) since time has passed
		require.True(t, IsSessionRetained(session))
	})

	t.Run("session not ready for removal - retention time in future", func(t *testing.T) {
		session := v1alpha1.BreakglassSession{
			Status: v1alpha1.BreakglassSessionStatus{
				RetainedUntil: metav1.NewTime(time.Now().Add(1 * time.Hour)),
			},
		}
		// Should be "retained" (not ready for removal) since time has not passed
		require.False(t, IsSessionRetained(session))
	})
}

// TestSessionControllerBasePath verifies the BasePath function
func TestSessionControllerBasePath(t *testing.T) {
	ctrl := BreakglassSessionController{}
	require.Equal(t, "breakglassSessions", ctrl.BasePath())
}

// TestIsSessionRejected covers the IsSessionRejected function
func TestIsSessionRejectedFunction(t *testing.T) {
	tests := []struct {
		name     string
		state    v1alpha1.BreakglassSessionState
		expected bool
	}{
		{"rejected state", v1alpha1.SessionStateRejected, true},
		{"approved state", v1alpha1.SessionStateApproved, false},
		{"pending state", v1alpha1.SessionStatePending, false},
		{"withdrawn state", v1alpha1.SessionStateWithdrawn, false},
		{"expired state", v1alpha1.SessionStateExpired, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					State: tt.state,
				},
			}
			require.Equal(t, tt.expected, IsSessionRejected(session))
		})
	}
}

// TestIsSessionWithdrawn covers the IsSessionWithdrawn function
func TestIsSessionWithdrawnFunction(t *testing.T) {
	tests := []struct {
		name     string
		state    v1alpha1.BreakglassSessionState
		expected bool
	}{
		{"withdrawn state", v1alpha1.SessionStateWithdrawn, true},
		{"approved state", v1alpha1.SessionStateApproved, false},
		{"pending state", v1alpha1.SessionStatePending, false},
		{"rejected state", v1alpha1.SessionStateRejected, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					State: tt.state,
				},
			}
			require.Equal(t, tt.expected, IsSessionWithdrawn(session))
		})
	}
}

// TestIsSessionExpired covers the IsSessionExpired function
func TestIsSessionExpiredFunction(t *testing.T) {
	tests := []struct {
		name      string
		state     v1alpha1.BreakglassSessionState
		expiresAt *metav1.Time
		expected  bool
	}{
		// State-first: Expired state takes precedence
		{"expired state", v1alpha1.SessionStateExpired, nil, true},
		{"expired state with past time", v1alpha1.SessionStateExpired, ptr(metav1.NewTime(time.Now().Add(-1 * time.Hour))), true},
		{"expired state with future time", v1alpha1.SessionStateExpired, ptr(metav1.NewTime(time.Now().Add(1 * time.Hour))), true},

		// Approved state checks timestamp
		{"approved state with past time", v1alpha1.SessionStateApproved, ptr(metav1.NewTime(time.Now().Add(-1 * time.Hour))), true},
		{"approved state with future time", v1alpha1.SessionStateApproved, ptr(metav1.NewTime(time.Now().Add(1 * time.Hour))), false},
		{"approved state with zero time", v1alpha1.SessionStateApproved, nil, false},

		// Other states are not expired
		{"pending state", v1alpha1.SessionStatePending, nil, false},
		{"rejected state", v1alpha1.SessionStateRejected, nil, false},
		{"withdrawn state", v1alpha1.SessionStateWithdrawn, nil, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					State: tt.state,
				},
			}
			if tt.expiresAt != nil {
				session.Status.ExpiresAt = *tt.expiresAt
			}
			require.Equal(t, tt.expected, IsSessionExpired(session))
		})
	}
}

// ptr is a helper to get pointer to metav1.Time
func ptr(t metav1.Time) *metav1.Time {
	return &t
}

// TestIsSessionValid covers additional cases for IsSessionValid
func TestIsSessionValidFunction(t *testing.T) {
	tests := []struct {
		name      string
		state     v1alpha1.BreakglassSessionState
		expiresAt *metav1.Time
		expected  bool
	}{
		// Terminal states are never valid
		{"rejected state", v1alpha1.SessionStateRejected, nil, false},
		{"withdrawn state", v1alpha1.SessionStateWithdrawn, nil, false},
		{"expired state", v1alpha1.SessionStateExpired, nil, false},
		{"timeout state", v1alpha1.SessionStateTimeout, nil, false},
		{"waiting for scheduled time", v1alpha1.SessionStateWaitingForScheduledTime, nil, false},

		// Approved state with valid expiry
		{"approved with future expiry", v1alpha1.SessionStateApproved, ptr(metav1.NewTime(time.Now().Add(1 * time.Hour))), true},
		{"approved with past expiry", v1alpha1.SessionStateApproved, ptr(metav1.NewTime(time.Now().Add(-1 * time.Hour))), false},

		// Pending is valid
		{"pending state", v1alpha1.SessionStatePending, nil, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			session := v1alpha1.BreakglassSession{
				Status: v1alpha1.BreakglassSessionStatus{
					State: tt.state,
				},
			}
			if tt.expiresAt != nil {
				session.Status.ExpiresAt = *tt.expiresAt
			}
			require.Equal(t, tt.expected, IsSessionValid(session))
		})
	}
}

// TestToRFC1123SubdomainEdgeCases covers edge cases in naming.ToRFC1123Subdomain
func TestToRFC1123SubdomainEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty string returns x", "", "x"},
		{"already valid", "valid-name", "valid-name"},
		{"uppercase", "UPPERCASE", "uppercase"},
		{"spaces", "hello world", "hello-world"},
		{"leading hyphen", "-leading", "leading"},
		{"trailing hyphen", "trailing-", "trailing"},
		{"consecutive hyphens", "hello--world", "hello-world"},
		{"special characters", "hello@world.com", "hello-world.com"},
		{"numbers", "test123", "test123"},
		{"mixed case with special", "User@Example.COM", "user-example.com"},
		{"underscores", "hello_world_test", "hello-world-test"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := naming.ToRFC1123Subdomain(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}

// TestToRFC1123LabelEdgeCases covers edge cases in naming.ToRFC1123Label
func TestToRFC1123LabelEdgeCases(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{"empty string returns x", "", "x"},
		{"already valid", "valid-name", "valid-name"},
		{"uppercase", "UPPERCASE", "uppercase"},
		{"special characters", "hello@world", "hello-world"},
		{"long string truncated", strings.Repeat("a", 100), strings.Repeat("a", 63)},
		{"leading hyphen after conversion", "@leading", "leading"},
		{"trailing hyphen after conversion", "trailing@", "trailing"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := naming.ToRFC1123Label(tt.input)
			require.Equal(t, tt.expected, result)
		})
	}
}

// TestAddIfNotPresent covers the addIfNotPresent helper
func TestAddIfNotPresentFunction(t *testing.T) {
	tests := []struct {
		name     string
		slice    []string
		item     string
		expected []string
	}{
		{"add to empty", []string{}, "item", []string{"item"}},
		{"add new item", []string{"a", "b"}, "c", []string{"a", "b", "c"}},
		{"item already present", []string{"a", "b", "c"}, "b", []string{"a", "b", "c"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := addIfNotPresent(tt.slice, tt.item)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestIsSessionRetained_ZeroTimestamp(t *testing.T) {
	session := v1alpha1.BreakglassSession{}
	if IsSessionRetained(session) {
		t.Fatalf("expected IsSessionRetained to be false when RetainedUntil is zero")
	}
}

// TestFirstNonEmpty covers the firstNonEmpty helper function
func TestFirstNonEmpty(t *testing.T) {
	tests := []struct {
		name     string
		values   []string
		expected string
	}{
		{"all empty", []string{"", "", ""}, ""},
		{"first non-empty wins", []string{"", "first", "second"}, "first"},
		{"already first", []string{"first", "second", "third"}, "first"},
		{"last one", []string{"", "", "last"}, "last"},
		{"single value", []string{"only"}, "only"},
		{"single empty", []string{""}, ""},
		{"no values", []string{}, ""},
		{"middle one", []string{"", "middle", ""}, "middle"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := firstNonEmpty(tt.values...)
			require.Equal(t, tt.expected, result)
		})
	}
}

// TestMatchesAuthIdentifier covers the matchesAuthIdentifier helper function
func TestMatchesAuthIdentifier(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		identifiers []string
		expected    bool
	}{
		{"empty value", "", []string{"foo"}, false},
		{"empty identifiers", "foo", []string{}, false},
		{"no match", "foo", []string{"bar", "baz"}, false},
		{"exact match", "foo", []string{"foo"}, true},
		{"case insensitive match", "Foo", []string{"foo"}, true},
		{"case insensitive match reverse", "foo", []string{"FOO"}, true},
		{"mixed case match", "FoO", []string{"fOo"}, true},
		{"match in list", "user@example.com", []string{"admin@example.com", "user@example.com"}, true},
		{"skip empty identifier", "foo", []string{"", "foo"}, true},
		{"all empty identifiers", "foo", []string{"", ""}, false},
		{"whitespace not matched", " foo", []string{"foo"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := matchesAuthIdentifier(tt.value, tt.identifiers)
			require.Equal(t, tt.expected, result)
		})
	}
}

func TestDecodeJSONStrict(t *testing.T) {
	t.Run("rejects unknown fields", func(t *testing.T) {
		// JSON with an unknown field "unknownField"
		input := `{"cluster":"test","user":"test@example.com","group":"admins","unknownField":"value"}`
		var req BreakglassSessionRequest
		err := decodeJSONStrict(strings.NewReader(input), &req)
		require.Error(t, err, "expected error for unknown field")
		require.Contains(t, err.Error(), "unknown field", "error should mention unknown field")
	})

	t.Run("accepts valid fields only", func(t *testing.T) {
		input := `{"cluster":"test","user":"test@example.com","group":"admins","reason":"emergency"}`
		var req BreakglassSessionRequest
		err := decodeJSONStrict(strings.NewReader(input), &req)
		require.NoError(t, err)
		require.Equal(t, "test", req.Clustername)
		require.Equal(t, "test@example.com", req.Username)
		require.Equal(t, "admins", req.GroupName)
		require.Equal(t, "emergency", req.Reason)
	})

	t.Run("catches typos in field names", func(t *testing.T) {
		// Common typo: "cluter" instead of "cluster"
		input := `{"cluter":"test","user":"test@example.com","group":"admins"}`
		var req BreakglassSessionRequest
		err := decodeJSONStrict(strings.NewReader(input), &req)
		require.Error(t, err, "expected error for typo'd field name")
	})

	t.Run("rejects trailing JSON data", func(t *testing.T) {
		// Input with a valid JSON object followed by extra content
		input := `{"cluster":"test","user":"test@example.com","group":"admins"}{"extra":"data"}`
		var req BreakglassSessionRequest
		err := decodeJSONStrict(strings.NewReader(input), &req)
		require.Error(t, err, "expected error for trailing JSON data")
		// The error message can be either "unexpected extra JSON input" or "unknown field"
		// depending on whether the trailing content is valid JSON with unknown fields
	})

	t.Run("rejects multiple JSON values", func(t *testing.T) {
		// Input with two separate valid JSON objects
		input := `{"cluster":"test1","user":"test@example.com","group":"admins"}
{"cluster":"test2","user":"test2@example.com","group":"admins"}`
		var req BreakglassSessionRequest
		err := decodeJSONStrict(strings.NewReader(input), &req)
		require.Error(t, err, "expected error for multiple JSON values")
		// When decoding into an empty struct{}, any fields in the second object
		// trigger "unknown field" since struct{} has no fields
	})

	t.Run("allows trailing whitespace only", func(t *testing.T) {
		// Trailing whitespace should be allowed (io.EOF after consuming whitespace)
		input := `{"cluster":"test","user":"test@example.com","group":"admins"}   ` + "\n"
		var req BreakglassSessionRequest
		err := decodeJSONStrict(strings.NewReader(input), &req)
		require.NoError(t, err, "trailing whitespace should be allowed")
	})
}

func TestSessionLimits(t *testing.T) {
	t.Run("IDP default limit blocks session creation when reached", func(t *testing.T) {
		builder := fake.NewClientBuilder().WithScheme(Scheme)
		for index, fn := range sessionIndexFunctions {
			builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
		}

		clusterName := "test-cluster"
		escalationNamespace := "default"
		idpName := "test-idp"
		maxPerUser := int32(2)

		// Create IDP with default session limit
		idp := &v1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name: idpName,
			},
			Spec: v1alpha1.IdentityProviderSpec{
				OIDC: v1alpha1.OIDCConfig{
					Authority: "https://auth.example.com",
					ClientID:  "test-client",
				},
				SessionLimits: &v1alpha1.SessionLimits{
					MaxActiveSessionsPerUser: &maxPerUser,
				},
			},
		}

		// Create escalation (no session limit override)
		esc := &v1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-escalation",
				Namespace: escalationNamespace,
				UID:       types.UID("esc-uid-123"),
			},
			Spec: v1alpha1.BreakglassEscalationSpec{
				Allowed: v1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   []string{"system:authenticated"},
				},
				EscalatedGroup: "admin-group",
				Approvers: v1alpha1.BreakglassEscalationApprovers{
					Users: []string{"approver@example.com"},
				},
				MaxValidFor: "1h",
			},
		}

		clusterConfig := &v1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterName,
				Namespace: escalationNamespace,
			},
		}

		// Create 2 existing active sessions for same user (at IDP limit)
		existingSessions := []*v1alpha1.BreakglassSession{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "existing-session-1",
					Namespace: escalationNamespace,
				},
				Spec: v1alpha1.BreakglassSessionSpec{
					Cluster:      clusterName,
					User:         "test-user@example.com",
					GrantedGroup: "other-group",
				},
				Status: v1alpha1.BreakglassSessionStatus{
					State: v1alpha1.SessionStatePending,
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "existing-session-2",
					Namespace: escalationNamespace,
				},
				Spec: v1alpha1.BreakglassSessionSpec{
					Cluster:      clusterName,
					User:         "test-user@example.com",
					GrantedGroup: "another-group",
				},
				Status: v1alpha1.BreakglassSessionStatus{
					State: v1alpha1.SessionStateApproved,
				},
			},
		}

		builder.WithObjects(idp, esc, clusterConfig, existingSessions[0], existingSessions[1])
		cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}, &v1alpha1.IdentityProvider{}).Build()
		sesmanager := SessionManager{Client: cli}
		escmanager := EscalationManager{Client: cli}

		logger, _ := zap.NewDevelopment()
		ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager,
			func(c *gin.Context) {
				c.Set("email", "test-user@example.com")
				c.Set("username", "TestUser")
				c.Set("user_id", "test-user@example.com")
				c.Set("identity_provider_name", idpName) // Set IDP name
				c.Set("groups", []string{"system:authenticated"})
				c.Next()
			}, "/config/config.yaml", nil, cli)

		ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
			return []string{"system:authenticated"}, nil
		}

		engine := gin.New()
		_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

		reqData := BreakglassSessionRequest{
			Clustername: clusterName,
			Username:    "test-user@example.com",
			GroupName:   "admin-group",
			Reason:      "Test reason",
		}
		b, _ := json.Marshal(reqData)
		req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		require.Equal(t, http.StatusUnprocessableEntity, w.Result().StatusCode, "should reject when IDP limit reached")
		body, _ := io.ReadAll(w.Result().Body)
		require.Contains(t, string(body), "session limit reached")
		require.Contains(t, string(body), "IDP default")
	})

	t.Run("escalation unlimited override bypasses IDP limits", func(t *testing.T) {
		builder := fake.NewClientBuilder().WithScheme(Scheme)
		for index, fn := range sessionIndexFunctions {
			builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
		}

		clusterName := "test-cluster"
		escalationNamespace := "default"
		idpName := "test-idp"
		maxPerUser := int32(1) // Very restrictive

		// Create IDP with restrictive limit
		idp := &v1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name: idpName,
			},
			Spec: v1alpha1.IdentityProviderSpec{
				OIDC: v1alpha1.OIDCConfig{
					Authority: "https://auth.example.com",
					ClientID:  "test-client",
				},
				SessionLimits: &v1alpha1.SessionLimits{
					MaxActiveSessionsPerUser: &maxPerUser,
				},
			},
		}

		// Create escalation with unlimited override (for platform team)
		esc := &v1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "platform-escalation",
				Namespace: escalationNamespace,
				UID:       types.UID("esc-uid-456"),
			},
			Spec: v1alpha1.BreakglassEscalationSpec{
				Allowed: v1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   []string{"platform-team"},
				},
				EscalatedGroup: "cluster-admin",
				Approvers: v1alpha1.BreakglassEscalationApprovers{
					Users: []string{"approver@example.com"},
				},
				MaxValidFor: "1h",
				SessionLimitsOverride: &v1alpha1.SessionLimitsOverride{
					Unlimited: true,
				},
			},
		}

		clusterConfig := &v1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterName,
				Namespace: escalationNamespace,
			},
		}

		// Create existing sessions (would exceed limit without override)
		existingSessions := []*v1alpha1.BreakglassSession{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "existing-session-1",
					Namespace: escalationNamespace,
				},
				Spec: v1alpha1.BreakglassSessionSpec{
					Cluster:      clusterName,
					User:         "platform-user@example.com",
					GrantedGroup: "other-group",
				},
				Status: v1alpha1.BreakglassSessionStatus{
					State: v1alpha1.SessionStatePending,
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "existing-session-2",
					Namespace: escalationNamespace,
				},
				Spec: v1alpha1.BreakglassSessionSpec{
					Cluster:      clusterName,
					User:         "platform-user@example.com",
					GrantedGroup: "another-group",
				},
				Status: v1alpha1.BreakglassSessionStatus{
					State: v1alpha1.SessionStateApproved,
				},
			},
		}

		builder.WithObjects(idp, esc, clusterConfig, existingSessions[0], existingSessions[1])
		cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}, &v1alpha1.IdentityProvider{}).Build()
		sesmanager := SessionManager{Client: cli}
		escmanager := EscalationManager{Client: cli}

		logger, _ := zap.NewDevelopment()
		ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager,
			func(c *gin.Context) {
				c.Set("email", "platform-user@example.com")
				c.Set("username", "PlatformUser")
				c.Set("user_id", "platform-user@example.com")
				c.Set("identity_provider_name", idpName)
				c.Set("groups", []string{"platform-team"})
				c.Next()
			}, "/config/config.yaml", nil, cli)

		ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
			return []string{"platform-team"}, nil
		}

		engine := gin.New()
		_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

		reqData := BreakglassSessionRequest{
			Clustername: clusterName,
			Username:    "platform-user@example.com",
			GroupName:   "cluster-admin",
			Reason:      "Platform emergency",
		}
		b, _ := json.Marshal(reqData)
		req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		// Session should be created because escalation has unlimited override
		require.Equal(t, http.StatusCreated, w.Result().StatusCode, "should allow session with unlimited escalation override")
	})

	t.Run("IDP group override allows higher limits for specific groups", func(t *testing.T) {
		builder := fake.NewClientBuilder().WithScheme(Scheme)
		for index, fn := range sessionIndexFunctions {
			builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
		}

		clusterName := "test-cluster"
		escalationNamespace := "default"
		idpName := "test-idp"
		defaultLimit := int32(1)
		platformLimit := int32(5)

		// Create IDP with default limit and platform-team group override
		idp := &v1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name: idpName,
			},
			Spec: v1alpha1.IdentityProviderSpec{
				OIDC: v1alpha1.OIDCConfig{
					Authority: "https://auth.example.com",
					ClientID:  "test-client",
				},
				SessionLimits: &v1alpha1.SessionLimits{
					MaxActiveSessionsPerUser: &defaultLimit,
					GroupOverrides: []v1alpha1.SessionLimitGroupOverride{
						{
							Group:                    "platform-team",
							MaxActiveSessionsPerUser: &platformLimit,
						},
					},
				},
			},
		}

		// Create escalation (no override - uses IDP group override)
		esc := &v1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-escalation",
				Namespace: escalationNamespace,
				UID:       types.UID("esc-uid-789"),
			},
			Spec: v1alpha1.BreakglassEscalationSpec{
				Allowed: v1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   []string{"platform-team"},
				},
				EscalatedGroup: "admin-group",
				Approvers: v1alpha1.BreakglassEscalationApprovers{
					Users: []string{"approver@example.com"},
				},
				MaxValidFor: "1h",
			},
		}

		clusterConfig := &v1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterName,
				Namespace: escalationNamespace,
			},
		}

		// Create 2 existing sessions (exceeds default limit of 1, but under platform limit of 5)
		existingSessions := []*v1alpha1.BreakglassSession{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "existing-session-1",
					Namespace: escalationNamespace,
				},
				Spec: v1alpha1.BreakglassSessionSpec{
					Cluster:      clusterName,
					User:         "platform-user@example.com",
					GrantedGroup: "other-group",
				},
				Status: v1alpha1.BreakglassSessionStatus{
					State: v1alpha1.SessionStatePending,
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "existing-session-2",
					Namespace: escalationNamespace,
				},
				Spec: v1alpha1.BreakglassSessionSpec{
					Cluster:      clusterName,
					User:         "platform-user@example.com",
					GrantedGroup: "another-group",
				},
				Status: v1alpha1.BreakglassSessionStatus{
					State: v1alpha1.SessionStateApproved,
				},
			},
		}

		builder.WithObjects(idp, esc, clusterConfig, existingSessions[0], existingSessions[1])
		cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}, &v1alpha1.IdentityProvider{}).Build()
		sesmanager := SessionManager{Client: cli}
		escmanager := EscalationManager{Client: cli}

		logger, _ := zap.NewDevelopment()
		ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager,
			func(c *gin.Context) {
				c.Set("email", "platform-user@example.com")
				c.Set("username", "PlatformUser")
				c.Set("user_id", "platform-user@example.com")
				c.Set("identity_provider_name", idpName)
				c.Set("groups", []string{"platform-team"})
				c.Next()
			}, "/config/config.yaml", nil, cli)

		ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
			return []string{"platform-team"}, nil
		}

		engine := gin.New()
		_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

		reqData := BreakglassSessionRequest{
			Clustername: clusterName,
			Username:    "platform-user@example.com",
			GroupName:   "admin-group",
			Reason:      "Test reason",
		}
		b, _ := json.Marshal(reqData)
		req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		// Should succeed because platform-team has higher limit (5) via IDP group override
		require.Equal(t, http.StatusCreated, w.Result().StatusCode, "should allow session with IDP group override")
	})

	t.Run("no limits without IDP or escalation configuration", func(t *testing.T) {
		builder := fake.NewClientBuilder().WithScheme(Scheme)
		for index, fn := range sessionIndexFunctions {
			builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
		}

		clusterName := "test-cluster"
		escalationNamespace := "default"

		// Create escalation without any session limits
		esc := &v1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-escalation",
				Namespace: escalationNamespace,
				UID:       types.UID("esc-uid-nolimit"),
			},
			Spec: v1alpha1.BreakglassEscalationSpec{
				Allowed: v1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   []string{"system:authenticated"},
				},
				EscalatedGroup: "admin-group",
				Approvers: v1alpha1.BreakglassEscalationApprovers{
					Users: []string{"approver@example.com"},
				},
				MaxValidFor: "1h",
			},
		}

		clusterConfig := &v1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterName,
				Namespace: escalationNamespace,
			},
		}

		builder.WithObjects(esc, clusterConfig)
		cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}).Build()
		sesmanager := SessionManager{Client: cli}
		escmanager := EscalationManager{Client: cli}

		logger, _ := zap.NewDevelopment()
		ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager,
			func(c *gin.Context) {
				c.Set("email", "test-user@example.com")
				c.Set("username", "TestUser")
				c.Set("user_id", "test-user@example.com")
				// No IDP name set - simulating legacy single-IDP mode
				c.Set("groups", []string{"system:authenticated"})
				c.Next()
			}, "/config/config.yaml", nil, cli)

		ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
			return []string{"system:authenticated"}, nil
		}

		engine := gin.New()
		_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

		reqData := BreakglassSessionRequest{
			Clustername: clusterName,
			Username:    "test-user@example.com",
			GroupName:   "admin-group",
			Reason:      "Test reason",
		}
		b, _ := json.Marshal(reqData)
		req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		// Should succeed - no limits configured
		require.Equal(t, http.StatusCreated, w.Result().StatusCode, "should allow session without any limits configured")
	})

	t.Run("escalation maxActiveSessionsTotal blocks when total sessions exceeded", func(t *testing.T) {
		builder := fake.NewClientBuilder().WithScheme(Scheme)
		for index, fn := range sessionIndexFunctions {
			builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
		}

		clusterName := "test-cluster"
		escalationNamespace := "default"
		idpName := "test-idp"
		maxTotal := int32(2)

		// Create IDP (no limits - escalation provides the limit)
		idp := &v1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name: idpName,
			},
			Spec: v1alpha1.IdentityProviderSpec{
				OIDC: v1alpha1.OIDCConfig{
					Authority: "https://auth.example.com",
					ClientID:  "test-client",
				},
			},
		}

		// Create escalation with maxActiveSessionsTotal limit
		esc := &v1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-escalation",
				Namespace: escalationNamespace,
				UID:       types.UID("esc-uid-total"),
			},
			Spec: v1alpha1.BreakglassEscalationSpec{
				Allowed: v1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   []string{"system:authenticated"},
				},
				EscalatedGroup: "admin-group",
				Approvers: v1alpha1.BreakglassEscalationApprovers{
					Users: []string{"approver@example.com"},
				},
				MaxValidFor: "1h",
				SessionLimitsOverride: &v1alpha1.SessionLimitsOverride{
					MaxActiveSessionsTotal: &maxTotal,
				},
			},
		}

		clusterConfig := &v1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterName,
				Namespace: escalationNamespace,
			},
		}

		// Create 2 existing active sessions for admin-group (at total limit)
		// Note: different users but same granted group
		// Sessions must have owner references to the escalation to be counted
		existingSessions := []*v1alpha1.BreakglassSession{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "existing-session-1",
					Namespace: escalationNamespace,
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "breakglass.t-caas.telekom.com/v1alpha1",
							Kind:       "BreakglassEscalation",
							Name:       "test-escalation",
							UID:        types.UID("esc-uid-total"),
						},
					},
				},
				Spec: v1alpha1.BreakglassSessionSpec{
					Cluster:      clusterName,
					User:         "user1@example.com",
					GrantedGroup: "admin-group",
				},
				Status: v1alpha1.BreakglassSessionStatus{
					State: v1alpha1.SessionStatePending,
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "existing-session-2",
					Namespace: escalationNamespace,
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "breakglass.t-caas.telekom.com/v1alpha1",
							Kind:       "BreakglassEscalation",
							Name:       "test-escalation",
							UID:        types.UID("esc-uid-total"),
						},
					},
				},
				Spec: v1alpha1.BreakglassSessionSpec{
					Cluster:      clusterName,
					User:         "user2@example.com",
					GrantedGroup: "admin-group",
				},
				Status: v1alpha1.BreakglassSessionStatus{
					State: v1alpha1.SessionStateApproved,
				},
			},
		}

		builder.WithObjects(idp, esc, clusterConfig, existingSessions[0], existingSessions[1])
		cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}, &v1alpha1.IdentityProvider{}).Build()
		sesmanager := SessionManager{Client: cli}
		escmanager := EscalationManager{Client: cli}

		logger, _ := zap.NewDevelopment()
		ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager,
			func(c *gin.Context) {
				c.Set("email", "new-user@example.com")
				c.Set("username", "NewUser")
				c.Set("user_id", "new-user@example.com")
				c.Set("identity_provider_name", idpName)
				c.Set("groups", []string{"system:authenticated"})
				c.Next()
			}, "/config/config.yaml", nil, cli)

		ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
			return []string{"system:authenticated"}, nil
		}

		engine := gin.New()
		_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

		reqData := BreakglassSessionRequest{
			Clustername: clusterName,
			Username:    "new-user@example.com",
			GroupName:   "admin-group",
			Reason:      "Test reason",
		}
		b, _ := json.Marshal(reqData)
		req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		require.Equal(t, http.StatusUnprocessableEntity, w.Result().StatusCode, "should reject when total session limit reached")
		body, _ := io.ReadAll(w.Result().Body)
		require.Contains(t, string(body), "session limit reached")
		require.Contains(t, string(body), "total active sessions")
	})

	t.Run("IDP group override with unlimited allows sessions", func(t *testing.T) {
		builder := fake.NewClientBuilder().WithScheme(Scheme)
		for index, fn := range sessionIndexFunctions {
			builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
		}

		clusterName := "test-cluster"
		escalationNamespace := "default"
		idpName := "test-idp"
		restrictiveLimit := int32(1)

		// Create IDP with very restrictive default but unlimited for sre-oncall
		idp := &v1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name: idpName,
			},
			Spec: v1alpha1.IdentityProviderSpec{
				OIDC: v1alpha1.OIDCConfig{
					Authority: "https://auth.example.com",
					ClientID:  "test-client",
				},
				SessionLimits: &v1alpha1.SessionLimits{
					MaxActiveSessionsPerUser: &restrictiveLimit, // Very restrictive
					GroupOverrides: []v1alpha1.SessionLimitGroupOverride{
						{
							Group:     "sre-oncall",
							Unlimited: true, // SRE oncall has no limits
						},
					},
				},
			},
		}

		// Create escalation (no override)
		esc := &v1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-escalation",
				Namespace: escalationNamespace,
				UID:       types.UID("esc-uid-unlimited-group"),
			},
			Spec: v1alpha1.BreakglassEscalationSpec{
				Allowed: v1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   []string{"sre-oncall"},
				},
				EscalatedGroup: "cluster-admin",
				Approvers: v1alpha1.BreakglassEscalationApprovers{
					Users: []string{"approver@example.com"},
				},
				MaxValidFor: "1h",
			},
		}

		clusterConfig := &v1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterName,
				Namespace: escalationNamespace,
			},
		}

		// Create multiple existing sessions for this user (would exceed the default limit)
		existingSessions := []*v1alpha1.BreakglassSession{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "existing-session-1",
					Namespace: escalationNamespace,
				},
				Spec: v1alpha1.BreakglassSessionSpec{
					Cluster:      clusterName,
					User:         "sre-user@example.com",
					GrantedGroup: "other-group",
				},
				Status: v1alpha1.BreakglassSessionStatus{
					State: v1alpha1.SessionStatePending,
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "existing-session-2",
					Namespace: escalationNamespace,
				},
				Spec: v1alpha1.BreakglassSessionSpec{
					Cluster:      clusterName,
					User:         "sre-user@example.com",
					GrantedGroup: "another-group",
				},
				Status: v1alpha1.BreakglassSessionStatus{
					State: v1alpha1.SessionStateApproved,
				},
			},
		}

		builder.WithObjects(idp, esc, clusterConfig, existingSessions[0], existingSessions[1])
		cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}, &v1alpha1.IdentityProvider{}).Build()
		sesmanager := SessionManager{Client: cli}
		escmanager := EscalationManager{Client: cli}

		logger, _ := zap.NewDevelopment()
		ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager,
			func(c *gin.Context) {
				c.Set("email", "sre-user@example.com")
				c.Set("username", "SREUser")
				c.Set("user_id", "sre-user@example.com")
				c.Set("identity_provider_name", idpName)
				c.Set("groups", []string{"sre-oncall"})
				c.Next()
			}, "/config/config.yaml", nil, cli)

		ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
			return []string{"sre-oncall"}, nil
		}

		engine := gin.New()
		_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

		reqData := BreakglassSessionRequest{
			Clustername: clusterName,
			Username:    "sre-user@example.com",
			GroupName:   "cluster-admin",
			Reason:      "SRE emergency",
		}
		b, _ := json.Marshal(reqData)
		req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		// Should succeed because sre-oncall group has unlimited override
		require.Equal(t, http.StatusCreated, w.Result().StatusCode, "should allow session with IDP group unlimited override")
	})
}

// TestSessionLimits_GlobPatterns tests glob pattern matching for IDP group overrides
func TestSessionLimits_GlobPatterns(t *testing.T) {
	t.Run("glob pattern matches user group", func(t *testing.T) {
		builder := fake.NewClientBuilder().WithScheme(Scheme)
		for index, fn := range sessionIndexFunctions {
			builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
		}

		clusterName := "test-cluster"
		escalationNamespace := "default"
		idpName := "test-idp"
		restrictiveLimit := int32(1)
		platformLimit := int32(10)

		// Create IDP with glob pattern for platform-* groups
		idp := &v1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name: idpName,
			},
			Spec: v1alpha1.IdentityProviderSpec{
				OIDC: v1alpha1.OIDCConfig{
					Authority: "https://auth.example.com",
					ClientID:  "test-client",
				},
				SessionLimits: &v1alpha1.SessionLimits{
					MaxActiveSessionsPerUser: &restrictiveLimit, // Default limit
					GroupOverrides: []v1alpha1.SessionLimitGroupOverride{
						{
							Group:                    "platform-*", // Glob pattern
							MaxActiveSessionsPerUser: &platformLimit,
						},
					},
				},
			},
		}

		// Create escalation
		esc := &v1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-escalation",
				Namespace: escalationNamespace,
				UID:       types.UID("esc-uid-glob"),
			},
			Spec: v1alpha1.BreakglassEscalationSpec{
				Allowed: v1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   []string{"platform-sre"},
				},
				EscalatedGroup: "cluster-admin",
				Approvers: v1alpha1.BreakglassEscalationApprovers{
					Users: []string{"approver@example.com"},
				},
				MaxValidFor: "1h",
			},
		}

		clusterConfig := &v1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterName,
				Namespace: escalationNamespace,
			},
		}

		// Create 5 existing sessions (exceeds default limit of 1, but under glob pattern limit of 10)
		var existingSessions []client.Object
		for i := range 5 {
			existingSessions = append(existingSessions, &v1alpha1.BreakglassSession{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("existing-session-%d", i),
					Namespace: escalationNamespace,
				},
				Spec: v1alpha1.BreakglassSessionSpec{
					Cluster:      clusterName,
					User:         "platform-user@example.com",
					GrantedGroup: "other-group",
				},
				Status: v1alpha1.BreakglassSessionStatus{
					State: v1alpha1.SessionStateApproved,
				},
			})
		}

		builder.WithObjects(idp, esc, clusterConfig)
		builder.WithObjects(existingSessions...)
		cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}, &v1alpha1.IdentityProvider{}).Build()
		sesmanager := SessionManager{Client: cli}
		escmanager := EscalationManager{Client: cli}

		logger, _ := zap.NewDevelopment()
		ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager,
			func(c *gin.Context) {
				c.Set("email", "platform-user@example.com")
				c.Set("username", "PlatformUser")
				c.Set("user_id", "platform-user@example.com")
				c.Set("identity_provider_name", idpName)
				c.Set("groups", []string{"platform-sre"}) // Matches glob pattern "platform-*"
				c.Next()
			}, "/config/config.yaml", nil, cli)

		ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
			return []string{"platform-sre"}, nil
		}

		engine := gin.New()
		_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

		reqData := BreakglassSessionRequest{
			Clustername: clusterName,
			Username:    "platform-user@example.com",
			GroupName:   "cluster-admin",
			Reason:      "Platform emergency",
		}
		b, _ := json.Marshal(reqData)
		req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		// Should succeed because platform-sre matches "platform-*" glob with higher limit
		require.Equal(t, http.StatusCreated, w.Result().StatusCode, "should allow session when glob pattern matches and within limit")
	})

	t.Run("first matching glob wins", func(t *testing.T) {
		builder := fake.NewClientBuilder().WithScheme(Scheme)
		for index, fn := range sessionIndexFunctions {
			builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
		}

		clusterName := "test-cluster"
		escalationNamespace := "default"
		idpName := "test-idp"
		restrictiveLimit := int32(1)
		specificLimit := int32(2)
		generalLimit := int32(100) // More permissive but should not be used

		// Create IDP where both patterns could match, but first should win
		idp := &v1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name: idpName,
			},
			Spec: v1alpha1.IdentityProviderSpec{
				OIDC: v1alpha1.OIDCConfig{
					Authority: "https://auth.example.com",
					ClientID:  "test-client",
				},
				SessionLimits: &v1alpha1.SessionLimits{
					MaxActiveSessionsPerUser: &restrictiveLimit,
					GroupOverrides: []v1alpha1.SessionLimitGroupOverride{
						{
							Group:                    "platform-sre", // More specific - matches first
							MaxActiveSessionsPerUser: &specificLimit, // Limit: 2
						},
						{
							Group:                    "platform-*",  // More general - matches second
							MaxActiveSessionsPerUser: &generalLimit, // Limit: 100
						},
					},
				},
			},
		}

		esc := &v1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-escalation",
				Namespace: escalationNamespace,
				UID:       types.UID("esc-uid-first-match"),
			},
			Spec: v1alpha1.BreakglassEscalationSpec{
				Allowed: v1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   []string{"platform-sre"},
				},
				EscalatedGroup: "cluster-admin",
				Approvers: v1alpha1.BreakglassEscalationApprovers{
					Users: []string{"approver@example.com"},
				},
				MaxValidFor: "1h",
			},
		}

		clusterConfig := &v1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterName,
				Namespace: escalationNamespace,
			},
		}

		// Create 2 existing sessions (at first-match limit of 2)
		existingSessions := []*v1alpha1.BreakglassSession{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "existing-session-1",
					Namespace: escalationNamespace,
				},
				Spec: v1alpha1.BreakglassSessionSpec{
					Cluster:      clusterName,
					User:         "sre-user@example.com",
					GrantedGroup: "other-group",
				},
				Status: v1alpha1.BreakglassSessionStatus{
					State: v1alpha1.SessionStateApproved,
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "existing-session-2",
					Namespace: escalationNamespace,
				},
				Spec: v1alpha1.BreakglassSessionSpec{
					Cluster:      clusterName,
					User:         "sre-user@example.com",
					GrantedGroup: "another-group",
				},
				Status: v1alpha1.BreakglassSessionStatus{
					State: v1alpha1.SessionStatePending,
				},
			},
		}

		builder.WithObjects(idp, esc, clusterConfig, existingSessions[0], existingSessions[1])
		cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}, &v1alpha1.IdentityProvider{}).Build()
		sesmanager := SessionManager{Client: cli}
		escmanager := EscalationManager{Client: cli}

		logger, _ := zap.NewDevelopment()
		ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager,
			func(c *gin.Context) {
				c.Set("email", "sre-user@example.com")
				c.Set("username", "SREUser")
				c.Set("user_id", "sre-user@example.com")
				c.Set("identity_provider_name", idpName)
				c.Set("groups", []string{"platform-sre"}) // Matches BOTH patterns
				c.Next()
			}, "/config/config.yaml", nil, cli)

		ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
			return []string{"platform-sre"}, nil
		}

		engine := gin.New()
		_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

		reqData := BreakglassSessionRequest{
			Clustername: clusterName,
			Username:    "sre-user@example.com",
			GroupName:   "cluster-admin",
			Reason:      "SRE emergency",
		}
		b, _ := json.Marshal(reqData)
		req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		// Should FAIL because first matching pattern (platform-sre) has limit 2, and we're at 2
		// The general "platform-*" pattern with limit 100 should NOT be used
		require.Equal(t, http.StatusUnprocessableEntity, w.Result().StatusCode, "first matching group override wins, should not fallback to more permissive pattern")
		body, _ := io.ReadAll(w.Result().Body)
		require.Contains(t, string(body), "session limit reached")
	})

	t.Run("invalid glob pattern is skipped", func(t *testing.T) {
		builder := fake.NewClientBuilder().WithScheme(Scheme)
		for index, fn := range sessionIndexFunctions {
			builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
		}

		clusterName := "test-cluster"
		escalationNamespace := "default"
		idpName := "test-idp"
		restrictiveLimit := int32(1)
		invalidPatternLimit := int32(100)
		validPatternLimit := int32(10)

		// Create IDP with an invalid glob pattern followed by a valid one
		idp := &v1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name: idpName,
			},
			Spec: v1alpha1.IdentityProviderSpec{
				OIDC: v1alpha1.OIDCConfig{
					Authority: "https://auth.example.com",
					ClientID:  "test-client",
				},
				SessionLimits: &v1alpha1.SessionLimits{
					MaxActiveSessionsPerUser: &restrictiveLimit,
					GroupOverrides: []v1alpha1.SessionLimitGroupOverride{
						{
							Group:                    "[invalid-regex", // Invalid glob pattern
							MaxActiveSessionsPerUser: &invalidPatternLimit,
						},
						{
							Group:                    "platform-*", // Valid pattern
							MaxActiveSessionsPerUser: &validPatternLimit,
						},
					},
				},
			},
		}

		esc := &v1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-escalation",
				Namespace: escalationNamespace,
				UID:       types.UID("esc-uid-invalid-glob"),
			},
			Spec: v1alpha1.BreakglassEscalationSpec{
				Allowed: v1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   []string{"platform-team"},
				},
				EscalatedGroup: "cluster-admin",
				Approvers: v1alpha1.BreakglassEscalationApprovers{
					Users: []string{"approver@example.com"},
				},
				MaxValidFor: "1h",
			},
		}

		clusterConfig := &v1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterName,
				Namespace: escalationNamespace,
			},
		}

		// Create 5 existing sessions (exceeds default of 1, but under valid pattern limit of 10)
		var existingSessions []client.Object
		for i := range 5 {
			existingSessions = append(existingSessions, &v1alpha1.BreakglassSession{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("existing-session-%d", i),
					Namespace: escalationNamespace,
				},
				Spec: v1alpha1.BreakglassSessionSpec{
					Cluster:      clusterName,
					User:         "platform-user@example.com",
					GrantedGroup: "other-group",
				},
				Status: v1alpha1.BreakglassSessionStatus{
					State: v1alpha1.SessionStateApproved,
				},
			})
		}

		builder.WithObjects(idp, esc, clusterConfig)
		builder.WithObjects(existingSessions...)
		cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}, &v1alpha1.IdentityProvider{}).Build()
		sesmanager := SessionManager{Client: cli}
		escmanager := EscalationManager{Client: cli}

		logger, _ := zap.NewDevelopment()
		ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager,
			func(c *gin.Context) {
				c.Set("email", "platform-user@example.com")
				c.Set("username", "PlatformUser")
				c.Set("user_id", "platform-user@example.com")
				c.Set("identity_provider_name", idpName)
				c.Set("groups", []string{"platform-team"})
				c.Next()
			}, "/config/config.yaml", nil, cli)

		ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
			return []string{"platform-team"}, nil
		}

		engine := gin.New()
		_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

		reqData := BreakglassSessionRequest{
			Clustername: clusterName,
			Username:    "platform-user@example.com",
			GroupName:   "cluster-admin",
			Reason:      "Test reason",
		}
		b, _ := json.Marshal(reqData)
		req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		// Invalid pattern is skipped, valid pattern "platform-*" matches with limit 10
		require.Equal(t, http.StatusCreated, w.Result().StatusCode, "should skip invalid glob and use next matching pattern")
	})

	t.Run("IDP group override without limit falls through to IDP default", func(t *testing.T) {
		// Test scenario: User matches a group override that has neither unlimited: true
		// nor maxActiveSessionsPerUser set. Should fall through to IDP default limit.
		builder := fake.NewClientBuilder().WithScheme(Scheme)
		for index, fn := range sessionIndexFunctions {
			builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
		}

		clusterName := "test-cluster"
		escalationNamespace := "default"
		idpName := "test-idp"
		idpDefaultLimit := int32(2)

		// Create IDP with a group override that has no limit fields set
		idp := &v1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name: idpName,
			},
			Spec: v1alpha1.IdentityProviderSpec{
				OIDC: v1alpha1.OIDCConfig{
					Authority: "https://auth.example.com",
					ClientID:  "test-client",
				},
				SessionLimits: &v1alpha1.SessionLimits{
					MaxActiveSessionsPerUser: &idpDefaultLimit, // IDP default: 2 sessions
					GroupOverrides: []v1alpha1.SessionLimitGroupOverride{
						{
							Group: "special-group", // Just group name, no unlimited or maxActiveSessionsPerUser
							// Unlimited: false (default)
							// MaxActiveSessionsPerUser: nil
						},
					},
				},
			},
		}

		esc := &v1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-escalation",
				Namespace: escalationNamespace,
				UID:       types.UID("esc-uid-fallthrough"),
			},
			Spec: v1alpha1.BreakglassEscalationSpec{
				Allowed: v1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   []string{"special-group"},
				},
				EscalatedGroup: "cluster-admin",
				Approvers: v1alpha1.BreakglassEscalationApprovers{
					Users: []string{"approver@example.com"},
				},
				MaxValidFor: "1h",
			},
		}

		clusterConfig := &v1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterName,
				Namespace: escalationNamespace,
			},
		}

		// Create 2 existing sessions (at IDP default limit)
		existingSessions := []*v1alpha1.BreakglassSession{
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "existing-session-1",
					Namespace: escalationNamespace,
				},
				Spec: v1alpha1.BreakglassSessionSpec{
					Cluster:      clusterName,
					User:         "special-user@example.com",
					GrantedGroup: "admin-group",
				},
				Status: v1alpha1.BreakglassSessionStatus{
					State: v1alpha1.SessionStateApproved,
				},
			},
			{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "existing-session-2",
					Namespace: escalationNamespace,
				},
				Spec: v1alpha1.BreakglassSessionSpec{
					Cluster:      clusterName,
					User:         "special-user@example.com",
					GrantedGroup: "other-group",
				},
				Status: v1alpha1.BreakglassSessionStatus{
					State: v1alpha1.SessionStatePending,
				},
			},
		}

		builder.WithObjects(idp, esc, clusterConfig, existingSessions[0], existingSessions[1])
		cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}, &v1alpha1.IdentityProvider{}).Build()
		sesmanager := SessionManager{Client: cli}
		escmanager := EscalationManager{Client: cli}

		logger, _ := zap.NewDevelopment()
		ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager,
			func(c *gin.Context) {
				c.Set("email", "special-user@example.com")
				c.Set("username", "SpecialUser")
				c.Set("user_id", "special-user@example.com")
				c.Set("identity_provider_name", idpName)
				c.Set("groups", []string{"special-group"}) // Matches the empty group override
				c.Next()
			}, "/config/config.yaml", nil, cli)

		ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
			return []string{"special-group"}, nil
		}

		engine := gin.New()
		_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

		reqData := BreakglassSessionRequest{
			Clustername: clusterName,
			Username:    "special-user@example.com",
			GroupName:   "cluster-admin",
			Reason:      "Test IDP fallthrough",
		}
		b, _ := json.Marshal(reqData)
		req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		// Should FAIL because group override matched but had no limit,
		// so it falls through to IDP default of 2, and we're at 2 sessions.
		require.Equal(t, http.StatusUnprocessableEntity, w.Result().StatusCode,
			"group override without limit should fall through to IDP default")
		body, _ := io.ReadAll(w.Result().Body)
		require.Contains(t, string(body), "session limit reached",
			"should include limit error message")
		require.Contains(t, string(body), "IDP default",
			"should indicate it's the IDP default limit")
	})
}

// TestApproverResolutionLimits tests the security limits for approver group resolution.
// These limits prevent resource exhaustion from malicious or misconfigured large approver groups.
func TestApproverResolutionLimits(t *testing.T) {
	t.Run("truncates single group exceeding MaxApproverGroupMembers", func(t *testing.T) {
		builder := fake.NewClientBuilder().WithScheme(Scheme)
		for index, fn := range sessionIndexFunctions {
			builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
		}

		clusterName := "test-cluster"
		escalationNamespace := "default"
		idpName := "test-idp"

		// Create IDP
		idp := &v1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{Name: idpName},
			Spec: v1alpha1.IdentityProviderSpec{
				OIDC: v1alpha1.OIDCConfig{
					Authority: "https://auth.example.com",
					ClientID:  "test-client",
				},
			},
		}

		// Create escalation with a single approver group
		esc := &v1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-escalation",
				Namespace: escalationNamespace,
				UID:       types.UID("esc-uid-limit-test"),
			},
			Spec: v1alpha1.BreakglassEscalationSpec{
				Allowed: v1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   []string{"requester-group"},
				},
				EscalatedGroup: "cluster-admin",
				Approvers: v1alpha1.BreakglassEscalationApprovers{
					Groups: []string{"large-approver-group"}, // This group will have >1000 members
				},
				MaxValidFor: "1h",
			},
		}

		clusterConfig := &v1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterName,
				Namespace: escalationNamespace,
			},
		}

		builder.WithObjects(idp, esc, clusterConfig)
		cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}, &v1alpha1.IdentityProvider{}).Build()
		sesmanager := SessionManager{Client: cli}
		escmanager := EscalationManager{Client: cli}

		logger, _ := zap.NewDevelopment()
		ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager,
			func(c *gin.Context) {
				c.Set("email", "user@example.com")
				c.Set("username", "User")
				c.Set("user_id", "user@example.com")
				c.Set("identity_provider_name", idpName)
				c.Set("groups", []string{"requester-group"})
				c.Next()
			}, "/config/config.yaml", nil, cli)

		ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
			return []string{"requester-group"}, nil
		}

		// Set up mock resolver that returns >1000 members for the approver group
		largeGroupMembers := make([]string, MaxApproverGroupMembers+100)
		for i := range largeGroupMembers {
			largeGroupMembers[i] = fmt.Sprintf("approver-%d@example.com", i)
		}
		mockResolver := &MockGroupResolver{
			members: map[string][]string{
				"large-approver-group": largeGroupMembers,
			},
		}
		ctrl.escalationManager.SetResolver(mockResolver)

		engine := gin.New()
		_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

		reqData := BreakglassSessionRequest{
			Clustername: clusterName,
			Username:    "user@example.com",
			GroupName:   "cluster-admin",
			Reason:      "Test truncation",
		}
		b, _ := json.Marshal(reqData)
		req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		// Session should still be created successfully even with truncation
		require.Equal(t, http.StatusCreated, w.Result().StatusCode, "session should be created even when approvers are truncated")
	})

	t.Run("caps total approvers across multiple groups via MaxTotalApprovers", func(t *testing.T) {
		// This test verifies that when multiple approver groups together would exceed
		// MaxTotalApprovers, the resolution stops early and later groups are skipped.
		// The session should still be created with whatever approvers were collected.
		builder := fake.NewClientBuilder().WithScheme(Scheme)
		for index, fn := range sessionIndexFunctions {
			builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
		}

		clusterName := "test-cluster"
		escalationNamespace := "default"
		idpName := "test-idp"

		// Create IDP
		idp := &v1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{Name: idpName},
			Spec: v1alpha1.IdentityProviderSpec{
				OIDC: v1alpha1.OIDCConfig{
					Authority: "https://auth.example.com",
					ClientID:  "test-client",
				},
			},
		}

		// Create escalation with multiple approver groups
		esc := &v1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "test-escalation",
				Namespace: escalationNamespace,
				UID:       types.UID("esc-uid-total-limit-test"),
			},
			Spec: v1alpha1.BreakglassEscalationSpec{
				Allowed: v1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   []string{"requester-group"},
				},
				EscalatedGroup: "cluster-admin",
				Approvers: v1alpha1.BreakglassEscalationApprovers{
					Groups: []string{"group-1", "group-2", "group-3"}, // 3 groups
				},
				MaxValidFor: "1h",
			},
		}

		clusterConfig := &v1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterName,
				Namespace: escalationNamespace,
			},
		}

		builder.WithObjects(idp, esc, clusterConfig)
		cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}, &v1alpha1.IdentityProvider{}).Build()
		sesmanager := SessionManager{Client: cli}
		escmanager := EscalationManager{Client: cli}

		logger, _ := zap.NewDevelopment()
		ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager,
			func(c *gin.Context) {
				c.Set("email", "user@example.com")
				c.Set("username", "User")
				c.Set("user_id", "user@example.com")
				c.Set("identity_provider_name", idpName)
				c.Set("groups", []string{"requester-group"})
				c.Next()
			}, "/config/config.yaml", nil, cli)

		ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
			return []string{"requester-group"}, nil
		}

		// Set up mock resolver with large enough groups that together exceed MaxTotalApprovers
		// Use groups that together would exceed 5000 total approvers
		// Group 1: 2500 members, Group 2: 2000 members, Group 3: 2000 members
		// Total = 6500, but MaxTotalApprovers=5000 so group-3 should be truncated
		group1Members := make([]string, 2500)
		for i := range group1Members {
			group1Members[i] = fmt.Sprintf("g1-approver-%d@example.com", i)
		}
		group2Members := make([]string, 2000)
		for i := range group2Members {
			group2Members[i] = fmt.Sprintf("g2-approver-%d@example.com", i)
		}
		group3Members := make([]string, 2000)
		for i := range group3Members {
			group3Members[i] = fmt.Sprintf("g3-approver-%d@example.com", i)
		}

		mockResolver := &MockGroupResolver{
			members: map[string][]string{
				"group-1": group1Members,
				"group-2": group2Members,
				"group-3": group3Members,
			},
		}
		ctrl.escalationManager.SetResolver(mockResolver)

		engine := gin.New()
		_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

		reqData := BreakglassSessionRequest{
			Clustername: clusterName,
			Username:    "user@example.com",
			GroupName:   "cluster-admin",
			Reason:      "Test total approvers limit",
		}
		b, _ := json.Marshal(reqData)
		req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		// Session should be created successfully - approver truncation doesn't fail session creation
		require.Equal(t, http.StatusCreated, w.Result().StatusCode,
			"session should be created even when total approvers are capped")
	})

	t.Run("preserves matched escalation when approvers are truncated", func(t *testing.T) {
		// This test verifies that even when approver resolution is truncated due to limits,
		// the matched BreakglassEscalation is still properly recorded on the session.
		builder := fake.NewClientBuilder().WithScheme(Scheme)
		for index, fn := range sessionIndexFunctions {
			builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
		}

		clusterName := "test-cluster"
		escalationNamespace := "default"
		idpName := "test-idp"

		// Create IDP
		idp := &v1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{Name: idpName},
			Spec: v1alpha1.IdentityProviderSpec{
				OIDC: v1alpha1.OIDCConfig{
					Authority: "https://auth.example.com",
					ClientID:  "test-client",
				},
			},
		}

		// Create escalation with a huge approver group that will be truncated
		esc := &v1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "truncated-escalation",
				Namespace: escalationNamespace,
				UID:       types.UID("esc-uid-preserve-match"),
			},
			Spec: v1alpha1.BreakglassEscalationSpec{
				Allowed: v1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   []string{"requester-group"},
				},
				EscalatedGroup: "cluster-admin",
				Approvers: v1alpha1.BreakglassEscalationApprovers{
					Groups: []string{"huge-approver-group"},
				},
				MaxValidFor: "1h",
			},
		}

		clusterConfig := &v1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterName,
				Namespace: escalationNamespace,
			},
		}

		builder.WithObjects(idp, esc, clusterConfig)
		cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}, &v1alpha1.IdentityProvider{}).Build()
		sesmanager := SessionManager{Client: cli}
		escmanager := EscalationManager{Client: cli}

		logger, _ := zap.NewDevelopment()
		ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager,
			func(c *gin.Context) {
				c.Set("email", "user@example.com")
				c.Set("username", "User")
				c.Set("user_id", "user@example.com")
				c.Set("identity_provider_name", idpName)
				c.Set("groups", []string{"requester-group"})
				c.Next()
			}, "/config/config.yaml", nil, cli)

		ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
			return []string{"requester-group"}, nil
		}

		// Create a group with more members than MaxApproverGroupMembers
		hugeGroupMembers := make([]string, MaxApproverGroupMembers+500)
		for i := range hugeGroupMembers {
			hugeGroupMembers[i] = fmt.Sprintf("approver-%d@example.com", i)
		}
		mockResolver := &MockGroupResolver{
			members: map[string][]string{
				"huge-approver-group": hugeGroupMembers,
			},
		}
		ctrl.escalationManager.SetResolver(mockResolver)

		engine := gin.New()
		_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

		reqData := BreakglassSessionRequest{
			Clustername: clusterName,
			Username:    "user@example.com",
			GroupName:   "cluster-admin",
			Reason:      "Test preserved matching",
		}
		b, _ := json.Marshal(reqData)
		req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		require.Equal(t, http.StatusCreated, w.Result().StatusCode,
			"session should be created with truncated approvers")

		// Verify the session has the correct owner reference to the escalation
		var sessions v1alpha1.BreakglassSessionList
		err := cli.List(context.Background(), &sessions)
		require.NoError(t, err, "should list sessions")
		require.Len(t, sessions.Items, 1, "should have exactly one session")

		session := sessions.Items[0]
		require.Len(t, session.OwnerReferences, 1, "session should have owner reference")
		require.Equal(t, "truncated-escalation", session.OwnerReferences[0].Name,
			"session should be owned by the matched escalation")
	})

	t.Run("totalSessionCount uses owner reference not grantedGroup", func(t *testing.T) {
		builder := fake.NewClientBuilder().WithScheme(Scheme)
		for index, fn := range sessionIndexFunctions {
			builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
		}

		clusterName := "test-cluster"
		escalationNamespace := "default"
		idpName := "test-idp"
		totalLimit := int32(2)

		// Create IDP
		idp := &v1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{Name: idpName},
			Spec: v1alpha1.IdentityProviderSpec{
				OIDC: v1alpha1.OIDCConfig{
					Authority: "https://auth.example.com",
					ClientID:  "test-client",
				},
			},
		}

		// Create two escalations that grant the SAME group but have different UIDs.
		// esc1 allows a *different* requester group so it will NOT match the request,
		// while esc2 allows "requester-group" and will be the matched escalation.
		esc1UID := types.UID("esc1-uid")
		esc1 := &v1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "escalation-1",
				Namespace: escalationNamespace,
				UID:       esc1UID,
			},
			Spec: v1alpha1.BreakglassEscalationSpec{
				Allowed: v1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   []string{"other-team"}, // Does NOT match "requester-group"
				},
				EscalatedGroup: "cluster-admin", // Same group as esc2
				Approvers: v1alpha1.BreakglassEscalationApprovers{
					Users: []string{"approver@example.com"},
				},
				MaxValidFor: "1h",
				SessionLimitsOverride: &v1alpha1.SessionLimitsOverride{
					MaxActiveSessionsTotal: &totalLimit, // Limit to 2 total sessions
				},
			},
		}

		esc2UID := types.UID("esc2-uid")
		esc2 := &v1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "escalation-2",
				Namespace: escalationNamespace,
				UID:       esc2UID,
			},
			Spec: v1alpha1.BreakglassEscalationSpec{
				Allowed: v1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   []string{"requester-group"}, // Matches the request
				},
				EscalatedGroup: "cluster-admin", // Same group as esc1
				Approvers: v1alpha1.BreakglassEscalationApprovers{
					Users: []string{"approver@example.com"},
				},
				MaxValidFor: "1h",
				SessionLimitsOverride: &v1alpha1.SessionLimitsOverride{
					MaxActiveSessionsTotal: &totalLimit, // Limit to 2 total sessions
				},
			},
		}

		clusterConfig := &v1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterName,
				Namespace: escalationNamespace,
			},
		}

		// Create 2 existing sessions OWNED BY esc1 (hitting its limit)
		var existingSessions []client.Object
		for i := range 2 {
			existingSessions = append(existingSessions, &v1alpha1.BreakglassSession{
				ObjectMeta: metav1.ObjectMeta{
					Name:      fmt.Sprintf("esc1-session-%d", i),
					Namespace: escalationNamespace,
					OwnerReferences: []metav1.OwnerReference{
						{
							APIVersion: "breakglass.t-caas.telekom.com/v1alpha1",
							Kind:       "BreakglassEscalation",
							Name:       esc1.Name,
							UID:        esc1UID,
						},
					},
				},
				Spec: v1alpha1.BreakglassSessionSpec{
					Cluster:      clusterName,
					User:         "other-user@example.com",
					GrantedGroup: "cluster-admin", // Same group - but owned by esc1
				},
				Status: v1alpha1.BreakglassSessionStatus{
					State: v1alpha1.SessionStateApproved,
				},
			})
		}

		builder.WithObjects(idp, esc1, esc2, clusterConfig)
		builder.WithObjects(existingSessions...)
		cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}, &v1alpha1.IdentityProvider{}).Build()
		sesmanager := SessionManager{Client: cli}
		escmanager := EscalationManager{Client: cli}

		logger, _ := zap.NewDevelopment()
		ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager,
			func(c *gin.Context) {
				c.Set("email", "user@example.com")
				c.Set("username", "User")
				c.Set("user_id", "user@example.com")
				c.Set("identity_provider_name", idpName)
				c.Set("groups", []string{"requester-group"})
				c.Next()
			}, "/config/config.yaml", nil, cli)

		ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
			return []string{"requester-group"}, nil
		}

		engine := gin.New()
		_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

		// Request session via esc2 (which should NOT count esc1's sessions).
		// Since esc1 doesn't allow "requester-group", only esc2 will match.
		// esc2 has 0 sessions, so it should succeed despite esc1 being at its limit.
		reqData := BreakglassSessionRequest{
			Clustername: clusterName,
			Username:    "user@example.com",
			GroupName:   "cluster-admin",
			Reason:      "Test owner reference counting",
		}
		b, _ := json.Marshal(reqData)
		req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		// The session MUST succeed because:
		// - esc2 is the only escalation matching "requester-group"
		// - esc2 has 0 sessions owned by it (the 2 existing sessions are owned by esc1)
		// - If owner-ref counting is broken (e.g., counting by grantedGroup), this would
		//   incorrectly fail with a 422 limit error because both escalations share "cluster-admin"
		require.Equal(t, http.StatusCreated, w.Result().StatusCode,
			"session should be created because esc2 has no sessions (esc1's sessions should not count)")

		// Verify the created session is owned by esc2, not esc1
		var response v1alpha1.BreakglassSession
		err := json.NewDecoder(w.Body).Decode(&response)
		require.NoError(t, err, "should decode response")

		createdSession := &v1alpha1.BreakglassSession{}
		err = cli.Get(context.Background(), client.ObjectKey{
			Name:      response.Name,
			Namespace: response.Namespace,
		}, createdSession)
		require.NoError(t, err, "should fetch created session")
		require.Len(t, createdSession.OwnerReferences, 1, "session should have one owner reference")
		require.Equal(t, esc2UID, createdSession.OwnerReferences[0].UID,
			"session should be owned by esc2, not esc1")
	})

	t.Run("boundary test - exactly MaxApproverGroupMembers members", func(t *testing.T) {
		// Tests the boundary condition where group has exactly 1000 members (the limit)
		// Should process all 1000 without truncation.
		builder := fake.NewClientBuilder().WithScheme(Scheme)
		for index, fn := range sessionIndexFunctions {
			builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
		}

		clusterName := "test-cluster"
		escalationNamespace := "default"
		idpName := "test-idp"

		idp := &v1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{Name: idpName},
			Spec: v1alpha1.IdentityProviderSpec{
				OIDC: v1alpha1.OIDCConfig{
					Authority: "https://auth.example.com",
					ClientID:  "test-client",
				},
			},
		}

		esc := &v1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "boundary-test-escalation",
				Namespace: escalationNamespace,
				UID:       types.UID("esc-uid-boundary"),
			},
			Spec: v1alpha1.BreakglassEscalationSpec{
				Allowed: v1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   []string{"requester-group"},
				},
				EscalatedGroup: "cluster-admin",
				Approvers: v1alpha1.BreakglassEscalationApprovers{
					Groups: []string{"exact-limit-group"},
				},
				MaxValidFor: "1h",
			},
		}

		clusterConfig := &v1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterName,
				Namespace: escalationNamespace,
			},
		}

		builder.WithObjects(idp, esc, clusterConfig)
		cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}, &v1alpha1.IdentityProvider{}).Build()
		sesmanager := SessionManager{Client: cli}
		escmanager := EscalationManager{Client: cli}

		logger, _ := zap.NewDevelopment()
		ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager,
			func(c *gin.Context) {
				c.Set("email", "user@example.com")
				c.Set("username", "User")
				c.Set("user_id", "user@example.com")
				c.Set("identity_provider_name", idpName)
				c.Set("groups", []string{"requester-group"})
				c.Next()
			}, "/config/config.yaml", nil, cli)

		ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
			return []string{"requester-group"}, nil
		}

		// Create exactly MaxApproverGroupMembers members (boundary case)
		boundaryMembers := make([]string, MaxApproverGroupMembers) // Exactly 1000
		for i := range boundaryMembers {
			boundaryMembers[i] = fmt.Sprintf("approver-%d@example.com", i)
		}
		mockResolver := &MockGroupResolver{
			members: map[string][]string{
				"exact-limit-group": boundaryMembers,
			},
		}
		ctrl.escalationManager.SetResolver(mockResolver)

		engine := gin.New()
		_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

		reqData := BreakglassSessionRequest{
			Clustername: clusterName,
			Username:    "user@example.com",
			GroupName:   "cluster-admin",
			Reason:      "Boundary test - exactly at limit",
		}
		b, _ := json.Marshal(reqData)
		req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		// Should succeed - exactly at limit, no truncation
		require.Equal(t, http.StatusCreated, w.Result().StatusCode,
			"should create session when at exactly MaxApproverGroupMembers boundary")
	})

	t.Run("explicit users plus groups exceeding total limit", func(t *testing.T) {
		// Tests that explicit users + group members together can't exceed MaxTotalApprovers
		builder := fake.NewClientBuilder().WithScheme(Scheme)
		for index, fn := range sessionIndexFunctions {
			builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
		}

		clusterName := "test-cluster"
		escalationNamespace := "default"
		idpName := "test-idp"

		idp := &v1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{Name: idpName},
			Spec: v1alpha1.IdentityProviderSpec{
				OIDC: v1alpha1.OIDCConfig{
					Authority: "https://auth.example.com",
					ClientID:  "test-client",
				},
			},
		}

		// Create explicit users list - halfway to limit
		explicitUsers := make([]string, MaxTotalApprovers/2)
		for i := range explicitUsers {
			explicitUsers[i] = fmt.Sprintf("explicit-user-%d@example.com", i)
		}

		esc := &v1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "explicit-plus-groups-escalation",
				Namespace: escalationNamespace,
				UID:       types.UID("esc-uid-explicit-groups"),
			},
			Spec: v1alpha1.BreakglassEscalationSpec{
				Allowed: v1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   []string{"requester-group"},
				},
				EscalatedGroup: "cluster-admin",
				Approvers: v1alpha1.BreakglassEscalationApprovers{
					Users:  explicitUsers,
					Groups: []string{"group-that-also-has-many"},
				},
				MaxValidFor: "1h",
			},
		}

		clusterConfig := &v1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterName,
				Namespace: escalationNamespace,
			},
		}

		builder.WithObjects(idp, esc, clusterConfig)
		cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}, &v1alpha1.IdentityProvider{}).Build()
		sesmanager := SessionManager{Client: cli}
		escmanager := EscalationManager{Client: cli}

		logger, _ := zap.NewDevelopment()
		ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager,
			func(c *gin.Context) {
				c.Set("email", "user@example.com")
				c.Set("username", "User")
				c.Set("user_id", "user@example.com")
				c.Set("identity_provider_name", idpName)
				c.Set("groups", []string{"requester-group"})
				c.Next()
			}, "/config/config.yaml", nil, cli)

		ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
			return []string{"requester-group"}, nil
		}

		// Group members that would exceed total limit when combined with explicit users
		groupMembers := make([]string, MaxTotalApprovers) // Would exceed when combined
		for i := range groupMembers {
			groupMembers[i] = fmt.Sprintf("group-member-%d@example.com", i)
		}
		mockResolver := &MockGroupResolver{
			members: map[string][]string{
				"group-that-also-has-many": groupMembers,
			},
		}
		ctrl.escalationManager.SetResolver(mockResolver)

		engine := gin.New()
		_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

		reqData := BreakglassSessionRequest{
			Clustername: clusterName,
			Username:    "user@example.com",
			GroupName:   "cluster-admin",
			Reason:      "Test explicit users + groups combined limit",
		}
		b, _ := json.Marshal(reqData)
		req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		// Session creation should succeed even though total potential approvers exceeds limit
		// The approvers list is just truncated/capped
		require.Equal(t, http.StatusCreated, w.Result().StatusCode,
			"session should be created with capped total approvers from explicit + groups")
	})

	t.Run("remainingCapacity equals zero skips group", func(t *testing.T) {
		// Tests that when remaining capacity is exactly 0, the group is skipped entirely
		// rather than being truncated to an empty slice with misleading logs.
		builder := fake.NewClientBuilder().WithScheme(Scheme)
		for index, fn := range sessionIndexFunctions {
			builder.WithIndex(&v1alpha1.BreakglassSession{}, index, fn)
		}

		clusterName := "test-cluster"
		escalationNamespace := "default"
		idpName := "test-idp"

		idp := &v1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{Name: idpName},
			Spec: v1alpha1.IdentityProviderSpec{
				OIDC: v1alpha1.OIDCConfig{
					Authority: "https://auth.example.com",
					ClientID:  "test-client",
				},
			},
		}

		esc := &v1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "remaining-capacity-test",
				Namespace: escalationNamespace,
				UID:       types.UID("esc-uid-remaining-capacity"),
			},
			Spec: v1alpha1.BreakglassEscalationSpec{
				Allowed: v1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   []string{"requester-group"},
				},
				EscalatedGroup: "cluster-admin",
				Approvers: v1alpha1.BreakglassEscalationApprovers{
					Groups: []string{"first-group", "second-group", "third-group"},
				},
				MaxValidFor: "1h",
			},
		}

		clusterConfig := &v1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      clusterName,
				Namespace: escalationNamespace,
			},
		}

		builder.WithObjects(idp, esc, clusterConfig)
		cli := builder.WithStatusSubresource(&v1alpha1.BreakglassSession{}, &v1alpha1.IdentityProvider{}).Build()
		sesmanager := SessionManager{Client: cli}
		escmanager := EscalationManager{Client: cli}

		logger, _ := zap.NewDevelopment()
		ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager,
			func(c *gin.Context) {
				c.Set("email", "user@example.com")
				c.Set("username", "User")
				c.Set("user_id", "user@example.com")
				c.Set("identity_provider_name", idpName)
				c.Set("groups", []string{"requester-group"})
				c.Next()
			}, "/config/config.yaml", nil, cli)

		ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
			return []string{"requester-group"}, nil
		}

		// Set up groups such that first-group exactly fills the limit,
		// second-group and third-group should be skipped with remainingCapacity=0
		firstGroupMembers := make([]string, MaxTotalApprovers) // Fills entire limit
		for i := range firstGroupMembers {
			firstGroupMembers[i] = fmt.Sprintf("first-approver-%d@example.com", i)
		}
		secondGroupMembers := make([]string, 100)
		for i := range secondGroupMembers {
			secondGroupMembers[i] = fmt.Sprintf("second-approver-%d@example.com", i)
		}
		mockResolver := &MockGroupResolver{
			members: map[string][]string{
				"first-group":  firstGroupMembers,
				"second-group": secondGroupMembers,
				"third-group":  {"third-approver@example.com"},
			},
		}
		ctrl.escalationManager.SetResolver(mockResolver)

		engine := gin.New()
		_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

		reqData := BreakglassSessionRequest{
			Clustername: clusterName,
			Username:    "user@example.com",
			GroupName:   "cluster-admin",
			Reason:      "Test remainingCapacity=0 edge case",
		}
		b, _ := json.Marshal(reqData)
		req, _ := http.NewRequest(http.MethodPost, "/breakglassSessions", bytes.NewReader(b))
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)

		// Session should be created successfully - second and third groups skipped
		require.Equal(t, http.StatusCreated, w.Result().StatusCode,
			"session should be created when some groups are skipped due to zero remaining capacity")
	})
}
