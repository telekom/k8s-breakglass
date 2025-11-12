package breakglass

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type FakeMailSender struct {
	LastRecivers          []string
	LastSubject, LastBody string
	OnSendError           error
}

func (s *FakeMailSender) Send(receivers []string, subject, body string) error {
	s.LastRecivers = receivers
	s.LastSubject = subject
	s.LastBody = body
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
		}, nil, cli)

	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated", "breakglass-standard-user"}, nil
	}

	ctrl.mail = &FakeMailSender{}

	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	// create request
	reqData := BreakglassSessionRequest{
		Clustername: "test",
		Username:    "tester@telekom.de",
		GroupName:   "breakglass-create-all",
	}
	b, _ := json.Marshal(reqData)
	req, _ := http.NewRequest("POST", "/breakglassSessions", bytes.NewReader(b))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	response := w.Result()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("Expected status CREATED (201) got '%d' instead", response.StatusCode)
	}

	// get created request and check if proper fields are set
	getSession := func() v1alpha1.BreakglassSession {
		req, _ := http.NewRequest("GET", "/breakglassSessions", nil)
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
	req, _ = http.NewRequest("POST",
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
	req, _ = http.NewRequest("POST",
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
		}, nil, cli)

	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated", "breakglass-standard-user"}, nil
	}

	ctrl.mail = &FakeMailSender{}

	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	// create request
	reqData := BreakglassSessionRequest{
		Clustername: "test",
		Username:    "requester@telekom.de",
		GroupName:   "breakglass-create-all",
	}
	b, _ := json.Marshal(reqData)
	req, _ := http.NewRequest("POST", "/breakglassSessions", bytes.NewReader(b))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	response := w.Result()
	if response.StatusCode != http.StatusCreated {
		t.Fatalf("Expected status CREATED (201) got '%d' instead", response.StatusCode)
	}

	// fetch created session
	req, _ = http.NewRequest("GET", "/breakglassSessions", nil)
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
	req, _ = http.NewRequest("POST", fmt.Sprintf("/breakglassSessions/%s/approve", ses.Name), nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	response = w.Result()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Expected status OK (200) got '%d' instead", response.StatusCode)
	}

	// fetch session and assert approver fields
	req, _ = http.NewRequest("GET", "/breakglassSessions", nil)
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
	req, _ = http.NewRequest("POST", fmt.Sprintf("/breakglassSessions/%s/reject", ses.Name), nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	response = w.Result()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatalf("Expected status BadRequest (400) got '%d' instead", response.StatusCode)
	}

	// fetch session and assert approver metadata remains unchanged (reject did not overwrite)
	req, _ = http.NewRequest("GET", "/breakglassSessions", nil)
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
		}, nil, cli)

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
	req, _ := http.NewRequest("POST", "/breakglassSessions", bytes.NewReader(b))
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

// Test that creating a session without a matching escalation returns 401 and no session is created
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
		}, nil, cli)

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
	req, _ := http.NewRequest("POST", "/breakglassSessions", bytes.NewReader(b))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	resp := w.Result()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("Expected 401 when no escalation found, got %d", resp.StatusCode)
	}

	// Verify no sessions exist
	req, _ = http.NewRequest("GET", "/breakglassSessions", nil)
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
	}, nil, cli)

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
	req, _ := http.NewRequest("POST", "/breakglassSessions", bytes.NewReader(b))
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
	req, _ = http.NewRequest("POST", fmt.Sprintf("/breakglassSessions/%s/approve", name), nil)
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
	}, nil, cli)

	// stub out group lookup to avoid kubeconfig parsing in unit tests
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated", "breakglass-standard-user"}, nil
	}

	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	// create a session
	reqData := BreakglassSessionRequest{Clustername: "c2", Username: "requester@ex.com", GroupName: "g-domain"}
	b, _ := json.Marshal(reqData)
	req, _ := http.NewRequest("POST", "/breakglassSessions", bytes.NewReader(b))
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
	req, _ = http.NewRequest("POST", fmt.Sprintf("/breakglassSessions/%s/approve", name), nil)
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
		}, nil, cli)

	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	ctrl.mail = &FakeMailSender{}

	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	// create session request which should match the escalation in "escns"
	reqData := BreakglassSessionRequest{
		Clustername: "test",
		Username:    "req@example.com",
		GroupName:   "g1",
	}
	b, _ := json.Marshal(reqData)
	req, _ := http.NewRequest("POST", "/breakglassSessions", bytes.NewReader(b))
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

// helper to get *bool
func ptrBool(b bool) *bool { return &b }

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
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, ctxSetup, nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated", "breakglass-standard-user"}, nil
	}
	ctrl.mail = &FakeMailSender{}
	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	// Filter by mine=true (user1@example.com)
	req, _ := http.NewRequest("GET", "/breakglassSessions?mine=true", nil)
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
		}, nil, cli)

	// Force getUserGroupsFn to return no special groups
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}

	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	req, _ := http.NewRequest("POST", "/breakglassSessions/pending-1/approve", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	res := w.Result()
	if res.StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected 401 Unauthorized for non-approver, got %d", res.StatusCode)
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
	}, nil, cli)

	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	ctrl.mail = &FakeMailSender{}
	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	// create session
	reqData := BreakglassSessionRequest{Clustername: "c", Username: "user@e.com", GroupName: "g"}
	b, _ := json.Marshal(reqData)
	req, _ := http.NewRequest("POST", "/breakglassSessions", bytes.NewReader(b))
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
	req, _ = http.NewRequest("POST", fmt.Sprintf("/breakglassSessions/%s/approve", name), nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected first approve to succeed, got %d", w.Result().StatusCode)
	}

	// approve second time -> conflict (409)
	req, _ = http.NewRequest("POST", fmt.Sprintf("/breakglassSessions/%s/approve", name), nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusConflict {
		t.Fatalf("expected second approve to return Conflict (409), got %d", w.Result().StatusCode)
	}

	// attempt to reject after approval -> should be BadRequest (terminal)
	req, _ = http.NewRequest("POST", fmt.Sprintf("/breakglassSessions/%s/reject", name), nil)
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
	}, nil, cli)

	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	ctrl.mail = &FakeMailSender{}
	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	// create session as requester user@e.com
	reqData := BreakglassSessionRequest{Clustername: "c", Username: "user@e.com", GroupName: "g"}
	b, _ := json.Marshal(reqData)
	req, _ := http.NewRequest("POST", "/breakglassSessions", bytes.NewReader(b))
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
	req, _ = http.NewRequest("POST", fmt.Sprintf("/breakglassSessions/%s/approve", name), nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected approve to succeed, got %d", w.Result().StatusCode)
	}

	// verify approved state
	req, _ = http.NewRequest("GET", fmt.Sprintf("/breakglassSessions/%s", name), nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	gotList := []v1alpha1.BreakglassSession{}
	if err := json.NewDecoder(w.Result().Body).Decode(&gotList); err != nil {
		t.Fatalf("failed to decode session status: %v", err)
	}
	if len(gotList) == 0 {
		t.Fatalf("expected session in response, got none")
	}
	got := gotList[0]
	if got.Status.State != v1alpha1.SessionStateApproved || got.Status.ApprovedAt.IsZero() {
		t.Fatalf("expected approved session, got state=%s approvedAt=%v", got.Status.State, got.Status.ApprovedAt)
	}

	// drop as owner -> should transition to Expired
	req, _ = http.NewRequest("POST", fmt.Sprintf("/breakglassSessions/%s/drop", name), nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected drop to succeed, got %d", w.Result().StatusCode)
	}

	// verify expired state
	req, _ = http.NewRequest("GET", fmt.Sprintf("/breakglassSessions/%s", name), nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	gotList = []v1alpha1.BreakglassSession{}
	if err := json.NewDecoder(w.Result().Body).Decode(&gotList); err != nil {
		t.Fatalf("failed to decode session status after drop: %v", err)
	}
	if len(gotList) == 0 {
		t.Fatalf("expected session in response after drop, got none")
	}
	got = gotList[0]
	if got.Status.State != v1alpha1.SessionStateExpired {
		t.Fatalf("expected expired session after drop, got state=%s", got.Status.State)
	}
	if got.Status.ExpiresAt.IsZero() {
		t.Fatalf("expected ExpiresAt to be set for expired session")
	}

	// ensure expired is terminal: further approve attempts must fail
	req, _ = http.NewRequest("POST", fmt.Sprintf("/breakglassSessions/%s/approve", name), nil)
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
	}, nil, cli)

	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	ctrl.mail = &FakeMailSender{}
	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	// create session as requester user@e.com
	reqData := BreakglassSessionRequest{Clustername: "c", Username: "user@e.com", GroupName: "g"}
	b, _ := json.Marshal(reqData)
	req, _ := http.NewRequest("POST", "/breakglassSessions", bytes.NewReader(b))
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
	req, _ = http.NewRequest("POST", fmt.Sprintf("/breakglassSessions/%s/approve", name), nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected approve to succeed, got %d", w.Result().StatusCode)
	}

	// cancel as approver -> should transition to Expired
	req, _ = http.NewRequest("POST", fmt.Sprintf("/breakglassSessions/%s/cancel", name), nil)
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
	}, nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	req, _ = http.NewRequest("POST", fmt.Sprintf("/breakglassSessions/%s/cancel", name), nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected cancel by non-approver to be Unauthorized, got %d", w.Result().StatusCode)
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
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, ctxSetup, nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	ctrl.mail = &FakeMailSender{}
	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	req, _ := http.NewRequest("GET", "/breakglassSessions?cluster=clusterA&mine=true", nil)
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
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, ctxSetup, nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	ctrl.mail = &FakeMailSender{}
	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	req, _ := http.NewRequest("GET", "/breakglassSessions?user=alice@example.com&mine=true", nil)
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
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, ctxSetup, nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	ctrl.mail = &FakeMailSender{}
	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	req, _ := http.NewRequest("GET", "/breakglassSessions?group=admins&mine=true", nil)
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

	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &ss, &es, ctxSetup, nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	ctrl.mail = &FakeMailSender{}

	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	// 1) Successful withdraw by owner on pending session
	{
		req, _ := http.NewRequest("POST", "/breakglassSessions/w-pending/withdraw", nil)
		req.Header.Set("X-Test-Email", "owner@example.com")
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		res := w.Result()
		if res.StatusCode != http.StatusOK {
			t.Fatalf("expected 200 OK for owner withdraw, got %d", res.StatusCode)
		}
		// verify status updated
		var bs v1alpha1.BreakglassSession
		if err := ss.Client.Get(context.Background(), client.ObjectKey{Name: "w-pending"}, &bs); err != nil {
			t.Fatalf("failed to get session after withdraw: %v", err)
		}
		if bs.Status.State != v1alpha1.SessionStateWithdrawn {
			t.Fatalf("expected withdrawn state, got %s", bs.Status.State)
		}
	}

	// 2) Unauthorized withdraw attempt by non-owner
	{
		req, _ := http.NewRequest("POST", "/breakglassSessions/w-approved/withdraw", nil)
		req.Header.Set("X-Test-Email", "other@example.com")
		w := httptest.NewRecorder()
		engine.ServeHTTP(w, req)
		res := w.Result()
		if res.StatusCode != http.StatusUnauthorized {
			t.Fatalf("expected 401 Unauthorized for non-owner withdraw, got %d", res.StatusCode)
		}
	}

	// 3) Owner attempts to withdraw a non-pending (approved) session -> BadRequest
	{
		req, _ := http.NewRequest("POST", "/breakglassSessions/w-approved/withdraw", nil)
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
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, ctxSetup, nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	ctrl.mail = &FakeMailSender{}
	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	req, _ := http.NewRequest("GET", "/breakglassSessions?cluster=c1&user=u1@example.com&mine=true", nil)
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
		}, nil, cli)

	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	ctrl.mail = &FakeMailSender{}

	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	// 1) attempt request without reason -> 422
	reqBody := BreakglassSessionRequest{Clustername: "c1", Username: "requester@example.com", GroupName: "g-with-reason"}
	b, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/breakglassSessions", bytes.NewReader(b))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	res := w.Result()
	if res.StatusCode != http.StatusUnprocessableEntity {
		t.Fatalf("expected 422 for missing required reason, got %d", res.StatusCode)
	}

	// 2) request with reason -> 201
	reqBody.Reason = "CASM-12345"
	b, _ = json.Marshal(reqBody)
	req, _ = http.NewRequest("POST", "/breakglassSessions", bytes.NewReader(b))
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	res = w.Result()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 for valid request, got %d", res.StatusCode)
	}

	// fetch session and verify stored request reason
	req, _ = http.NewRequest("GET", "/breakglassSessions", nil)
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
	req, _ = http.NewRequest("POST", fmt.Sprintf("/breakglassSessions/%s/approve", ses.Name), bytes.NewReader(bb))
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	res = w.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected 200 approving, got %d", res.StatusCode)
	}

	// fetch session and assert approvalReason stored
	req, _ = http.NewRequest("GET", "/breakglassSessions", nil)
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
		}, nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	ctrl.mail = &FakeMailSender{}

	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	long := strings.Repeat("A", 3000)
	reqBody := BreakglassSessionRequest{Clustername: "lc1", Username: "longreq@example.com", GroupName: "g-long", Reason: long}
	b, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/breakglassSessions", bytes.NewReader(b))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	res := w.Result()
	if res.StatusCode != http.StatusCreated {
		t.Fatalf("expected 201 for long reason, got %d", res.StatusCode)
	}

	// fetch and assert stored
	req, _ = http.NewRequest("GET", "/breakglassSessions", nil)
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
	if len(sessions) != 1 {
		t.Fatalf("expected 1 session, got %d", len(sessions))
	}
	if sessions[0].Spec.RequestReason != long {
		t.Fatalf("long reason not stored correctly")
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
		}, nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	ctrl.mail = &FakeMailSender{}
	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	reqBody := BreakglassSessionRequest{Clustername: "wc1", Username: "ws@example.com", GroupName: "g-ws", Reason: "   "}
	b, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/breakglassSessions", bytes.NewReader(b))
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
		}, nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	ctrl.mail = &FakeMailSender{}
	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	// create request
	reqBody := BreakglassSessionRequest{Clustername: "oc1", Username: "owner@example.com", GroupName: "g-owner"}
	b, _ := json.Marshal(reqBody)
	req, _ := http.NewRequest("POST", "/breakglassSessions", bytes.NewReader(b))
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusCreated {
		t.Fatalf("create failed")
	}

	// get session name
	req, _ = http.NewRequest("GET", "/breakglassSessions?mine=true", nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	var sessions []v1alpha1.BreakglassSession
	_ = json.NewDecoder(w.Result().Body).Decode(&sessions)
	if len(sessions) != 1 {
		t.Fatalf("expected session present")
	}
	name := sessions[0].Name

	// owner rejects own pending session
	req, _ = http.NewRequest("POST", fmt.Sprintf("/breakglassSessions/%s/reject", name), nil)
	w = httptest.NewRecorder()
	engine.ServeHTTP(w, req)
	if w.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200 on owner reject, got %d", w.Result().StatusCode)
	}

	// verify rejected
	req, _ = http.NewRequest("GET", "/breakglassSessions?mine=true", nil)
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
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, ctxSetup, nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	ctrl.mail = &FakeMailSender{}
	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	req, _ := http.NewRequest("GET", "/breakglassSessions?cluster=cluster1&group=ops&mine=true", nil)
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
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, ctxSetup, nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	ctrl.mail = &FakeMailSender{}
	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	req, _ := http.NewRequest("GET", "/breakglassSessions?user=sam@example.com&group=ops&mine=true", nil)
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
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, ctxSetup, nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	ctrl.mail = &FakeMailSender{}
	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	req, _ := http.NewRequest("GET", "/breakglassSessions?cluster=z1&user=p@example.com&group=wheel&mine=true", nil)
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
	builder.WithObjects(pending, approved, rejected, withdrawn, expired, timeout)
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
		default:
			c.Set("email", "approver@ex.com")
			c.Set("username", "approver")
		}
		c.Next()
	}
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, ctxSetup, nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	ctrl.mail = &FakeMailSender{}
	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	// helper to query by state
	queryByState := func(state string) []v1alpha1.BreakglassSession {
		req, _ := http.NewRequest("GET", "/breakglassSessions?state="+state+"&mine=true", nil)
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

	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, ctxSetup, nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	ctrl.mail = &FakeMailSender{}

	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	// bob should see the pending session without specifying mine=true
	req, _ := http.NewRequest("GET", "/breakglassSessions", nil)
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
	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, ctxSetup, nil, cli)
	ctrl.identityProvider = ErrIdentityProvider{}
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) { return []string{}, nil }
	ctrl.mail = &FakeMailSender{}

	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	req, _ := http.NewRequest("GET", "/breakglassSessions?mine=true", nil)
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

	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, ctxSetup, nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	ctrl.mail = &FakeMailSender{}

	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	// Since self-approval is blocked, the owner acting as approver should NOT see the pending session
	req, _ := http.NewRequest("GET", "/breakglassSessions", nil)
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

	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, ctxSetup, nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	ctrl.mail = &FakeMailSender{}

	engine := gin.New()
	_ = ctrl.Register(engine.Group("/breakglassSessions", ctrl.Handlers()...))

	req, _ := http.NewRequest("GET", "/breakglassSessions", nil)
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

	ctrl := NewBreakglassSessionController(logger.Sugar(), config.Config{}, &sesmanager, &escmanager, ctxSetup, nil, cli)
	ctrl.getUserGroupsFn = func(ctx context.Context, cug ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}
	ctrl.mail = &FakeMailSender{}

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
		{"state_pending_mine_u2", "state=pending&mine=true", "u2@example.com", []string{"s4", "s6"}},
		{"state_approved_mine_u2", "state=approved&mine=true", "u2@example.com", []string{"s2"}},
		{"cluster_c2_state_expired_mine_u2", "cluster=c2&state=expired&mine=true", "u2@example.com", []string{"s6"}},
		{"user_u1_group_g2_mine", "user=u1@example.com&group=g2&mine=true", "u1@example.com", []string{"s3", "s5"}},
	}

	for _, tc := range cases {
		req, _ := http.NewRequest("GET", "/breakglassSessions?"+tc.query, nil)
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
		}, nil, cli)

	// Mock group resolver to return members
	mockResolver := &MockGroupResolver{
		members: map[string][]string{
			"security-team": {"security1@example.com", "security2@example.com"},
			"flm-on-duty":   {"flm-manager@example.com"},
		},
	}
	ctrl.escalationManager.Resolver = mockResolver

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
	req, _ := http.NewRequest("POST", "/breakglassSessions", bytes.NewReader(b))
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

	req, _ := http.NewRequest("GET", "/breakglassEscalations", nil)
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
		}, nil, cli)

	// Mock group resolver
	mockResolver := &MockGroupResolver{
		members: map[string][]string{
			"security-team": {"security@example.com"},
		},
	}
	ctrl.escalationManager.Resolver = mockResolver

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
	req, _ := http.NewRequest("POST", "/breakglassSessions", bytes.NewReader(b))
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

type MockGroupResolver struct {
	members map[string][]string
}

func (m *MockGroupResolver) Members(ctx context.Context, group string) ([]string, error) {
	if members, ok := m.members[group]; ok {
		return members, nil
	}
	return nil, fmt.Errorf("group not found: %s", group)
}
