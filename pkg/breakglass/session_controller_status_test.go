package breakglass

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap/zaptest"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func TestRespondBreakglassSessionErrorIncludesSession(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	session := breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session-1"},
	}
	respondBreakglassSessionError(c, http.StatusConflict, "session already in requested state", session)

	require.Equal(t, http.StatusConflict, w.Code)
	var response map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	var message, code string
	require.NoError(t, json.Unmarshal(response["error"], &message))
	require.NoError(t, json.Unmarshal(response["code"], &code))
	var responseSession breakglassv1alpha1.BreakglassSession
	require.NoError(t, json.Unmarshal(response["session"], &responseSession))
	assert.Equal(t, "session already in requested state", message)
	assert.Equal(t, "CONFLICT", code)
	assert.Equal(t, "session-1", responseSession.Name)
}

func TestRespondBreakglassSessionNotFoundPreservesSessionField(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	respondBreakglassSessionNotFound(c, "missing-session")

	require.Equal(t, http.StatusNotFound, w.Code)
	var response map[string]string
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	assert.Equal(t, "session not found", response["error"])
	assert.Equal(t, "NOT_FOUND", response["code"])
	assert.Equal(t, "missing-session", response["session"])
}

func TestSetSessionStatusHelperRejectsTerminalNonApprovalTransition(t *testing.T) {
	gin.SetMode(gin.TestMode)
	log := zaptest.NewLogger(t).Sugar()
	scheme := runtime.NewScheme()
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))

	session := &breakglassv1alpha1.BreakglassSession{
		ObjectMeta: metav1.ObjectMeta{Name: "expired-session"},
		Spec: breakglassv1alpha1.BreakglassSessionSpec{
			Cluster:      "test-cluster",
			User:         "requester@example.com",
			GrantedGroup: "admin-group",
		},
		Status: breakglassv1alpha1.BreakglassSessionStatus{
			State: breakglassv1alpha1.SessionStateExpired,
		},
	}
	escalation := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "admin-escalation"},
		Spec: breakglassv1alpha1.BreakglassEscalationSpec{
			Allowed: breakglassv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{"test-cluster"},
				Groups:   []string{"system:authenticated"},
			},
			EscalatedGroup: "admin-group",
			Approvers: breakglassv1alpha1.BreakglassEscalationApprovers{
				Users: []string{"approver@example.com"},
			},
		},
	}
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(session, escalation).Build()
	ctrl := &BreakglassSessionController{
		log:               log,
		sessionManager:    &SessionManager{Client: fakeClient},
		escalationManager: &testEscalationLookup{Client: fakeClient},
		identityProvider:  KeycloakIdentityProvider{log: log},
	}
	ctrl.getUserGroupsFn = func(context.Context, ClusterUserGroup) ([]string, error) {
		return []string{"system:authenticated"}, nil
	}

	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)
	// setSessionStatus is currently registered only for approve/reject routes.
	// This direct helper call documents the defensive branch used if an internal
	// caller adds a non-approval transition later.
	c.Request = httptest.NewRequest(http.MethodPost, "/internal/session-status-helper", nil)
	c.Params = gin.Params{{Key: "name", Value: "expired-session"}}
	c.Set("email", "approver@example.com")
	c.Set("username", "approver")
	c.Set("user_id", "approver@example.com")
	c.Set("groups", []string{"system:authenticated"})

	ctrl.setSessionStatus(c, breakglassv1alpha1.SessionConditionTypeExpired)

	require.Equal(t, http.StatusBadRequest, w.Code)
	var response map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	var message, code string
	require.NoError(t, json.Unmarshal(response["error"], &message))
	require.NoError(t, json.Unmarshal(response["code"], &code))
	var responseSession breakglassv1alpha1.BreakglassSession
	require.NoError(t, json.Unmarshal(response["session"], &responseSession))
	assert.Equal(t, "session is in terminal state Expired and cannot be modified", message)
	assert.Equal(t, "BAD_REQUEST", code)
	assert.Equal(t, "expired-session", responseSession.Name)
}

func TestBreakglassSessionErrorCode(t *testing.T) {
	tests := []struct {
		name     string
		status   int
		expected string
	}{
		{
			name:     "bad request",
			status:   http.StatusBadRequest,
			expected: "BAD_REQUEST",
		},
		{
			name:     "unauthorized",
			status:   http.StatusUnauthorized,
			expected: "UNAUTHORIZED",
		},
		{
			name:     "forbidden",
			status:   http.StatusForbidden,
			expected: "FORBIDDEN",
		},
		{
			name:     "conflict",
			status:   http.StatusConflict,
			expected: "CONFLICT",
		},
		{
			name:     "not found",
			status:   http.StatusNotFound,
			expected: "NOT_FOUND",
		},
		{
			name:     "unprocessable entity",
			status:   http.StatusUnprocessableEntity,
			expected: "UNPROCESSABLE_ENTITY",
		},
		{
			name:     "too many requests",
			status:   http.StatusTooManyRequests,
			expected: "TOO_MANY_REQUESTS",
		},
		{
			name:     "bad gateway",
			status:   http.StatusBadGateway,
			expected: "BAD_GATEWAY",
		},
		{
			name:     "service unavailable",
			status:   http.StatusServiceUnavailable,
			expected: "SERVICE_UNAVAILABLE",
		},
		{
			name:     "unknown client status",
			status:   http.StatusTeapot,
			expected: "ERROR",
		},
		{
			name:     "unknown server status",
			status:   http.StatusGatewayTimeout,
			expected: "INTERNAL_ERROR",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			assert.Equal(t, tt.expected, breakglassSessionErrorCode(tt.status))
		})
	}
}

func TestCheckSessionLimits_MissingIDP(t *testing.T) {
	log := zaptest.NewLogger(t).Sugar()
	scheme := runtime.NewScheme()
	_ = breakglassv1alpha1.AddToScheme(scheme)
	fakeClient := fake.NewClientBuilder().WithScheme(scheme).Build()

	wc := &BreakglassSessionController{
		sessionManager: &SessionManager{
			Client: fakeClient,
		},
	}

	esc := &breakglassv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{Name: "test-esc"},
	}

	err := wc.checkSessionLimits(context.Background(), esc, "missing-idp", "test@example.com", []string{"developers"}, log)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "IdentityProvider \"missing-idp\" not found")
}
