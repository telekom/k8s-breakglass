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
	var response breakglassSessionErrorResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	assert.Equal(t, "session already in requested state", response.Error)
	assert.Equal(t, "CONFLICT", response.Code)
	assert.Equal(t, "session-1", response.Session.Name)
}

func TestRespondBreakglassSessionNotFoundPreservesSessionField(t *testing.T) {
	gin.SetMode(gin.TestMode)
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	respondBreakglassSessionNotFound(c, "missing-session")

	require.Equal(t, http.StatusNotFound, w.Code)
	var response breakglassSessionNameErrorResponse
	require.NoError(t, json.Unmarshal(w.Body.Bytes(), &response))
	assert.Equal(t, "session not found", response.Error)
	assert.Equal(t, "NOT_FOUND", response.Code)
	assert.Equal(t, "missing-session", response.Session)
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
			name:     "unknown client status",
			status:   http.StatusTeapot,
			expected: "ERROR",
		},
		{
			name:     "unknown server status",
			status:   http.StatusBadGateway,
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
