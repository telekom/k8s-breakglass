package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/breakglass/debug"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"go.uber.org/zap/zaptest"
)

const stepUpApprovePath = "/api/breakglassSessions/s1/approve"

// stepUpController registers an approve route behind a fake authentication
// middleware that sets the claims of the test request.
type stepUpController struct{ claims jwt.MapClaims }

func (stepUpController) BasePath() string { return "breakglassSessions" }

func (stepUpController) Register(rg *gin.RouterGroup) error {
	rg.POST(":name/approve", func(c *gin.Context) { c.Status(http.StatusOK) })
	rg.GET(":name", func(c *gin.Context) { c.Status(http.StatusOK) })
	return nil
}

func (s stepUpController) Handlers() []gin.HandlerFunc {
	return []gin.HandlerFunc{func(c *gin.Context) {
		if s.claims != nil {
			c.Set("raw_claims", s.claims)
		}
	}}
}

func newStepUpServer(t *testing.T, stepUp config.StepUp, claims jwt.MapClaims) *Server {
	t.Helper()
	gin.SetMode(gin.TestMode)
	server := NewServer(zaptest.NewLogger(t), config.Config{Server: config.Server{AllowedOrigins: []string{"https://ui.example.com"}}, StepUp: stepUp}, true, &AuthHandler{})
	require.NoError(t, server.RegisterAll([]APIController{stepUpController{claims: claims}}))
	return server
}

func serveStepUp(server *Server, method, path, challenge string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, nil)
	if challenge != "" {
		req.Header.Set(StepUpChallengeHeader, challenge)
	}
	w := httptest.NewRecorder()
	server.gin.ServeHTTP(w, req)
	return w
}

// approve performs the challenge round trip and returns the final response.
func approve(t *testing.T, server *Server) *httptest.ResponseRecorder {
	t.Helper()
	w := serveStepUp(server, http.MethodPost, stepUpApprovePath, "")
	if w.Code != http.StatusPreconditionRequired {
		return w
	}
	challenge := w.Header().Get(StepUpChallengeHeader)
	require.NotEmpty(t, challenge)
	return serveStepUp(server, http.MethodPost, stepUpApprovePath, challenge)
}

var maxAgeStepUp = config.StepUp{Enabled: true, MaxAuthAge: "5m"}

func TestStepUp(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name       string
		stepUp     config.StepUp
		claims     jwt.MapClaims
		wantCode   int
		wantHeader string
	}{
		{
			name:     "fresh token passes",
			stepUp:   maxAgeStepUp,
			claims:   jwt.MapClaims{"sub": "alice", "auth_time": float64(now.Add(-time.Minute).Unix())},
			wantCode: http.StatusOK,
		},
		{
			name:       "stale auth_time is rejected",
			stepUp:     maxAgeStepUp,
			claims:     jwt.MapClaims{"sub": "alice", "auth_time": float64(now.Add(-time.Hour).Unix())},
			wantCode:   http.StatusUnauthorized,
			wantHeader: `Bearer error="insufficient_user_authentication", error_description="authentication is not recent enough", max_age="300"`,
		},
		{
			name:       "missing auth_time is rejected",
			stepUp:     maxAgeStepUp,
			claims:     jwt.MapClaims{"sub": "alice"},
			wantCode:   http.StatusUnauthorized,
			wantHeader: `Bearer error="insufficient_user_authentication", error_description="auth_time claim missing", max_age="300"`,
		},
		{
			name:     "accepted acr passes",
			stepUp:   config.StepUp{Enabled: true, RequiredACR: []string{"gold", "platinum"}},
			claims:   jwt.MapClaims{"sub": "alice", "acr": "gold"},
			wantCode: http.StatusOK,
		},
		{
			name:       "wrong acr is rejected",
			stepUp:     config.StepUp{Enabled: true, RequiredACR: []string{"gold", "platinum"}},
			claims:     jwt.MapClaims{"sub": "alice", "acr": "1"},
			wantCode:   http.StatusUnauthorized,
			wantHeader: `Bearer error="insufficient_user_authentication", error_description="authentication context class not accepted", acr_values="gold platinum"`,
		},
		{
			name:     "missing claims fail closed",
			stepUp:   maxAgeStepUp,
			wantCode: http.StatusUnauthorized,
		},
		{
			name:     "flag off leaves stale token unchanged",
			stepUp:   config.StepUp{MaxAuthAge: "5m"},
			claims:   jwt.MapClaims{"sub": "alice"},
			wantCode: http.StatusOK,
		},
		{
			name:     "action outside the list is not checked",
			stepUp:   config.StepUp{Enabled: true, MaxAuthAge: "5m", Actions: []string{"debugSession.approve"}},
			claims:   jwt.MapClaims{"sub": "alice"},
			wantCode: http.StatusOK,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := approve(t, newStepUpServer(t, tt.stepUp, tt.claims))
			assert.Equal(t, tt.wantCode, w.Code, w.Body.String())
			assert.Equal(t, tt.wantHeader, w.Header().Get("WWW-Authenticate"))
		})
	}
}

func TestStepUpChallenge(t *testing.T) {
	claims := jwt.MapClaims{"sub": "alice", "sid": "s-1", "auth_time": float64(time.Now().Unix())}

	t.Run("replayed challenge is rejected", func(t *testing.T) {
		server := newStepUpServer(t, maxAgeStepUp, claims)
		first := serveStepUp(server, http.MethodPost, stepUpApprovePath, "")
		require.Equal(t, http.StatusPreconditionRequired, first.Code)
		challenge := first.Header().Get(StepUpChallengeHeader)

		require.Equal(t, http.StatusOK, serveStepUp(server, http.MethodPost, stepUpApprovePath, challenge).Code)
		replay := serveStepUp(server, http.MethodPost, stepUpApprovePath, challenge)
		assert.Equal(t, http.StatusPreconditionRequired, replay.Code)
		assert.NotEqual(t, challenge, replay.Header().Get(StepUpChallengeHeader))
	})

	t.Run("challenge is bound to the target", func(t *testing.T) {
		server := newStepUpServer(t, maxAgeStepUp, claims)
		challenge := serveStepUp(server, http.MethodPost, stepUpApprovePath, "").Header().Get(StepUpChallengeHeader)
		other := serveStepUp(server, http.MethodPost, "/api/breakglassSessions/s2/approve", challenge)
		assert.Equal(t, http.StatusPreconditionRequired, other.Code)
	})

	t.Run("expired challenge is rejected", func(t *testing.T) {
		store := &stepUpChallengeStore{byKey: map[string]stepUpChallenge{}}
		now := time.Now()
		nonce, ok := store.issue("k", now)
		require.True(t, ok)
		assert.False(t, store.consume("k", nonce, now.Add(stepUpChallengeTTL+time.Second)))
	})

	t.Run("read routes need no challenge", func(t *testing.T) {
		server := newStepUpServer(t, maxAgeStepUp, jwt.MapClaims{"sub": "alice"})
		assert.Equal(t, http.StatusOK, serveStepUp(server, http.MethodGet, "/api/breakglassSessions/s1", "").Code)
	})
}

func TestNewStepUpValidation(t *testing.T) {
	for name, cfg := range map[string]config.StepUp{
		"no requirement": {Enabled: true},
		"bad duration":   {Enabled: true, MaxAuthAge: "soon"},
		"negative":       {Enabled: true, MaxAuthAge: "-1m"},
		"acr with quote": {Enabled: true, RequiredACR: []string{`a"b`}},
		"unknown action": {Enabled: true, MaxAuthAge: "5m", Actions: []string{"denyPolicy.update"}},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := newStepUp(cfg, zaptest.NewLogger(t))
			assert.Error(t, err)
		})
	}
	s, err := newStepUp(config.StepUp{}, zaptest.NewLogger(t))
	assert.NoError(t, err)
	assert.Nil(t, s)
}

func TestStepUpCORSHeaders(t *testing.T) {
	gin.SetMode(gin.TestMode)
	cfg := config.Config{Server: config.Server{AllowedOrigins: []string{"https://ui.example.com"}}, StepUp: maxAgeStepUp}
	server := NewServer(zaptest.NewLogger(t), cfg, true, &AuthHandler{})
	req := httptest.NewRequest(http.MethodOptions, stepUpApprovePath, nil)
	req.Header.Set("Origin", "https://ui.example.com")
	req.Header.Set("Access-Control-Request-Method", http.MethodPost)
	req.Header.Set("Access-Control-Request-Headers", StepUpChallengeHeader)
	w := httptest.NewRecorder()
	server.gin.ServeHTTP(w, req)
	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.True(t, headerListContains(strings.Split(w.Header().Get("Access-Control-Allow-Headers"), ","), StepUpChallengeHeader))
}

// TestStepUpActionsMatchRoutes guards against route renames silently
// disabling step-up for an action.
func TestStepUpActionsMatchRoutes(t *testing.T) {
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	api := engine.Group("/api")
	for _, c := range []APIController{&breakglass.BreakglassSessionController{}, &debug.DebugSessionAPIController{}} {
		require.NoError(t, c.Register(api.Group(c.BasePath())))
	}
	routes := map[string]bool{}
	for _, r := range engine.Routes() {
		routes[r.Method+" "+r.Path] = true
	}
	for action, route := range stepUpActions {
		assert.True(t, routes[route], "action %s: route %q is not registered", action, route)
	}
}
