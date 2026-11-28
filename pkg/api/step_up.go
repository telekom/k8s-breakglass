package api

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/telekom/k8s-breakglass/pkg/apiresponses"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"go.uber.org/zap"
)

// StepUpChallengeHeader carries the server-issued, single-use step-up
// challenge. The server sets it on a 428 response; the client repeats the
// request with the same header.
const StepUpChallengeHeader = "X-Breakglass-Step-Up-Challenge"

const (
	stepUpChallengeTTL  = 2 * time.Minute
	stepUpMaxChallenges = 10000
	stepUpClockSkew     = time.Minute
)

// stepUpActions maps the action names accepted in stepUp.actions to the
// "METHOD route" they guard. Routes are the Gin route patterns registered by
// the API controllers under /api.
var stepUpActions = map[string]string{
	"session.request":                       http.MethodPost + " /api/breakglassSessions",
	"session.approve":                       http.MethodPost + " /api/breakglassSessions/:name/approve",
	"session.reject":                        http.MethodPost + " /api/breakglassSessions/:name/reject",
	"session.cancel":                        http.MethodPost + " /api/breakglassSessions/:name/cancel",
	"debugSession.create":                   http.MethodPost + " /api/debugSessions",
	"debugSession.approve":                  http.MethodPost + " /api/debugSessions/:name/approve",
	"debugSession.reject":                   http.MethodPost + " /api/debugSessions/:name/reject",
	"debugSession.join":                     http.MethodPost + " /api/debugSessions/:name/join",
	"debugSession.renew":                    http.MethodPost + " /api/debugSessions/:name/renew",
	"debugSession.terminate":                http.MethodPost + " /api/debugSessions/:name/terminate",
	"debugSession.injectEphemeralContainer": http.MethodPost + " /api/debugSessions/:name/injectEphemeralContainer",
	"debugSession.createPodCopy":            http.MethodPost + " /api/debugSessions/:name/createPodCopy",
	"debugSession.createNodeDebugPod":       http.MethodPost + " /api/debugSessions/:name/createNodeDebugPod",
}

// defaultStepUpActions is the proposed critical-action list, pending
// confirmation by Platform IAM.
var defaultStepUpActions = []string{
	"session.request",
	"session.approve",
	"session.cancel",
	"debugSession.create",
	"debugSession.approve",
}

type stepUp struct {
	maxAuthAge  time.Duration
	requiredACR []string
	routes      map[string]string // "METHOD route" -> action name
	challenges  *stepUpChallengeStore
	log         *zap.Logger
	now         func() time.Time
}

// newStepUp validates cfg and returns nil when step-up is disabled.
func newStepUp(cfg config.StepUp, log *zap.Logger) (*stepUp, error) {
	if !cfg.Enabled {
		return nil, nil
	}
	s := &stepUp{
		requiredACR: cfg.RequiredACR,
		routes:      map[string]string{},
		challenges:  &stepUpChallengeStore{byKey: map[string]stepUpChallenge{}},
		log:         log,
		now:         time.Now,
	}
	if cfg.MaxAuthAge != "" {
		d, err := time.ParseDuration(cfg.MaxAuthAge)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("stepUp.maxAuthAge %q: must be a positive duration", cfg.MaxAuthAge)
		}
		s.maxAuthAge = d
	}
	for _, acr := range cfg.RequiredACR {
		if acr == "" || strings.ContainsAny(acr, " \"\\") {
			return nil, fmt.Errorf("stepUp.requiredACR %q: must be non-empty without spaces, quotes or backslashes", acr)
		}
	}
	if s.maxAuthAge == 0 && len(s.requiredACR) == 0 {
		return nil, fmt.Errorf("stepUp.enabled requires stepUp.maxAuthAge or stepUp.requiredACR")
	}
	actions := cfg.Actions
	if len(actions) == 0 {
		actions = defaultStepUpActions
	}
	for _, action := range actions {
		route, ok := stepUpActions[action]
		if !ok {
			return nil, fmt.Errorf("stepUp.actions: unknown action %q", action)
		}
		s.routes[route] = action
	}
	return s, nil
}

// middleware must run after the authentication middleware, which sets the
// verified "raw_claims". Requests to non-critical routes pass through.
func (s *stepUp) middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		action, critical := s.routes[c.Request.Method+" "+c.FullPath()]
		if !critical {
			c.Next()
			return
		}
		rawClaims, _ := c.Get("raw_claims")
		claims, _ := rawClaims.(jwt.MapClaims)
		if claims == nil {
			apiresponses.RespondUnauthorized(c)
			c.Abort()
			return
		}
		if reason := s.insufficient(claims); reason != "" {
			s.log.Info("step-up authentication required", zap.String("action", action), zap.String("reason", reason))
			s.requireAuthentication(c, reason)
			return
		}
		now := s.now()
		key := stepUpBindingKey(claims, action, c.Request.URL.Path)
		if s.challenges.consume(key, c.GetHeader(StepUpChallengeHeader), now) {
			c.Next()
			return
		}
		nonce, ok := s.challenges.issue(key, now)
		if !ok {
			apiresponses.RespondError(c, http.StatusServiceUnavailable, "too many pending step-up challenges, try again later", "")
			c.Abort()
			return
		}
		c.Header(StepUpChallengeHeader, nonce)
		apiresponses.RespondError(c, http.StatusPreconditionRequired, "step-up challenge required",
			"repeat the request with the "+StepUpChallengeHeader+" response header")
		c.Abort()
	}
}

// insufficient returns why the token does not satisfy step-up, or "".
func (s *stepUp) insufficient(claims jwt.MapClaims) string {
	if s.maxAuthAge > 0 {
		authTime, ok := numericClaim(claims["auth_time"])
		if !ok {
			return "auth_time claim missing"
		}
		age := s.now().Sub(time.Unix(authTime, 0))
		if age > s.maxAuthAge || age < -stepUpClockSkew {
			return "authentication is not recent enough"
		}
	}
	if len(s.requiredACR) > 0 {
		acr, _ := claims["acr"].(string)
		if !slices.Contains(s.requiredACR, acr) {
			return "authentication context class not accepted"
		}
	}
	return ""
}

// requireAuthentication sends the RFC 9470 insufficient_user_authentication
// challenge.
func (s *stepUp) requireAuthentication(c *gin.Context, reason string) {
	params := []string{`error="insufficient_user_authentication"`, `error_description="` + reason + `"`}
	if s.maxAuthAge > 0 {
		params = append(params, `max_age="`+strconv.Itoa(int(s.maxAuthAge.Seconds()))+`"`)
	}
	if len(s.requiredACR) > 0 {
		params = append(params, `acr_values="`+strings.Join(s.requiredACR, " ")+`"`)
	}
	c.Header("WWW-Authenticate", "Bearer "+strings.Join(params, ", "))
	apiresponses.RespondUnauthorizedWithMessage(c, "step-up authentication required: "+reason)
	c.Abort()
}

// stepUpBindingKey ties a challenge to the IdP session and authentication
// event (sub, sid, auth_time), the action and the concrete target path.
func stepUpBindingKey(claims jwt.MapClaims, action, path string) string {
	sub, _ := claims["sub"].(string)
	sid, _ := claims["sid"].(string)
	authTime, _ := numericClaim(claims["auth_time"])
	return strings.Join([]string{sub, sid, strconv.FormatInt(authTime, 10), action, path}, "\x00")
}

func numericClaim(v any) (int64, bool) {
	switch n := v.(type) {
	case float64:
		return int64(n), true
	case json.Number:
		i, err := n.Int64()
		return i, err == nil
	}
	return 0, false
}

type stepUpChallenge struct {
	nonce   string
	expires time.Time
}

// stepUpChallengeStore holds one outstanding challenge per binding key.
// ponytail: in-memory and per replica; a challenge issued by one replica is
// unknown to the others. Use session affinity or move to a shared store
// before running several API replicas with step-up enabled.
type stepUpChallengeStore struct {
	mu    sync.Mutex
	byKey map[string]stepUpChallenge
}

func (s *stepUpChallengeStore) issue(key string, now time.Time) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.byKey[key]; !exists && len(s.byKey) >= stepUpMaxChallenges {
		for k, ch := range s.byKey {
			if now.After(ch.expires) {
				delete(s.byKey, k)
			}
		}
		if len(s.byKey) >= stepUpMaxChallenges {
			return "", false
		}
	}
	nonce := rand.Text()
	s.byKey[key] = stepUpChallenge{nonce: nonce, expires: now.Add(stepUpChallengeTTL)}
	return nonce, true
}

// consume reports whether nonce is the outstanding challenge for key and
// removes it, so each challenge is accepted at most once.
func (s *stepUpChallengeStore) consume(key, nonce string, now time.Time) bool {
	if nonce == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	ch, ok := s.byKey[key]
	if !ok || subtle.ConstantTimeCompare([]byte(ch.nonce), []byte(nonce)) != 1 {
		return false
	}
	delete(s.byKey, key)
	return !now.After(ch.expires)
}
