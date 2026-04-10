package system

import (
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

// ReqLoggerKey is the context key used to store request-scoped logger in gin context.
const ReqLoggerKey = "reqLogger"

// GetReqLogger returns the request-scoped sugared logger from gin.Context if present,
// otherwise returns a fallback sugared logger derived from the provided zap.Logger.
func GetReqLogger(c *gin.Context, fallback *zap.SugaredLogger) *zap.SugaredLogger {
	if c == nil {
		return fallback
	}
	if v, ok := c.Get(ReqLoggerKey); ok {
		if l, ok2 := v.(*zap.SugaredLogger); ok2 {
			return l
		}
	}
	return fallback
}

// EnrichReqLoggerWithAuth annotates the request-scoped logger with any auth-related
// identity fields available in the Gin context (email, username, groups). Returns a
// new sugared logger with the additional fields attached.
func EnrichReqLoggerWithAuth(c *gin.Context, reqLogger *zap.SugaredLogger) *zap.SugaredLogger {
	if c == nil || reqLogger == nil {
		return reqLogger
	}
	if v, ok := c.Get("email"); ok {
		if email, ok2 := v.(string); ok2 && email != "" {
			reqLogger = reqLogger.With("email", email)
		}
	}
	if v, ok := c.Get("username"); ok {
		if username, ok2 := v.(string); ok2 && username != "" {
			reqLogger = reqLogger.With("username", username)
		}
	}
	if v, ok := c.Get("groups"); ok {
		if groups, ok2 := v.([]string); ok2 && len(groups) > 0 {
			reqLogger = reqLogger.With("groupCount", len(groups))
			reqLogger.Debugw("Request token groups", "groupCount", len(groups), "groups", "[REDACTED]")
		}
	}
	return reqLogger
}

// RedactGroupName returns a short hint for a group name so logs can correlate
// related events without disclosing the full value. The hint is a partial mask:
// short names (≤4 runes) are fully masked; longer names expose only the first 3
// runes followed by "***". This is NOT a cryptographically non-reversible
// redaction — it reduces incidental disclosure in logs but is NOT a substitute
// for access controls on log aggregation systems.
// Behaviour:
//   - 0 runes  → ""
//   - 1–4 runes → "***"  (fully masked to avoid disclosing short names like "ops", "sre")
//   - 5+ runes → first 3 chars + "***"
func RedactGroupName(name string) string {
	if name == "" {
		return ""
	}
	runes := []rune(name)
	if len(runes) <= 4 {
		return "***"
	}
	return string(runes[:3]) + "***"
}

// NamespacedFields returns a variadic slice of key/value pairs suitable for passing
// to SugaredLogger.With or Infow/Errorw calls. If namespace is empty it will only
// include the "name" key; otherwise it includes both "name" and "namespace".
func NamespacedFields(name, namespace string) []interface{} {
	if namespace == "" {
		return []interface{}{"name", name}
	}
	return []interface{}{"name", name, "namespace", namespace}
}
