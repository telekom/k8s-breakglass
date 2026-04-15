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
			reqLogger.Debugw("Request token groups", "groups", "[REDACTED]")
		}
	}
	return reqLogger
}

// RedactGroupName fully redacts a group name so that no prefix or structural
// signal is disclosed in log output. Any non-empty name is replaced with the
// literal string "[REDACTED]"; empty names are returned as-is.
//
// This is NOT a cryptographically non-reversible redaction — it prevents
// incidental log disclosure but is NOT a substitute for access controls on
// log aggregation systems.
func RedactGroupName(name string) string {
	if name == "" {
		return ""
	}
	return "[REDACTED]"
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
