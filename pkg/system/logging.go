// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

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
			// full groups list is useful at debug level only
			reqLogger.Debugw("Request token groups", "groups", groups)
		}
	}
	return reqLogger
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
