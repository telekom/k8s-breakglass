/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package apiresponses

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	"go.uber.org/zap"
)

const (
	// CIDKey is the gin context key that holds the request correlation ID.
	CIDKey = "cid"
	// RequestIDHeader carries the correlation ID back to the client.
	RequestIDHeader = "X-Request-ID"
)

// APIError is the one error body every REST endpoint returns. Error keeps the
// human-readable message, Code is machine-readable and CID is the request
// correlation ID (also sent as X-Request-ID). Details carries extra context,
// for example a "; "-separated list of validation messages. Responses that
// need more fields embed APIError, built with NewError.
type APIError struct {
	Error   string `json:"error"`
	Code    string `json:"code"`
	CID     string `json:"cid"`
	Details string `json:"details,omitempty"`
}

// CorrelationID returns the request correlation ID. When no middleware set
// one (for example on an engine without the correlation middleware), it
// generates one, stores it and echoes it in the X-Request-ID header so the
// client can still quote it.
func CorrelationID(c *gin.Context) string {
	if v, ok := c.Get(CIDKey); ok {
		if cid, ok := v.(string); ok && cid != "" {
			return cid
		}
	}
	cid := uuid.NewString()
	c.Set(CIDKey, cid)
	c.Header(RequestIDHeader, cid)
	return cid
}

// NewError builds the standard error body for the request.
func NewError(c *gin.Context, code, message string) APIError {
	return APIError{Error: message, Code: code, CID: CorrelationID(c)}
}

// CodeForStatus maps an HTTP status to the standard error code.
func CodeForStatus(status int) string {
	switch status {
	case http.StatusBadRequest:
		return "BAD_REQUEST"
	case http.StatusUnauthorized:
		return "UNAUTHORIZED"
	case http.StatusForbidden:
		return "FORBIDDEN"
	case http.StatusNotFound:
		return "NOT_FOUND"
	case http.StatusConflict:
		return "CONFLICT"
	case http.StatusGone:
		return "GONE"
	case http.StatusRequestEntityTooLarge:
		return "PAYLOAD_TOO_LARGE"
	case http.StatusUnprocessableEntity:
		return "UNPROCESSABLE_ENTITY"
	case http.StatusTooManyRequests:
		return "TOO_MANY_REQUESTS"
	case http.StatusBadGateway:
		return "BAD_GATEWAY"
	case http.StatusServiceUnavailable:
		return "SERVICE_UNAVAILABLE"
	default:
		if status >= http.StatusInternalServerError {
			return "INTERNAL_ERROR"
		}
		return "ERROR"
	}
}

func respond(c *gin.Context, status int, message, details string) {
	body := NewError(c, CodeForStatus(status), message)
	body.Details = details
	c.JSON(status, body)
}

// RespondError sends the standard error body for any status; the code is
// derived from the status.
func RespondError(c *gin.Context, status int, message, details string) {
	respond(c, status, message, details)
}

// RespondNotFound sends a 404 Not Found response with a standardized message.
// Use this when a requested resource does not exist.
func RespondNotFound(c *gin.Context, resourceType, resourceName string) {
	respond(c, http.StatusNotFound, fmt.Sprintf("%s not found: %s", resourceType, resourceName), "")
}

// RespondNotFoundSimple sends a 404 Not Found response with a simple message.
func RespondNotFoundSimple(c *gin.Context, message string) {
	respond(c, http.StatusNotFound, message, "")
}

// RespondUnauthorized sends a 401 Unauthorized response.
// Use this when authentication is missing or invalid.
func RespondUnauthorized(c *gin.Context) {
	respond(c, http.StatusUnauthorized, "user not authenticated", "")
}

// RespondUnauthorizedWithMessage sends a 401 Unauthorized response with a custom message.
func RespondUnauthorizedWithMessage(c *gin.Context, message string) {
	if message == "" {
		message = "user not authenticated"
	}
	respond(c, http.StatusUnauthorized, message, "")
}

// RespondForbidden sends a 403 Forbidden response with an optional reason.
// Use this when the user is authenticated but not authorized for the action.
func RespondForbidden(c *gin.Context, reason string) {
	if reason == "" {
		reason = "access denied"
	}
	respond(c, http.StatusForbidden, reason, "")
}

// RespondBadRequest sends a 400 Bad Request response.
// Use this for client errors like malformed JSON or invalid parameters.
func RespondBadRequest(c *gin.Context, message string) {
	respond(c, http.StatusBadRequest, message, "")
}

// RespondBadRequestWithDetails sends a 400 Bad Request with additional details.
func RespondBadRequestWithDetails(c *gin.Context, message, details string) {
	respond(c, http.StatusBadRequest, message, details)
}

// RespondConflict sends a 409 Conflict response.
// Use this when the request conflicts with current state (e.g., already approved).
func RespondConflict(c *gin.Context, message string) {
	respond(c, http.StatusConflict, message, "")
}

// RespondInternalError sends a 500 Internal Server Error response.
// It logs the error with full details but returns a sanitized message to the client.
func RespondInternalError(c *gin.Context, operation string, err error, log *zap.SugaredLogger) {
	if log != nil {
		log.Errorw(fmt.Sprintf("Failed to %s", operation), "error", err)
	}
	respond(c, http.StatusInternalServerError, fmt.Sprintf("failed to %s", operation), "")
}

// RespondInternalErrorSimple sends a 500 response with a simple message.
// Use this when you've already logged the error or don't need detailed logging.
func RespondInternalErrorSimple(c *gin.Context, message string) {
	respond(c, http.StatusInternalServerError, message, "")
}

// RespondTooManyRequests sends a 429 Too Many Requests response.
func RespondTooManyRequests(c *gin.Context, message string) {
	if message == "" {
		message = "too many requests"
	}
	respond(c, http.StatusTooManyRequests, message, "")
}

// RespondTooManyRequestsWithRetryAfter sends a 429 Too Many Requests response
// with a Retry-After header indicating when the client should retry.
func RespondTooManyRequestsWithRetryAfter(c *gin.Context, retryAfter string, message string) {
	c.Header("Retry-After", retryAfter)
	RespondTooManyRequests(c, message)
}

// RespondTooManyRequestsWithAuthState sends a 429 response while preserving
// the authenticated marker expected by rate-limit clients.
func RespondTooManyRequestsWithAuthState(c *gin.Context, message string, authenticated bool) {
	if message == "" {
		message = "too many requests"
	}
	c.JSON(http.StatusTooManyRequests, struct {
		APIError
		Authenticated bool `json:"authenticated"`
	}{NewError(c, CodeForStatus(http.StatusTooManyRequests), message), authenticated})
}

// RespondBadGateway sends a 502 Bad Gateway response.
// Useful when proxying upstream services.
func RespondBadGateway(c *gin.Context, message string) {
	if message == "" {
		message = "bad gateway"
	}
	respond(c, http.StatusBadGateway, message, "")
}

// RespondServiceUnavailable sends a 503 Service Unavailable response.
// Use this when a required backend service is not available.
func RespondServiceUnavailable(c *gin.Context, service string) {
	respond(c, http.StatusServiceUnavailable, fmt.Sprintf("service unavailable: %s", service), "")
}

// RespondOK sends a 200 OK response with the given data.
func RespondOK(c *gin.Context, data interface{}) {
	c.JSON(http.StatusOK, data)
}

// RespondCreated sends a 201 Created response with the given data.
func RespondCreated(c *gin.Context, data interface{}) {
	c.JSON(http.StatusCreated, data)
}

// RespondNoContent sends a 204 No Content response.
// Use this for successful operations that don't return data.
func RespondNoContent(c *gin.Context) {
	c.Status(http.StatusNoContent)
}

// RespondUnprocessableEntity sends a 422 Unprocessable Entity response.
// Use this when the request body is syntactically correct but semantically invalid.
func RespondUnprocessableEntity(c *gin.Context, message string) {
	respond(c, http.StatusUnprocessableEntity, message, "")
}
