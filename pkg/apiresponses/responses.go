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
	"go.uber.org/zap"
)

// APIError represents a standardized error response.
// This ensures consistent error message formatting across all API endpoints.
type APIError struct {
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
	Details string `json:"details,omitempty"`
}

// RespondNotFound sends a 404 Not Found response with a standardized message.
// Use this when a requested resource does not exist.
func RespondNotFound(c *gin.Context, resourceType, resourceName string) {
	c.JSON(http.StatusNotFound, APIError{
		Error: fmt.Sprintf("%s not found: %s", resourceType, resourceName),
		Code:  "NOT_FOUND",
	})
}

// RespondNotFoundSimple sends a 404 Not Found response with a simple message.
func RespondNotFoundSimple(c *gin.Context, message string) {
	c.JSON(http.StatusNotFound, APIError{
		Error: message,
		Code:  "NOT_FOUND",
	})
}

// RespondUnauthorized sends a 401 Unauthorized response.
// Use this when authentication is missing or invalid.
func RespondUnauthorized(c *gin.Context) {
	c.JSON(http.StatusUnauthorized, APIError{
		Error: "user not authenticated",
		Code:  "UNAUTHORIZED",
	})
}

// RespondUnauthorizedWithMessage sends a 401 Unauthorized response with a custom message.
func RespondUnauthorizedWithMessage(c *gin.Context, message string) {
	if message == "" {
		message = "user not authenticated"
	}
	c.JSON(http.StatusUnauthorized, APIError{
		Error: message,
		Code:  "UNAUTHORIZED",
	})
}

// RespondForbidden sends a 403 Forbidden response with an optional reason.
// Use this when the user is authenticated but not authorized for the action.
func RespondForbidden(c *gin.Context, reason string) {
	if reason == "" {
		reason = "access denied"
	}
	c.JSON(http.StatusForbidden, APIError{
		Error: reason,
		Code:  "FORBIDDEN",
	})
}

// RespondBadRequest sends a 400 Bad Request response.
// Use this for client errors like malformed JSON or invalid parameters.
func RespondBadRequest(c *gin.Context, message string) {
	c.JSON(http.StatusBadRequest, APIError{
		Error: message,
		Code:  "BAD_REQUEST",
	})
}

// RespondBadRequestWithDetails sends a 400 Bad Request with additional details.
func RespondBadRequestWithDetails(c *gin.Context, message, details string) {
	c.JSON(http.StatusBadRequest, APIError{
		Error:   message,
		Code:    "BAD_REQUEST",
		Details: details,
	})
}

// RespondConflict sends a 409 Conflict response.
// Use this when the request conflicts with current state (e.g., already approved).
func RespondConflict(c *gin.Context, message string) {
	c.JSON(http.StatusConflict, APIError{
		Error: message,
		Code:  "CONFLICT",
	})
}

// RespondInternalError sends a 500 Internal Server Error response.
// It logs the error with full details but returns a sanitized message to the client.
func RespondInternalError(c *gin.Context, operation string, err error, log *zap.SugaredLogger) {
	if log != nil {
		log.Errorw(fmt.Sprintf("Failed to %s", operation), "error", err)
	}
	c.JSON(http.StatusInternalServerError, APIError{
		Error: fmt.Sprintf("failed to %s", operation),
		Code:  "INTERNAL_ERROR",
	})
}

// RespondInternalErrorSimple sends a 500 response with a simple message.
// Use this when you've already logged the error or don't need detailed logging.
func RespondInternalErrorSimple(c *gin.Context, message string) {
	c.JSON(http.StatusInternalServerError, APIError{
		Error: message,
		Code:  "INTERNAL_ERROR",
	})
}

// RespondBadGateway sends a 502 Bad Gateway response.
// Useful when proxying upstream services.
func RespondBadGateway(c *gin.Context, message string) {
	if message == "" {
		message = "bad gateway"
	}
	c.JSON(http.StatusBadGateway, APIError{
		Error: message,
		Code:  "BAD_GATEWAY",
	})
}

// RespondServiceUnavailable sends a 503 Service Unavailable response.
// Use this when a required backend service is not available.
func RespondServiceUnavailable(c *gin.Context, service string) {
	c.JSON(http.StatusServiceUnavailable, APIError{
		Error: fmt.Sprintf("service unavailable: %s", service),
		Code:  "SERVICE_UNAVAILABLE",
	})
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
	c.JSON(http.StatusUnprocessableEntity, APIError{
		Error: message,
		Code:  "UNPROCESSABLE_ENTITY",
	})
}
