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

package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestRespondNotFound(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	RespondNotFound(c, "session", "my-session")

	assert.Equal(t, http.StatusNotFound, w.Code)

	var resp APIError
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "session not found: my-session", resp.Error)
	assert.Equal(t, "NOT_FOUND", resp.Code)
}

func TestRespondNotFoundSimple(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	RespondNotFoundSimple(c, "custom message")

	assert.Equal(t, http.StatusNotFound, w.Code)

	var resp APIError
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "custom message", resp.Error)
	assert.Equal(t, "NOT_FOUND", resp.Code)
}

func TestRespondUnauthorized(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	RespondUnauthorized(c)

	assert.Equal(t, http.StatusUnauthorized, w.Code)

	var resp APIError
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "user not authenticated", resp.Error)
	assert.Equal(t, "UNAUTHORIZED", resp.Code)
}

func TestRespondForbidden(t *testing.T) {
	tests := []struct {
		name     string
		reason   string
		expected string
	}{
		{
			name:     "with custom reason",
			reason:   "not an approver",
			expected: "not an approver",
		},
		{
			name:     "with empty reason",
			reason:   "",
			expected: "access denied",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			c, _ := gin.CreateTestContext(w)

			RespondForbidden(c, tt.reason)

			assert.Equal(t, http.StatusForbidden, w.Code)

			var resp APIError
			err := json.Unmarshal(w.Body.Bytes(), &resp)
			require.NoError(t, err)
			assert.Equal(t, tt.expected, resp.Error)
			assert.Equal(t, "FORBIDDEN", resp.Code)
		})
	}
}

func TestRespondBadRequest(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	RespondBadRequest(c, "invalid duration format")

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp APIError
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "invalid duration format", resp.Error)
	assert.Equal(t, "BAD_REQUEST", resp.Code)
}

func TestRespondBadRequestWithDetails(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	RespondBadRequestWithDetails(c, "validation failed", "field 'duration' must be positive")

	assert.Equal(t, http.StatusBadRequest, w.Code)

	var resp APIError
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "validation failed", resp.Error)
	assert.Equal(t, "BAD_REQUEST", resp.Code)
	assert.Equal(t, "field 'duration' must be positive", resp.Details)
}

func TestRespondConflict(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	RespondConflict(c, "session already approved")

	assert.Equal(t, http.StatusConflict, w.Code)

	var resp APIError
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "session already approved", resp.Error)
	assert.Equal(t, "CONFLICT", resp.Code)
}

func TestRespondInternalError(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	log := zap.NewNop().Sugar()
	testErr := errors.New("database connection failed")

	RespondInternalError(c, "update session status", testErr, log)

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var resp APIError
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "failed to update session status", resp.Error)
	assert.Equal(t, "INTERNAL_ERROR", resp.Code)
}

func TestRespondInternalErrorNilLogger(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	testErr := errors.New("some error")

	// Should not panic with nil logger
	RespondInternalError(c, "do something", testErr, nil)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestRespondInternalErrorSimple(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	RespondInternalErrorSimple(c, "unexpected error")

	assert.Equal(t, http.StatusInternalServerError, w.Code)

	var resp APIError
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "unexpected error", resp.Error)
	assert.Equal(t, "INTERNAL_ERROR", resp.Code)
}

func TestRespondServiceUnavailable(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	RespondServiceUnavailable(c, "identity provider")

	assert.Equal(t, http.StatusServiceUnavailable, w.Code)

	var resp APIError
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "service unavailable: identity provider", resp.Error)
	assert.Equal(t, "SERVICE_UNAVAILABLE", resp.Code)
}

func TestRespondOK(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	data := map[string]string{"status": "healthy"}
	RespondOK(c, data)

	assert.Equal(t, http.StatusOK, w.Code)

	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "healthy", resp["status"])
}

func TestRespondCreated(t *testing.T) {
	w := httptest.NewRecorder()
	c, _ := gin.CreateTestContext(w)

	data := map[string]string{"name": "new-session"}
	RespondCreated(c, data)

	assert.Equal(t, http.StatusCreated, w.Code)

	var resp map[string]string
	err := json.Unmarshal(w.Body.Bytes(), &resp)
	require.NoError(t, err)
	assert.Equal(t, "new-session", resp["name"])
}

func TestRespondNoContent(t *testing.T) {
	// Create a router to properly handle the status
	router := gin.New()
	router.GET("/test", func(c *gin.Context) {
		RespondNoContent(c)
	})

	w := httptest.NewRecorder()
	req, _ := http.NewRequest(http.MethodGet, "/test", nil)
	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusNoContent, w.Code)
	assert.Empty(t, w.Body.Bytes())
}
