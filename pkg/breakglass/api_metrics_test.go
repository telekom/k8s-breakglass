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

package breakglass

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func init() {
	gin.SetMode(gin.TestMode)
}

func TestInstrumentedHandler_Success(t *testing.T) {
	router := gin.New()

	successHandler := func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	}

	router.GET("/test", instrumentedHandler("test-endpoint", successHandler))

	req := httptest.NewRequest(http.MethodGet, "/test", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
}

func TestInstrumentedHandler_Error(t *testing.T) {
	router := gin.New()

	errorHandler := func(c *gin.Context) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "bad request"})
	}

	router.GET("/test-error", instrumentedHandler("test-error-endpoint", errorHandler))

	req := httptest.NewRequest(http.MethodGet, "/test-error", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusBadRequest, w.Code)
}

func TestInstrumentedHandler_ServerError(t *testing.T) {
	router := gin.New()

	serverErrorHandler := func(c *gin.Context) {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
	}

	router.GET("/test-server-error", instrumentedHandler("test-server-error-endpoint", serverErrorHandler))

	req := httptest.NewRequest(http.MethodGet, "/test-server-error", nil)
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusInternalServerError, w.Code)
}

func TestInstrumentedHandler_PreservesContext(t *testing.T) {
	router := gin.New()

	var capturedHeader string
	handler := func(c *gin.Context) {
		capturedHeader = c.GetHeader("X-Test-Header")
		c.JSON(http.StatusOK, gin.H{"received": capturedHeader})
	}

	router.GET("/test-context", instrumentedHandler("test-context-endpoint", handler))

	req := httptest.NewRequest(http.MethodGet, "/test-context", nil)
	req.Header.Set("X-Test-Header", "test-value")
	w := httptest.NewRecorder()

	router.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code)
	assert.Equal(t, "test-value", capturedHeader)
}

func TestInstrumentedHandler_MultipleEndpoints(t *testing.T) {
	router := gin.New()

	router.GET("/endpoint1", instrumentedHandler("endpoint1", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"endpoint": "1"})
	}))

	router.GET("/endpoint2", instrumentedHandler("endpoint2", func(c *gin.Context) {
		c.JSON(http.StatusOK, gin.H{"endpoint": "2"})
	}))

	// Test endpoint1
	req1 := httptest.NewRequest(http.MethodGet, "/endpoint1", nil)
	w1 := httptest.NewRecorder()
	router.ServeHTTP(w1, req1)
	assert.Equal(t, http.StatusOK, w1.Code)

	// Test endpoint2
	req2 := httptest.NewRequest(http.MethodGet, "/endpoint2", nil)
	w2 := httptest.NewRecorder()
	router.ServeHTTP(w2, req2)
	assert.Equal(t, http.StatusOK, w2.Code)
}
