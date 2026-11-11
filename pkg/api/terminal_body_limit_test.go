// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"go.uber.org/zap/zaptest"
)

func TestTerminalStreamBodyIsNotLimitedLikeJSON(t *testing.T) {
	server := NewServer(zaptest.NewLogger(t), config.Config{Server: config.Server{ListenAddress: ":8080", AllowedOrigins: []string{"https://test.example.com"}}}, true, &AuthHandler{})
	defer server.Close()
	read := func(c *gin.Context) {
		n, err := io.Copy(io.Discard, c.Request.Body)
		if err != nil {
			c.String(http.StatusRequestEntityTooLarge, "%d", n)
			return
		}
		c.String(http.StatusOK, "%d", n)
	}
	server.gin.POST("/api/debugSessions/:name/terminal", read)
	server.gin.POST("/api/debugSessions/:name/join", read)
	body := bytes.Repeat([]byte("x"), 2<<20) // 64 full 32 KiB stdin frames
	for path, want := range map[string]int{
		"/api/debugSessions/s1/terminal": http.StatusOK,
		"/api/debugSessions/s1/join":     http.StatusRequestEntityTooLarge,
	} {
		w := httptest.NewRecorder()
		server.gin.ServeHTTP(w, httptest.NewRequest(http.MethodPost, path, bytes.NewReader(body)))
		require.Equal(t, want, w.Code, path)
		if want == http.StatusOK {
			require.Equal(t, strconv.Itoa(len(body)), w.Body.String())
		}
	}
	require.False(t, isTerminalStreamRequest(httptest.NewRequest(http.MethodPost, "/api/debugSessions/s1/terminal/x", nil)))
	require.False(t, isTerminalStreamRequest(httptest.NewRequest(http.MethodGet, "/api/debugSessions/s1/terminal", nil)))
}
