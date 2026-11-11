// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"
	"time"

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

func TestTerminalRejectionReachesClientWithOpenInput(t *testing.T) {
	server := NewServer(zaptest.NewLogger(t), config.Config{Server: config.Server{ListenAddress: ":8080", AllowedOrigins: []string{"https://test.example.com"}}}, true, &AuthHandler{})
	defer server.Close()
	// A middleware after the body limit rejects without reading the body,
	// as authentication or rate limiting does.
	server.gin.POST("/api/debugSessions/:name/terminal", func(c *gin.Context) {
		c.AbortWithStatus(http.StatusUnauthorized)
	})
	httpServer := httptest.NewServer(server.gin)
	defer httpServer.Close()
	input, inputWriter := io.Pipe()
	defer inputWriter.Close()
	go func() { _, _ = inputWriter.Write([]byte("typed but never ended")) }()
	req, err := http.NewRequest(http.MethodPost, httpServer.URL+"/api/debugSessions/s1/terminal", input)
	require.NoError(t, err)
	type outcome struct {
		status int
		err    error
	}
	done := make(chan outcome, 1)
	go func() {
		response, err := http.DefaultClient.Do(req)
		if err != nil {
			done <- outcome{err: err}
			return
		}
		_ = response.Body.Close()
		done <- outcome{status: response.StatusCode}
	}()
	select {
	case result := <-done:
		require.NoError(t, result.err)
		require.Equal(t, http.StatusUnauthorized, result.status)
	case <-time.After(5 * time.Second):
		_ = inputWriter.CloseWithError(errors.New("test timeout"))
		t.Fatal("the rejection must arrive while the client's input is still open")
	}
}
