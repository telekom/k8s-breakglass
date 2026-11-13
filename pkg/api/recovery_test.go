// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"
)

func TestRecoverPanicsDoesNotLogCredentials(t *testing.T) {
	gin.SetMode(gin.TestMode)
	core, logs := observer.New(zapcore.DebugLevel)
	engine := gin.New()
	engine.Use(recoverPanics(zap.New(core)))
	engine.GET("/boom/:name", func(*gin.Context) { panic("kaboom") })

	req := httptest.NewRequest(http.MethodGet, "/boom/x?token=query-secret", nil)
	req.Header.Set("Authorization", "Bearer header-secret")
	req.Header.Set("Cookie", "session=cookie-secret")
	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, req)

	if rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), `"cid"`) {
		t.Fatalf("status %d body %s, want 500 with the standard error body", rec.Code, rec.Body.String())
	}
	entries := logs.AllUntimed()
	if len(entries) != 1 {
		t.Fatalf("got %d log entries, want 1", len(entries))
	}
	e := entries[0]
	fields := e.ContextMap()
	if e.Level != zapcore.ErrorLevel || e.Message != "[Recovery from panic]" || fields["error"] != "kaboom" || fields["path"] != "/boom/:name" || fields["method"] != http.MethodGet {
		t.Fatalf("unexpected entry: %s %q %v", e.Level, e.Message, fields)
	}
	for k, v := range fields {
		if s, _ := v.(string); strings.Contains(s, "secret") {
			t.Errorf("field %s leaks a credential: %q", k, s)
		}
	}
}

func TestRecoverPanicsAfterFlushKeepsTheStream(t *testing.T) {
	gin.SetMode(gin.TestMode)
	core, logs := observer.New(zapcore.DebugLevel)
	engine := gin.New()
	engine.Use(recoverPanics(zap.New(core)))
	engine.GET("/stream", func(c *gin.Context) {
		c.String(http.StatusOK, "partial")
		c.Writer.Flush()
		panic("kaboom")
	})

	rec := httptest.NewRecorder()
	engine.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/stream", nil))

	if rec.Code != http.StatusOK || rec.Body.String() != "partial" {
		t.Fatalf("status %d body %q, want the flushed 200 \"partial\" unchanged", rec.Code, rec.Body.String())
	}
	if logs.FilterMessage("[Recovery from panic]").Len() != 1 {
		t.Fatalf("panic not logged: %v", logs.AllUntimed())
	}
}

func TestAccessLogNeverLogsQueryAndCoversPanics(t *testing.T) {
	gin.SetMode(gin.TestMode)
	core, logs := observer.New(zapcore.DebugLevel)
	log := zap.New(core)
	engine := gin.New()
	engine.Use(accessLog(log), recoverPanics(log))
	engine.GET("/auth/callback", func(c *gin.Context) { c.Status(http.StatusOK) })
	engine.GET("/api/breakglassSessions/status", func(c *gin.Context) { c.Status(http.StatusOK) })
	engine.GET("/boom", func(*gin.Context) { panic("kaboom") })

	for _, target := range []string{
		"/auth/callback?code=secret-code&state=secret-state",
		"/api/breakglassSessions/status?token=secret-token",
		"/not-a-route?code=secret-code",
		"/boom?token=secret-token",
	} {
		engine.ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, target, nil))
	}

	lines := logs.FilterMessage("http_request").AllUntimed()
	if len(lines) != 4 {
		t.Fatalf("got %d http_request lines, want 4", len(lines))
	}
	wantPaths := []string{"/auth/callback", "/api/breakglassSessions/status", "/not-a-route", "/boom"}
	for i, e := range lines {
		if got := e.ContextMap()["path"]; got != wantPaths[i] {
			t.Errorf("line %d path %v, want %s", i, got, wantPaths[i])
		}
	}
	if got := lines[3].ContextMap()["status"]; got != int64(http.StatusInternalServerError) {
		t.Errorf("panicking request logged with status %v, want 500", got)
	}
	for _, e := range logs.AllUntimed() {
		if strings.Contains(e.Message, "secret") {
			t.Errorf("message leaks a secret: %q", e.Message)
		}
		for k, v := range e.ContextMap() {
			if strings.Contains(fmt.Sprint(v), "secret") {
				t.Errorf("%s: field %s leaks a secret: %v", e.Message, k, v)
			}
		}
	}
}
