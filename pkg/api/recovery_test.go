// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package api

import (
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

	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("status %d, want 500", rec.Code)
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
