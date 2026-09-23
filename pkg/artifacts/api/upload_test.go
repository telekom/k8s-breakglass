// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
)

func TestUploadBodyLimitReturnsRequestEntityTooLarge(t *testing.T) {
	response := httptest.NewRecorder()
	context, _ := gin.CreateTestContext(response)
	body := http.MaxBytesReader(response, io.NopCloser(strings.NewReader("oversized")), 4)
	defer func() { require.NoError(t, body.Close()) }()
	_, err := io.ReadAll(body)
	require.Error(t, err)
	writeUploadError(context, fmt.Errorf("stage artifact: %w", err))
	context.Writer.WriteHeaderNow()
	require.Equal(t, http.StatusRequestEntityTooLarge, response.Code)
}

func TestBearerTokenRequiresExactlyOneBearerCredential(t *testing.T) {
	for name, header := range map[string]string{
		"empty":         "",
		"wrong scheme":  "Basic abc",
		"missing value": "Bearer",
		"extra value":   "Bearer one two",
	} {
		t.Run(name, func(t *testing.T) {
			if got := bearerToken(header); got != "" {
				t.Fatalf("bearerToken(%q) = %q, want empty", header, got)
			}
		})
	}
	if got := bearerToken("bearer token-value"); got != "token-value" {
		t.Fatalf("bearerToken() = %q, want token-value", got)
	}
}
