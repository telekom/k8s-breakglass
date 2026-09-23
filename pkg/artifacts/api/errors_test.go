// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/backend"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/storage"
)

func TestArtifactHTTPErrorClassification(t *testing.T) {
	for name, write := range map[string]func(*gin.Context, error){"read": writeReadError, "upload": writeUploadError} {
		t.Run(name, func(t *testing.T) {
			for _, tc := range []struct {
				err    error
				status int
			}{
				{backend.ErrInvalid, http.StatusBadRequest}, {backend.ErrForbidden, http.StatusNotFound},
				{backend.ErrExpired, http.StatusGone}, {backend.ErrConflict, http.StatusConflict},
				{storage.ErrAmbiguous, http.StatusServiceUnavailable}, {context.DeadlineExceeded, http.StatusServiceUnavailable},
				{errors.New("provider unavailable: private endpoint"), http.StatusServiceUnavailable},
			} {
				response := httptest.NewRecorder()
				ctx, _ := gin.CreateTestContext(response)
				write(ctx, fmt.Errorf("wrapped: %w", tc.err))
				ctx.Writer.WriteHeaderNow()
				require.Equal(t, tc.status, response.Code)
				require.Empty(t, response.Body.String())
			}
		})
	}
}
