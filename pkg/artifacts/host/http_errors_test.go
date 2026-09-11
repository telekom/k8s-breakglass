// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package host

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	artifactapi "github.com/telekom/k8s-breakglass/pkg/artifacts/api"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/backend"
)

func TestArtifactRoutesDistinguishInvalidInputFromProviderFailure(t *testing.T) {
	for _, scenario := range []string{"invalid archive", "ambiguous upload", "download outage"} {
		t.Run(scenario, func(t *testing.T) {
			service, _, store, keys, now, _ := lifecycleFixture(t)
			record, err := service.Reserve(context.Background(), lifecycleRecord(*now))
			require.NoError(t, err)
			route := "/api/debugSessionArtifactUploads/hub/session/" + record.ArtifactID
			signed, err := backend.ReservationToken(keys, record, route, *now, 15*time.Minute)
			require.NoError(t, err)
			body := validLocalArchive(t, record.Expected)
			if scenario == "invalid archive" {
				body = []byte("not an archive")
			}
			if scenario == "ambiguous upload" {
				store.lost = true
				store.inventoryErr = errors.New("private provider unavailable")
			}
			router := gin.New()
			upload, err := artifactapi.NewUploadController(service)
			require.NoError(t, err)
			require.NoError(t, upload.Register(router.Group("/api/"+upload.BasePath())))
			request := httptest.NewRequest(http.MethodPut, route, bytes.NewReader(body))
			request.Header.Set("Authorization", "Bearer "+signed)
			response := httptest.NewRecorder()
			router.ServeHTTP(response, request)
			if scenario == "invalid archive" {
				require.Equal(t, http.StatusBadRequest, response.Code)
				require.Empty(t, response.Body.String())
				return
			}
			if scenario == "ambiguous upload" {
				require.Equal(t, http.StatusServiceUnavailable, response.Code)
				require.Empty(t, response.Body.String())
				return
			}
			require.Equal(t, http.StatusCreated, response.Code, response.Body.String())
			store.inventoryErr = errors.New("private provider unavailable")
			read, err := artifactapi.NewReadController(service, func(*gin.Context, string, string, string) (backend.SessionBinding, error) {
				return backend.SessionBinding{Namespace: "hub", Name: "session", UID: record.SessionUID, TargetClusterUID: record.TargetClusterUID, TargetIdentityDigest: record.TargetIdentityDigest, OperationEpoch: record.OperationEpoch, ConnectionLeaseUID: record.ConnectionLeaseUID}, nil
			})
			require.NoError(t, err)
			require.NoError(t, read.Register(router.Group("/api/"+read.BasePath())))
			response = httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/api/debugSessionArtifacts/hub/session/"+record.ArtifactID, nil))
			require.Equal(t, http.StatusServiceUnavailable, response.Code)
			require.Empty(t, response.Body.String())
		})
	}
}
