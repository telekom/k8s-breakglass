package api

import (
	"bytes"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/gin-gonic/gin"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"go.uber.org/zap"
)

type bodyLimitController struct{}

func (bodyLimitController) BasePath() string            { return "debugSessionArtifactUploads" }
func (bodyLimitController) Handlers() []gin.HandlerFunc { return nil }
func (bodyLimitController) Register(group *gin.RouterGroup) error {
	group.PUT("/:artifactID", func(context *gin.Context) {
		if _, err := io.Copy(io.Discard, context.Request.Body); err != nil {
			context.Status(http.StatusRequestEntityTooLarge)
			return
		}
		context.Status(http.StatusNoContent)
	})
	return nil
}

func TestServerArtifactUploadRouteUsesConfiguredStreamingLimit(t *testing.T) {
	for _, tc := range []struct {
		name       string
		configured int64
		size       int
		status     int
	}{
		{"configured exact", 2 << 20, 2 << 20, http.StatusNoContent},
		{"configured over", 2 << 20, (2 << 20) + 1, http.StatusRequestEntityTooLarge},
		{"unset exact fallback", 0, 1 << 20, http.StatusNoContent},
		{"unset over fallback", 0, (1 << 20) + 1, http.StatusRequestEntityTooLarge},
		{"negative fallback", -1, (1 << 20) + 1, http.StatusRequestEntityTooLarge},
		{"oversized fallback", (512 << 20) + 1, (1 << 20) + 1, http.StatusRequestEntityTooLarge},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := NewServer(zap.NewNop(), config.Config{Server: config.Server{AllowedOrigins: []string{"https://test.example"}}, Artifacts: config.Artifacts{UploadMaxBytes: tc.configured}}, true, nil)
			if err := server.RegisterAll([]APIController{bodyLimitController{}}); err != nil {
				t.Fatal(err)
			}
			request := httptest.NewRequest(http.MethodPut, "/api/debugSessionArtifactUploads/dsa-test", bytes.NewReader(bytes.Repeat([]byte{'x'}, tc.size)))
			response := httptest.NewRecorder()
			server.gin.ServeHTTP(response, request)
			if response.Code != tc.status {
				t.Fatalf("artifact upload status = %d, want %d", response.Code, tc.status)
			}
		})
	}
}
