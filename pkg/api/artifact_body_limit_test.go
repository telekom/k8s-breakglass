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
	server := NewServer(zap.NewNop(), config.Config{Server: config.Server{AllowedOrigins: []string{"https://test.example"}}, Artifacts: config.Artifacts{UploadMaxBytes: 2 << 20}}, true, nil)
	if err := server.RegisterAll([]APIController{bodyLimitController{}}); err != nil {
		t.Fatal(err)
	}
	body := bytes.NewReader(bytes.Repeat([]byte{'x'}, 1500000))
	request := httptest.NewRequest(http.MethodPut, "/api/debugSessionArtifactUploads/dsa-test", body)
	response := httptest.NewRecorder()
	server.gin.ServeHTTP(response, request)
	if response.Code != http.StatusNoContent {
		t.Fatalf("artifact upload status = %d, want %d", response.Code, http.StatusNoContent)
	}
}
