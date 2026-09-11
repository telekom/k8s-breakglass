// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

// Package api exposes the collector-only artifact upload endpoint. Human
// metadata and downloads are intentionally separate routes so a collector
// token cannot be reused as a reader credential.
package api

import (
	"errors"
	"net/http"
	"strings"

	"github.com/gin-gonic/gin"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/backend"
)

// UploadController registers the canonical one-time upload route. The route
// is authenticated by the signed token in the Authorization header; no
// provider endpoint or credential is accepted from the request.
type UploadController struct {
	service *backend.Service
}

func NewUploadController(service *backend.Service) (*UploadController, error) {
	if service == nil {
		return nil, errors.New("artifact upload service is required")
	}
	return &UploadController{service: service}, nil
}

func (controller *UploadController) BasePath() string { return "debugSessionArtifactUploads" }

func (controller *UploadController) Handlers() []gin.HandlerFunc { return nil }

func (controller *UploadController) Register(group *gin.RouterGroup) error {
	group.PUT("/:namespace/:session/:artifactID", controller.handleUpload)
	return nil
}

func (controller *UploadController) handleUpload(context *gin.Context) {
	token := bearerToken(context.GetHeader("Authorization"))
	if token == "" {
		context.Status(http.StatusNotFound)
		return
	}
	route := "/api/" + controller.BasePath() + "/" + context.Param("namespace") + "/" + context.Param("session") + "/" + context.Param("artifactID")
	result, err := controller.service.Upload(context.Request.Context(), token, route, context.Request.Body)
	if err != nil {
		writeUploadError(context, err)
		return
	}
	context.JSON(http.StatusCreated, result)
}

func bearerToken(header string) string {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") {
		return ""
	}
	return parts[1]
}

func writeUploadError(context *gin.Context, err error) {
	switch {
	case errors.Is(err, backend.ErrForbidden):
		// Do not disclose whether the session or artifact exists.
		context.Status(http.StatusNotFound)
	case errors.Is(err, backend.ErrExpired):
		context.Status(http.StatusGone)
	case errors.Is(err, backend.ErrReplay), errors.Is(err, backend.ErrConflict):
		context.Status(http.StatusConflict)
	case errors.Is(err, backend.ErrInvalid):
		context.Status(http.StatusBadRequest)
	default:
		context.Status(http.StatusServiceUnavailable)
	}
}

var _ interface {
	BasePath() string
	Register(*gin.RouterGroup) error
	Handlers() []gin.HandlerFunc
} = (*UploadController)(nil)
