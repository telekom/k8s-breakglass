// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

// Package api exposes authenticated artifact metadata and download routes.
// The binding resolver is supplied by the host API so this package cannot
// invent a session identity or bypass the live-session authorizer.
package api

import (
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/backend"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/storage"
)

// BindingResolver resolves the live session identity used by every metadata
// and byte request. It receives the authenticated Gin context so the resolver
// can apply the same issuer/subject/group checks as the debug-session API.
// Implementations must fail closed for stale or revoked sessions and must not
// read an identity from request-controlled fields.
type BindingResolver func(*gin.Context, string, string, string) (backend.SessionBinding, error)

// ReadController registers the authenticated artifact metadata and download
// API. It has no storage-provider configuration or URL surface.
type ReadController struct {
	service  *backend.Service
	resolve  BindingResolver
	handlers []gin.HandlerFunc
}

func NewReadController(service *backend.Service, resolve BindingResolver, handlers ...gin.HandlerFunc) (*ReadController, error) {
	if service == nil || resolve == nil {
		return nil, errors.New("artifact read service and binding resolver are required")
	}
	return &ReadController{service: service, resolve: resolve, handlers: handlers}, nil
}

func (controller *ReadController) BasePath() string { return "debugSessionArtifacts" }

func (controller *ReadController) Handlers() []gin.HandlerFunc { return controller.handlers }

func (controller *ReadController) Register(group *gin.RouterGroup) error {
	group.GET("/:namespace/:session", controller.handleList)
	group.GET("/:namespace/:session/:artifactID", controller.handleDownload)
	return nil
}

func (controller *ReadController) handleList(context *gin.Context) {
	binding, err := controller.resolve(context, context.Param("namespace"), context.Param("session"), "")
	if err != nil {
		context.Status(http.StatusNotFound)
		return
	}
	records, err := controller.service.ListAuthorized(context.Request.Context(), context.Param("namespace"), context.Param("session"), binding.UID, func() error {
		current, err := controller.resolve(context, context.Param("namespace"), context.Param("session"), "")
		if err != nil || current.UID != binding.UID {
			return backend.ErrForbidden
		}
		return nil
	})
	if err != nil {
		writeReadError(context, err)
		return
	}
	context.JSON(http.StatusOK, records)
}

func (controller *ReadController) handleDownload(context *gin.Context) {
	namespace, session, artifactID := context.Param("namespace"), context.Param("session"), context.Param("artifactID")
	binding, err := controller.resolve(context, namespace, session, artifactID)
	if err != nil {
		context.Status(http.StatusNotFound)
		return
	}
	reader, public, err := controller.service.Download(context.Request.Context(), namespace, session, artifactID, binding)
	if err != nil {
		writeReadError(context, err)
		return
	}
	defer func() { _ = reader.Close() }()
	context.Header("Content-Type", "application/gzip")
	context.Header("Content-Disposition", fmt.Sprintf("attachment; filename=%q", public.ArtifactID+".tar.gz"))
	if public.Size > 0 {
		context.Header("Content-Length", strconv.FormatInt(public.Size, 10))
	}
	context.Status(http.StatusOK)
	if _, err := io.Copy(context.Writer, &requestAuthorizedReader{reader: reader, authorize: func() error {
		current, err := controller.resolve(context, namespace, session, artifactID)
		if err != nil || current != binding {
			return backend.ErrForbidden
		}
		return nil
	}}); err != nil {
		return
	}
}

func writeReadError(context *gin.Context, err error) {
	switch {
	case errors.Is(err, backend.ErrForbidden), errors.Is(err, storage.ErrNotFound):
		context.Status(http.StatusNotFound)
	case errors.Is(err, backend.ErrExpired):
		context.Status(http.StatusGone)
	case errors.Is(err, backend.ErrConflict), errors.Is(err, storage.ErrConflict):
		context.Status(http.StatusConflict)
	default:
		context.Status(http.StatusBadRequest)
	}
}

var _ interface {
	BasePath() string
	Register(*gin.RouterGroup) error
	Handlers() []gin.HandlerFunc
} = (*ReadController)(nil)

// requestAuthorizedReader keeps the caller's participant authorization live while streaming.
type requestAuthorizedReader struct {
	reader    io.Reader
	authorize func() error
}

func (reader *requestAuthorizedReader) Read(buffer []byte) (int, error) {
	if err := reader.authorize(); err != nil {
		return 0, err
	}
	n, err := reader.reader.Read(buffer)
	if authErr := reader.authorize(); authErr != nil {
		clear(buffer[:n])
		return 0, authErr
	}
	return n, err
}
