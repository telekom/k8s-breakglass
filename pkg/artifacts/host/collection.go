// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package host

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/archive"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/backend"
	artifactcontroller "github.com/telekom/k8s-breakglass/pkg/artifacts/controller"
	"github.com/telekom/k8s-breakglass/pkg/breakglass/debug"
	corev1 "k8s.io/api/core/v1"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

type collectionController struct {
	service  *backend.Service
	debug    *debug.DebugSessionAPIController
	provider artifactcontroller.TargetClientProvider
	maximum  int64
}
type collectionRequest struct {
	Recipe        string `json:"recipe"`
	PodNamespace  string `json:"podNamespace"`
	PodName       string `json:"podName"`
	DetailLevel   string `json:"detailLevel,omitempty"`
	MaxAgeMinutes int64  `json:"maxAgeMinutes,omitempty"`
}

func (c *collectionController) BasePath() string            { return "debugSessionArtifacts" }
func (c *collectionController) Handlers() []gin.HandlerFunc { return nil }
func (c *collectionController) Register(group *gin.RouterGroup) error {
	group.POST("/:namespace/:session", c.create)
	return nil
}
func (c *collectionController) create(ctx *gin.Context) {
	var request collectionRequest
	decoder := json.NewDecoder(io.LimitReader(ctx.Request.Body, 4097))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&request); err != nil {
		ctx.Status(http.StatusBadRequest)
		return
	}
	var extra any
	if decoder.Decode(&extra) != io.EOF {
		ctx.Status(http.StatusBadRequest)
		return
	}
	session, err := c.debug.AuthorizeArtifactCollection(ctx, ctx.Param("namespace"), ctx.Param("session"))
	if err != nil {
		ctx.Status(http.StatusForbidden)
		return
	}
	if session.Status.ResolvedTemplate == nil || session.Status.ResolvedTemplate.ArtifactCollection == nil || !slices.Contains(session.Status.ResolvedTemplate.ArtifactCollection.AllowedRecipes, request.Recipe) || session.Status.ConnectionLease == nil || session.Status.ConnectionLease.Epoch < 1 {
		ctx.Status(http.StatusForbidden)
		return
	}
	var podUID string
	for _, pod := range session.Status.AllowedPods {
		if pod.Namespace == request.PodNamespace && pod.Name == request.PodName {
			podUID = pod.UID
			break
		}
	}
	if podUID == "" {
		ctx.Status(http.StatusForbidden)
		return
	}
	target, config, err := c.provider.GetClientForPrivilegedOperation(ctx.Request.Context(), session.Spec.Cluster)
	if err != nil {
		ctx.Status(http.StatusServiceUnavailable)
		return
	}
	defer c.provider.ReleasePrivilegedOperationClusterConfig(config)
	var pod corev1.Pod
	if err := target.Get(ctx.Request.Context(), ctrlclient.ObjectKey{Namespace: request.PodNamespace, Name: request.PodName}, &pod); err != nil || string(pod.UID) != podUID || !pod.DeletionTimestamp.IsZero() {
		ctx.Status(http.StatusForbidden)
		return
	}
	record := backend.Record{ConnectionLeaseUID: string(session.Status.ConnectionLease.UID), Namespace: session.Namespace, SessionName: session.Name, SessionUID: string(session.UID), TargetClusterUID: string(config.UID), TargetPodNamespace: pod.Namespace, TargetPodName: pod.Name, TargetPodUID: string(pod.UID), Recipe: request.Recipe, RecipeVersion: 1, OperationEpoch: uint64(session.Status.ConnectionLease.Epoch), ExpiresAt: session.Status.ExpiresAt.Time, MaxBytes: c.maximum}
	if session.Status.ConnectionLease.TargetUID != config.UID {
		ctx.Status(http.StatusForbidden)
		return
	}
	record.Expected = archive.Expected{Recipe: request.Recipe, RecipeVersion: 1, SessionNamespace: session.Namespace, SessionName: session.Name, SessionUID: string(session.UID), RedactionProfile: "credential-text.v1", RedactionVersion: 1}
	switch request.Recipe {
	case archive.SystemSummaryRecipe:
		if request.MaxAgeMinutes != 0 {
			ctx.Status(http.StatusBadRequest)
			return
		}
		if request.DetailLevel == "" {
			request.DetailLevel = "basic"
		}
		if request.DetailLevel != "basic" && request.DetailLevel != "extended" {
			ctx.Status(http.StatusBadRequest)
			return
		}
		record.MaxBytes = min(record.MaxBytes, int64(archive.MaxSystemSummaryArchiveBytes))
		record.Expected.Inputs.DetailLevel = &request.DetailLevel
	case archive.CrashdumpCollectionRecipe:
		if request.DetailLevel != "" || pod.Spec.NodeName == "" {
			ctx.Status(http.StatusBadRequest)
			return
		}
		if request.MaxAgeMinutes == 0 {
			request.MaxAgeMinutes = 60
		}
		if request.MaxAgeMinutes < 1 || request.MaxAgeMinutes > 10080 {
			ctx.Status(http.StatusBadRequest)
			return
		}
		var node corev1.Node
		if err := target.Get(ctx.Request.Context(), ctrlclient.ObjectKey{Name: pod.Spec.NodeName}, &node); err != nil || node.UID == "" || !node.DeletionTimestamp.IsZero() {
			ctx.Status(http.StatusForbidden)
			return
		}
		record.Expected.Node = &pod.Spec.NodeName
		record.Expected.Inputs.Node = &pod.Spec.NodeName
		record.Expected.Inputs.MaxAgeMinutes = &request.MaxAgeMinutes
		podUID += "/" + string(node.UID)
		record.TargetNodeUID = string(node.UID)
	default:
		ctx.Status(http.StatusForbidden)
		return
	}
	record.Expected.Inputs.MaxArchiveBytes = record.MaxBytes
	record.TargetIdentityDigest = opaqueDigest(string(config.UID) + "/" + podUID)
	profile, err := debug.ProfileDigestForSession(session)
	if err != nil {
		ctx.Status(http.StatusForbidden)
		return
	}
	record.RuntimeBindingDigest = opaqueDigest(profile + "/" + record.TargetIdentityDigest + "/" + record.ConnectionLeaseUID)
	plan, _ := json.Marshal(struct {
		Recipe  string
		Inputs  archive.Inputs
		Profile string
	}{request.Recipe, record.Expected.Inputs, profile})
	record.PlanDigest = opaqueDigest(string(plan))
	if err := c.provider.ValidatePrivilegedOperationClusterConfig(ctx.Request.Context(), config); err != nil {
		ctx.Status(http.StatusForbidden)
		return
	}
	final, err := c.debug.AuthorizeArtifactCollection(ctx, session.Namespace, session.Name)
	if err != nil || final.UID != session.UID || final.ResourceVersion != session.ResourceVersion || !time.Now().Before(record.ExpiresAt) {
		ctx.Status(http.StatusForbidden)
		return
	}
	reserved, err := c.service.Reserve(ctx.Request.Context(), record)
	if err != nil {
		if errors.Is(err, backend.ErrConflict) {
			ctx.Status(http.StatusConflict)
		} else {
			ctx.Status(http.StatusForbidden)
		}
		return
	}
	ctx.JSON(http.StatusCreated, c.service.Public(reserved))
}
func opaqueDigest(value string) string {
	sum := sha256.Sum256([]byte(value))
	return hex.EncodeToString(sum[:])
}
