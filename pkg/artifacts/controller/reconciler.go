// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

// Package controller reconciles durable artifact records and their fixed
// collector Jobs. Provider operations remain in backend.Service.
package controller

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.uber.org/zap"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/archive"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/backend"
	artifactjob "github.com/telekom/k8s-breakglass/pkg/artifacts/job"
	artifactkube "github.com/telekom/k8s-breakglass/pkg/artifacts/kube"
)

// UploadTokenIssuer issues a token whose claims are bound to the immutable
// record. The implementation owns the verifier keyring and JTI/epoch policy.
type UploadTokenIssuer interface {
	IssueUploadToken(context.Context, backend.Record, string) (string, error)
}

type Reconciler struct {
	ctrlclient.Client
	Service       *backend.Service
	TokenIssuer   UploadTokenIssuer
	Image         string
	ControllerURL string
	Log           *zap.SugaredLogger
	Now           func() time.Time
}

func (reconciler *Reconciler) SetupWithManager(manager ctrl.Manager) error {
	if reconciler.Client == nil || reconciler.Service == nil || reconciler.TokenIssuer == nil {
		return errors.New("artifact reconciler client, backend service, and token issuer are required")
	}
	return ctrl.NewControllerManagedBy(manager).For(&breakglassv1alpha1.DebugSessionArtifact{}).Owns(&batchv1.Job{}).Complete(reconciler)
}

func (reconciler *Reconciler) Reconcile(ctx context.Context, request ctrl.Request) (ctrl.Result, error) {
	var object breakglassv1alpha1.DebugSessionArtifact
	if err := reconciler.Get(ctx, request.NamespacedName, &object); err != nil {
		return ctrl.Result{}, ctrlclient.IgnoreNotFound(err)
	}
	record := artifactkube.Record(&object)
	now := time.Now
	if reconciler.Now != nil {
		now = reconciler.Now
	}
	if record.State == backend.StateAvailable && !record.ExpiresAt.IsZero() && !now().Before(record.ExpiresAt) {
		if err := reconciler.Service.Cleanup(ctx, record, backend.StateExpired); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	if record.State == backend.StateDeleting || record.State == backend.StateUnknown {
		if err := reconciler.Service.Cleanup(ctx, record, backend.StateDeleted); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{}, nil
	}
	if record.State == backend.StatePending || record.State == backend.StateUploading {
		if err := reconciler.ensureUploadResources(ctx, object, record); err != nil {
			return ctrl.Result{}, err
		}
	}
	return ctrl.Result{}, nil
}

func (reconciler *Reconciler) ensureUploadResources(ctx context.Context, object breakglassv1alpha1.DebugSessionArtifact, record backend.Record) error {
	if reconciler.Image == "" || reconciler.ControllerURL == "" {
		return errors.New("artifact reconciler image and controller URL are required")
	}
	secretName := object.Spec.ArtifactID + "-upload"
	route := "/api/debugSessionArtifactUploads/" + object.Spec.SessionRef.Namespace + "/" + object.Spec.SessionRef.Name + "/" + object.Spec.ArtifactID
	var secret corev1.Secret
	secretKey := types.NamespacedName{Namespace: object.Namespace, Name: secretName}
	err := reconciler.Get(ctx, secretKey, &secret)
	if apierrors.IsNotFound(err) {
		token, issueErr := reconciler.TokenIssuer.IssueUploadToken(ctx, record, route)
		if issueErr != nil {
			return fmt.Errorf("issue diagnostic artifact upload token: %w", issueErr)
		}
		controller := true
		blockOwnerDeletion := true
		secret = corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: object.Namespace, Labels: map[string]string{"breakglass.t-caas.telekom.com/artifact": object.Spec.ArtifactID}, OwnerReferences: []metav1.OwnerReference{{APIVersion: breakglassv1alpha1.GroupVersion.String(), Kind: "DebugSessionArtifact", Name: object.Name, UID: object.UID, Controller: &controller, BlockOwnerDeletion: &blockOwnerDeletion}}}, Type: corev1.SecretTypeOpaque, Immutable: boolPtr(true), Data: map[string][]byte{"token": []byte(token)}}
		if createErr := reconciler.Create(ctx, &secret); createErr != nil {
			if !apierrors.IsAlreadyExists(createErr) {
				return fmt.Errorf("create diagnostic artifact upload token Secret: %w", createErr)
			}
			if getErr := reconciler.Get(ctx, secretKey, &secret); getErr != nil {
				return fmt.Errorf("get concurrently created diagnostic artifact upload token Secret: %w", getErr)
			}
		}
	} else if err != nil {
		return fmt.Errorf("get diagnostic artifact upload token Secret: %w", err)
	}
	if err := validateTokenSecret(secret, object); err != nil {
		return err
	}
	jobName := object.Spec.ArtifactID + "-collect"
	var existing batchv1.Job
	if err := reconciler.Get(ctx, types.NamespacedName{Namespace: object.Namespace, Name: jobName}, &existing); err == nil {
		if err := validateCollectorJob(existing, object); err != nil {
			return err
		}
		return nil
	} else if !apierrors.IsNotFound(err) {
		return fmt.Errorf("get diagnostic artifact collector Job: %w", err)
	}
	config := artifactjob.Config{Namespace: object.Namespace, Name: jobName, ArtifactID: object.Spec.ArtifactID, ArtifactName: object.Name, ArtifactUID: string(object.UID), SessionNamespace: object.Spec.SessionRef.Namespace, SessionName: object.Spec.SessionRef.Name, SessionUID: object.Spec.SessionRef.UID, Recipe: object.Spec.Recipe, RecipeVersion: int(object.Spec.RecipeVersion), PlanDigest: object.Spec.PlanDigest, RuntimeBindingDigest: object.Spec.RuntimeBindingDigest, RedactionProfile: object.Spec.RedactionProfile, RedactionVersion: int(object.Spec.RedactionVersion), UploadURL: strings.TrimSuffix(reconciler.ControllerURL, "/") + route, UploadTokenSecretName: secretName, Image: reconciler.Image, Node: valueOrEmpty(object.Spec.Node), MaxBytes: object.Spec.MaxBytes, TimeoutSeconds: object.Spec.TimeoutSeconds, DetailLevel: valueOrEmpty(object.Spec.Inputs.DetailLevel), MaxAgeMinutes: valueOrZero(object.Spec.Inputs.MaxAgeMinutes)}
	collectorJob, err := artifactjob.Build(config)
	if err != nil {
		return fmt.Errorf("build diagnostic artifact collector Job: %w", err)
	}
	if err := reconciler.Create(ctx, collectorJob); err != nil && !apierrors.IsAlreadyExists(err) {
		return fmt.Errorf("create diagnostic artifact collector Job: %w", err)
	}
	return nil
}

func validateTokenSecret(secret corev1.Secret, object breakglassv1alpha1.DebugSessionArtifact) error {
	if secret.Namespace != object.Namespace || secret.Immutable == nil || !*secret.Immutable || len(secret.Data["token"]) == 0 {
		return errors.New("diagnostic artifact upload token Secret does not satisfy its immutable contract")
	}
	for _, owner := range secret.OwnerReferences {
		if owner.Kind == "DebugSessionArtifact" && owner.UID == object.UID && owner.Controller != nil && *owner.Controller {
			return nil
		}
	}
	return errors.New("diagnostic artifact upload token Secret is not owned by the artifact")
}

func validateCollectorJob(job batchv1.Job, object breakglassv1alpha1.DebugSessionArtifact) error {
	if job.Namespace != object.Namespace || job.Labels["breakglass.t-caas.telekom.com/artifact"] != object.Spec.ArtifactID || job.Labels["breakglass.t-caas.telekom.com/session-uid"] != string(object.Spec.SessionRef.UID) || job.Annotations["breakglass.t-caas.telekom.com/plan-sha256"] != object.Spec.PlanDigest {
		return errors.New("diagnostic artifact collector Job does not match the artifact binding")
	}
	pod := job.Spec.Template.Spec
	if len(pod.InitContainers) != 1 || pod.InitContainers[0].Name != "collector" || len(pod.Containers) != 1 || pod.Containers[0].Name != "uploader" {
		return errors.New("diagnostic artifact collector Job does not enforce collector-before-uploader ordering")
	}
	if pod.SecurityContext == nil || pod.SecurityContext.FSGroup == nil || *pod.SecurityContext.FSGroup != 65532 || pod.AutomountServiceAccountToken == nil || *pod.AutomountServiceAccountToken {
		return errors.New("diagnostic artifact collector Job does not satisfy its filesystem and token contract")
	}
	if job.Spec.Template.Annotations["breakglass.t-caas.telekom.com/plan-sha256"] != object.Spec.PlanDigest {
		return errors.New("diagnostic artifact collector Pod template does not carry the full plan digest")
	}
	if object.Spec.Recipe == archive.CrashdumpCollectionRecipe && object.Spec.Node != nil && pod.NodeName != *object.Spec.Node {
		return errors.New("diagnostic artifact crashdump Job is not pinned to its approved node")
	}
	for _, owner := range job.OwnerReferences {
		if owner.Kind == "DebugSessionArtifact" && owner.UID == object.UID && owner.Controller != nil && *owner.Controller {
			return nil
		}
	}
	return errors.New("diagnostic artifact collector Job is not owned by the artifact")
}

func valueOrEmpty(value *string) string {
	if value == nil {
		return ""
	}
	return *value
}
func valueOrZero(value *int64) int64 {
	if value == nil {
		return 0
	}
	return *value
}
func boolPtr(value bool) *bool { return &value }

var _ reconcile.Reconciler = (*Reconciler)(nil)
