// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

// Package controller reconciles durable artifact records and their fixed
// collector Jobs. Provider operations remain in backend.Service.
package controller

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strings"
	"time"

	"go.uber.org/zap"
	batchv1 "k8s.io/api/batch/v1"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/reconcile"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/backend"
	artifactjob "github.com/telekom/k8s-breakglass/pkg/artifacts/job"
	artifactkube "github.com/telekom/k8s-breakglass/pkg/artifacts/kube"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/breakglass/debug"
	"github.com/telekom/k8s-breakglass/pkg/quotas"
)

const artifactFinalizer = "breakglass.t-caas.telekom.com/debug-session-artifact"

// UploadTokenIssuer issues a token whose claims are bound to the immutable
// record. The implementation owns the verifier keyring and JTI/epoch policy.
type UploadTokenIssuer interface {
	IssueUploadToken(context.Context, backend.Record, string) (string, error)
}

type TargetClientProvider interface {
	GetClientForPrivilegedOperation(context.Context, string) (ctrlclient.Client, *breakglassv1alpha1.ClusterConfig, error)
	ValidatePrivilegedOperationClusterConfig(context.Context, *breakglassv1alpha1.ClusterConfig) error
	ReleasePrivilegedOperationClusterConfig(*breakglassv1alpha1.ClusterConfig)
}

// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=debugsessionartifacts,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=debugsessionartifacts/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=debugsessionartifacts/finalizers,verbs=update

type Reconciler struct {
	ctrlclient.Client
	Service         *backend.Service
	TokenIssuer     UploadTokenIssuer
	Image           string
	ControllerURL   string
	Log             *zap.SugaredLogger
	Now             func() time.Time
	ClusterProvider TargetClientProvider
	LiveReader      ctrlclient.Reader
}

func (reconciler *Reconciler) SetupWithManager(manager ctrl.Manager) error {
	if reconciler.Client == nil || reconciler.LiveReader == nil || reconciler.Service == nil || reconciler.TokenIssuer == nil || reconciler.ClusterProvider == nil {
		return errors.New("artifact reconciler client, live reader, backend service, token issuer, and cluster provider are required")
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
	terminalRecord := record.State == backend.StateDeleted || record.State == backend.StateExpired || record.State == backend.StateRevoked
	if object.DeletionTimestamp.IsZero() && !terminalRecord && !containsString(object.Finalizers, artifactFinalizer) {
		object.Finalizers = append(object.Finalizers, artifactFinalizer)
		if err := reconciler.Update(ctx, &object); err != nil {
			return ctrl.Result{}, fmt.Errorf("add diagnostic artifact finalizer: %w", err)
		}
		return ctrl.Result{Requeue: true}, nil
	}
	if object.DeletionTimestamp.IsZero() && record.State == backend.StateAvailable && !record.ExpiresAt.IsZero() && !now().Before(record.ExpiresAt) {
		if err := reconciler.Service.Cleanup(ctx, record, backend.StateExpired); err != nil {
			return ctrl.Result{}, err
		}
		if err := reconciler.cleanupSpokeResources(ctx, &object); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}
	if object.DeletionTimestamp.IsZero() && (record.State == backend.StatePending || record.State == backend.StateUploading) && !record.ExpiresAt.IsZero() && !now().Before(record.ExpiresAt) {
		if err := reconciler.Service.Cleanup(ctx, record, backend.StateExpired); err != nil {
			return ctrl.Result{}, err
		}
		if err := reconciler.cleanupSpokeResources(ctx, &object); err != nil {
			return ctrl.Result{}, err
		}
		return ctrl.Result{Requeue: true}, nil
	}
	if object.DeletionTimestamp.IsZero() && record.Recipe == backend.TerminalRecordingRecipe && !terminalRecord && !record.CleanupAmbiguous {
		if !now().Before(record.ExpiresAt) {
			if err := reconciler.Service.Cleanup(ctx, record, backend.StateExpired); err != nil {
				return ctrl.Result{}, err
			}
			return ctrl.Result{Requeue: true}, nil
		}
		if record.State == backend.StateUploading || record.State == backend.StateUnknown {
			if _, err := reconciler.Service.RecoverRecording(ctx, record); err != nil {
				return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
			}
		}
		return ctrl.Result{RequeueAfter: min(30*time.Second, time.Until(record.ExpiresAt))}, nil
	}
	if object.DeletionTimestamp.IsZero() && record.Recipe != backend.TerminalRecordingRecipe && (record.State == backend.StatePending || record.State == backend.StateUploading || record.State == backend.StateAvailable) {
		revoked, err := reconciler.collectionRevoked(ctx, &object, now)
		if err != nil {
			return ctrl.Result{}, err
		}
		if revoked {
			return ctrl.Result{Requeue: true}, reconciler.cleanupRevokedCollection(ctx, &object)
		}
		if record.State == backend.StateAvailable {
			// Completed diagnostics belong to the live session, unlike retained
			// terminal recordings. Poll revocation without recreating workloads.
			return ctrl.Result{RequeueAfter: min(30*time.Second, max(time.Second, time.Until(record.ExpiresAt)))}, nil
		}
		if writeErr := reconciler.ensureUploadResources(ctx, object, record); writeErr != nil {
			revoked, readErr := reconciler.collectionRevoked(ctx, &object, now)
			if readErr != nil {
				return ctrl.Result{}, errors.Join(writeErr, readErr)
			}
			if revoked {
				return ctrl.Result{Requeue: true}, reconciler.cleanupRevokedCollection(ctx, &object)
			}
			return ctrl.Result{}, writeErr
		}
		return ctrl.Result{RequeueAfter: 30 * time.Second}, nil
	}
	if !object.DeletionTimestamp.IsZero() || record.State == backend.StateDeleting || record.State == backend.StateUnknown || record.State == backend.StateExpired || record.State == backend.StateRevoked || record.State == backend.StateDeleted {
		if record.State != backend.StateExpired && record.State != backend.StateRevoked && record.State != backend.StateDeleted {
			terminal := backend.StateDeleted
			if record.State == backend.StatePending || record.State == backend.StateUploading {
				terminal = backend.StateRevoked
			}
			if err := reconciler.Service.Cleanup(ctx, record, terminal); err != nil {
				return ctrl.Result{}, err
			}
		}
		if err := reconciler.cleanupSpokeResources(ctx, &object); err != nil {
			return ctrl.Result{}, err
		}
		current := &breakglassv1alpha1.DebugSessionArtifact{}
		if err := reconciler.hubGet(ctx, ctrlclient.ObjectKeyFromObject(&object), current); err != nil {
			return ctrl.Result{}, err
		}
		if current.UID != object.UID {
			return ctrl.Result{}, errors.New("artifact was replaced while finalizing")
		}
		if len(current.Status.Resources) != 0 {
			return ctrl.Result{}, errors.New("artifact cleanup inventory is not empty")
		}
		current.Finalizers = removeString(current.Finalizers, artifactFinalizer)
		if err := reconciler.Update(ctx, current); err != nil {
			return ctrl.Result{}, fmt.Errorf("remove diagnostic artifact finalizer: %w", err)
		}
		if current.DeletionTimestamp.IsZero() {
			uid, rv := current.UID, current.ResourceVersion
			if err := reconciler.Delete(ctx, current, &ctrlclient.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &rv}}); err != nil && !apierrors.IsNotFound(err) {
				return ctrl.Result{}, fmt.Errorf("delete cleaned artifact reservation: %w", err)
			}
		}
	}
	if record.State == backend.StateAvailable {
		return ctrl.Result{RequeueAfter: max(time.Second, time.Until(record.ExpiresAt))}, nil
	}
	return ctrl.Result{}, nil
}

// collectionRevoked distinguishes definitive live revocation from transient read
// failures. A broad authorization error is not proof that cleanup is required.
func (reconciler *Reconciler) collectionRevoked(ctx context.Context, object *breakglassv1alpha1.DebugSessionArtifact, now func() time.Time) (bool, error) {
	var session breakglassv1alpha1.DebugSession
	err := reconciler.hubGet(ctx, types.NamespacedName{Namespace: object.Spec.SessionRef.Namespace, Name: object.Spec.SessionRef.Name}, &session)
	if apierrors.IsNotFound(err) {
		return true, nil
	}
	if err != nil {
		return false, fmt.Errorf("read collector session revocation: %w", err)
	}
	decisionTime := now()
	if string(session.UID) != object.Spec.SessionRef.UID || !session.DeletionTimestamp.IsZero() || session.Status.State != breakglassv1alpha1.DebugSessionStateActive || session.Status.ExpiresAt == nil || !decisionTime.Before(session.Status.ExpiresAt.Time) || breakglass.DebugSessionIdleExpired(&session, decisionTime) || session.Annotations[quotas.AdmissionAnnotation] == quotas.Pending {
		return true, nil
	}
	if object.Spec.ConnectionLeaseUID != "" {
		ref := session.Status.ConnectionLease
		if ref == nil || string(ref.UID) != object.Spec.ConnectionLeaseUID || ref.Epoch <= 0 || uint64(ref.Epoch) != object.Spec.OperationEpoch {
			return true, nil
		}
		var lease coordinationv1.Lease
		err := reconciler.hubGet(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, &lease)
		if apierrors.IsNotFound(err) {
			return true, nil
		}
		if err != nil {
			return false, fmt.Errorf("read collector lease revocation: %w", err)
		}
		decisionTime = now()
		if err := debug.ValidateConnectionLease(&lease, debug.ConnectionLeaseRef{Namespace: ref.Namespace, Name: ref.Name, UID: ref.UID, HolderUID: ref.HolderUID, TargetUID: ref.TargetUID, ProfileDigest: ref.ProfileDigest, Epoch: ref.Epoch, ExpiresAt: ref.ExpiresAt.Time}, decisionTime); err != nil {
			return true, nil
		}
		if !decisionTime.Before(session.Status.ExpiresAt.Time) || breakglass.DebugSessionIdleExpired(&session, decisionTime) {
			return true, nil
		}
	}
	return false, nil
}

func (reconciler *Reconciler) cleanupRevokedCollection(ctx context.Context, expected *breakglassv1alpha1.DebugSessionArtifact) error {
	var current breakglassv1alpha1.DebugSessionArtifact
	if err := reconciler.hubGet(ctx, ctrlclient.ObjectKeyFromObject(expected), &current); err != nil {
		return err
	}
	if expected.UID == "" || current.UID != expected.UID {
		return backend.ErrConflict
	}
	// Revoke provider access first, but do not leave an existing collector Job
	// running merely because provider cleanup is temporarily unavailable.
	record := artifactkube.Record(&current)
	var providerErr error
	if record.State != backend.StateRevoked && record.State != backend.StateExpired && record.State != backend.StateDeleted {
		providerErr = reconciler.Service.Cleanup(ctx, record, backend.StateRevoked)
	}
	spokeErr := reconciler.cleanupSpokeResources(ctx, &current)
	return errors.Join(providerErr, spokeErr)
}

func (reconciler *Reconciler) ensureUploadResources(ctx context.Context, object breakglassv1alpha1.DebugSessionArtifact, record backend.Record) error {
	if reconciler.Image == "" || reconciler.ControllerURL == "" {
		return errors.New("artifact reconciler image and controller URL are required")
	}
	session, target, targetClient, release, err := reconciler.spokeClient(ctx, &object)
	if err != nil {
		return err
	}
	defer release()
	if err := reconciler.validateSpokeWrite(ctx, &object, session, target, targetClient); err != nil {
		return err
	}
	targetNamespace := session.Spec.TargetNamespace
	if targetNamespace == "" {
		targetNamespace = object.Spec.SessionRef.Namespace
	}
	secretName := object.Spec.ArtifactID + "-upload"
	if err := reconciler.persistTargetIdentity(ctx, &object, session.Spec.Cluster, targetNamespace); err != nil {
		return err
	}
	secretRef, err := reconciler.persistResourceIntent(ctx, &object, "Secret", targetNamespace, secretName)
	if err != nil {
		return err
	}
	route := "/api/debugSessionArtifactUploads/" + object.Spec.SessionRef.Namespace + "/" + object.Spec.SessionRef.Name + "/" + object.Spec.ArtifactID
	var secret corev1.Secret
	secretKey := types.NamespacedName{Namespace: targetNamespace, Name: secretName}
	err = targetClient.Get(ctx, secretKey, &secret)
	if apierrors.IsNotFound(err) {
		if secretRef.UID != "" {
			return errors.New("artifact upload Secret disappeared after creation; refusing replacement adoption")
		}
		token, issueErr := reconciler.TokenIssuer.IssueUploadToken(ctx, record, route)
		if issueErr != nil {
			return fmt.Errorf("issue diagnostic artifact upload token: %w", issueErr)
		}
		secret = corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: secretName, Namespace: targetNamespace, Labels: map[string]string{"breakglass.t-caas.telekom.com/artifact": object.Spec.ArtifactID}, Annotations: map[string]string{"breakglass.t-caas.telekom.com/artifact-uid": string(object.UID), "breakglass.t-caas.telekom.com/operation-id": secretRef.OperationID}}, Type: corev1.SecretTypeOpaque, Immutable: boolPtr(true), Data: map[string][]byte{"token": []byte(token)}}
		if err := reconciler.validateSpokeWrite(ctx, &object, session, target, targetClient); err != nil {
			return err
		}
		if createErr := targetClient.Create(ctx, &secret); createErr != nil {
			return fmt.Errorf("create diagnostic artifact upload token Secret outcome is ambiguous: %w", createErr)
		}
		if err := reconciler.persistResourceUID(ctx, &object, "Secret", secret.UID, secret.ResourceVersion); err != nil {
			return err
		}
		if err := reconciler.validateSpokeWrite(ctx, &object, session, target, targetClient); err != nil {
			return err
		}
	} else if err != nil {
		return fmt.Errorf("get diagnostic artifact upload token Secret: %w", err)
	} else if secretRef.UID == "" || string(secret.UID) != secretRef.UID {
		return errors.New("artifact upload Secret exists without the recorded creation UID")
	}
	if err := validateTokenSecret(secret, object, targetNamespace, secretRef.OperationID); err != nil {
		return err
	}
	jobName := object.Spec.ArtifactID + "-collect"
	jobRef, err := reconciler.persistResourceIntent(ctx, &object, "Job", targetNamespace, jobName)
	if err != nil {
		return err
	}
	config := artifactjob.Config{Namespace: targetNamespace, Name: jobName, ArtifactID: object.Spec.ArtifactID, ArtifactName: object.Name, ArtifactUID: string(object.UID), SessionNamespace: object.Spec.SessionRef.Namespace, SessionName: object.Spec.SessionRef.Name, SessionUID: object.Spec.SessionRef.UID, Recipe: object.Spec.Recipe, RecipeVersion: int(object.Spec.RecipeVersion), PlanDigest: object.Spec.PlanDigest, RuntimeBindingDigest: object.Spec.RuntimeBindingDigest, RedactionProfile: object.Spec.RedactionProfile, RedactionVersion: int(object.Spec.RedactionVersion), UploadURL: strings.TrimSuffix(reconciler.ControllerURL, "/") + route, UploadTokenSecretName: secretName, Image: reconciler.Image, Node: valueOrEmpty(object.Spec.Node), MaxBytes: object.Spec.MaxBytes, TimeoutSeconds: object.Spec.TimeoutSeconds, DetailLevel: valueOrEmpty(object.Spec.Inputs.DetailLevel), MaxAgeMinutes: valueOrZero(object.Spec.Inputs.MaxAgeMinutes)}
	collectorJob, err := artifactjob.Build(config)
	if err != nil {
		return fmt.Errorf("build diagnostic artifact collector Job: %w", err)
	}
	collectorJob.OwnerReferences = nil
	if collectorJob.Annotations == nil {
		collectorJob.Annotations = map[string]string{}
	}
	collectorJob.Annotations["breakglass.t-caas.telekom.com/artifact-uid"] = string(object.UID)
	collectorJob.Annotations["breakglass.t-caas.telekom.com/operation-id"] = jobRef.OperationID
	var existing batchv1.Job
	if err := targetClient.Get(ctx, types.NamespacedName{Namespace: targetNamespace, Name: jobName}, &existing); err == nil {
		if jobRef.UID == "" {
			return errors.New("artifact collector Job exists without the recorded creation UID")
		}
		if string(existing.UID) != jobRef.UID {
			return errors.New("artifact collector Job was replaced; refusing adoption")
		}
		if err := validateCollectorJob(existing, *collectorJob, object, targetNamespace, jobRef.OperationID); err != nil {
			return err
		}
		return nil
	} else if !apierrors.IsNotFound(err) {
		return fmt.Errorf("get diagnostic artifact collector Job: %w", err)
	}
	if jobRef.UID != "" {
		return errors.New("artifact collector Job disappeared after creation; refusing replacement adoption")
	}
	if err := reconciler.validateSpokeWrite(ctx, &object, session, target, targetClient); err != nil {
		return err
	}
	if err := targetClient.Create(ctx, collectorJob); err != nil {
		return fmt.Errorf("create diagnostic artifact collector Job outcome is ambiguous: %w", err)
	}
	if err := reconciler.persistResourceUID(ctx, &object, "Job", collectorJob.UID, collectorJob.ResourceVersion); err != nil {
		return err
	}
	if err := reconciler.validateSpokeWrite(ctx, &object, session, target, targetClient); err != nil {
		return err
	}
	return nil
}

func validateTokenSecret(secret corev1.Secret, object breakglassv1alpha1.DebugSessionArtifact, expectedNamespace, operationID string) error {
	if secret.Namespace != expectedNamespace || secret.Immutable == nil || !*secret.Immutable || len(secret.Data["token"]) == 0 {
		return errors.New("diagnostic artifact upload token Secret does not satisfy its immutable contract")
	}
	if secret.Annotations["breakglass.t-caas.telekom.com/artifact-uid"] == string(object.UID) && secret.Annotations["breakglass.t-caas.telekom.com/operation-id"] == operationID {
		return nil
	}
	return errors.New("diagnostic artifact upload token Secret is not bound to the artifact")
}

func validateCollectorJob(job, expected batchv1.Job, object breakglassv1alpha1.DebugSessionArtifact, expectedNamespace, operationID string) error {
	if job.Namespace != expectedNamespace || job.Labels["breakglass.t-caas.telekom.com/artifact"] != object.Spec.ArtifactID || job.Labels["breakglass.t-caas.telekom.com/session-uid"] != object.Spec.SessionRef.UID || job.Annotations["breakglass.t-caas.telekom.com/plan-sha256"] != object.Spec.PlanDigest || job.Annotations["breakglass.t-caas.telekom.com/operation-id"] != operationID {
		return errors.New("diagnostic artifact collector Job does not match the artifact binding")
	}
	if job.Annotations["breakglass.t-caas.telekom.com/artifact-uid"] != string(object.UID) {
		return errors.New("diagnostic artifact collector Job is not bound to the artifact")
	}
	return artifactjob.ValidateExecution(job, expected)
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

func containsString(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}
func removeString(values []string, needle string) []string {
	result := values[:0]
	for _, value := range values {
		if value != needle {
			result = append(result, value)
		}
	}
	return result
}

func (reconciler *Reconciler) spokeClient(ctx context.Context, object *breakglassv1alpha1.DebugSessionArtifact) (*breakglassv1alpha1.DebugSession, *breakglassv1alpha1.ClusterConfig, ctrlclient.Client, func(), error) {
	var session breakglassv1alpha1.DebugSession
	if err := reconciler.hubGet(ctx, types.NamespacedName{Namespace: object.Spec.SessionRef.Namespace, Name: object.Spec.SessionRef.Name}, &session); err != nil {
		return nil, nil, nil, func() {}, fmt.Errorf("get live debug session for artifact: %w", err)
	}
	if string(session.UID) != object.Spec.SessionRef.UID || session.DeletionTimestamp != nil {
		return nil, nil, nil, func() {}, errors.New("debug session identity changed")
	}
	targetClient, target, err := reconciler.ClusterProvider.GetClientForPrivilegedOperation(ctx, session.Spec.Cluster)
	if err != nil {
		return nil, nil, nil, func() {}, fmt.Errorf("get artifact target client: %w", err)
	}
	release := func() { reconciler.ClusterProvider.ReleasePrivilegedOperationClusterConfig(target) }
	if string(target.UID) != object.Spec.TargetClusterUID {
		release()
		return nil, nil, nil, func() {}, errors.New("artifact target cluster identity changed")
	}
	return &session, target, targetClient, release, nil
}

func (reconciler *Reconciler) validateSpokeWrite(ctx context.Context, object *breakglassv1alpha1.DebugSessionArtifact, session *breakglassv1alpha1.DebugSession, target *breakglassv1alpha1.ClusterConfig, targetClient ctrlclient.Client) error {
	if object.Spec.OperationEpoch > math.MaxInt64 {
		return errors.New("artifact operation epoch exceeds lease range")
	}
	if object.Spec.TargetPod != nil {
		ref := object.Spec.TargetPod
		var pod corev1.Pod
		if ref.UID == "" || targetClient == nil {
			return errors.New("artifact target pod identity is missing")
		}
		if err := targetClient.Get(ctx, types.NamespacedName{Namespace: ref.Namespace, Name: ref.Name}, &pod); err != nil {
			return fmt.Errorf("read artifact target pod before spoke write: %w", err)
		}
		if string(pod.UID) != ref.UID || !pod.DeletionTimestamp.IsZero() {
			return errors.New("artifact target pod identity changed")
		}
		if object.Spec.TargetNodeUID != "" {
			var node corev1.Node
			if err := targetClient.Get(ctx, types.NamespacedName{Name: pod.Spec.NodeName}, &node); err != nil {
				return fmt.Errorf("read artifact target node before spoke write: %w", err)
			}
			if string(node.UID) != object.Spec.TargetNodeUID || !node.DeletionTimestamp.IsZero() {
				return errors.New("artifact target node identity changed")
			}
		}
	}
	if err := reconciler.ClusterProvider.ValidatePrivilegedOperationClusterConfig(ctx, target); err != nil {
		return err
	}
	var liveSession breakglassv1alpha1.DebugSession
	if err := reconciler.hubGet(ctx, types.NamespacedName{Namespace: object.Spec.SessionRef.Namespace, Name: object.Spec.SessionRef.Name}, &liveSession); err != nil {
		return fmt.Errorf("read live debug session after target fence: %w", err)
	}
	var liveArtifact breakglassv1alpha1.DebugSessionArtifact
	if err := reconciler.hubGet(ctx, ctrlclient.ObjectKeyFromObject(object), &liveArtifact); err != nil {
		return fmt.Errorf("read live artifact after target fence: %w", err)
	}
	if object.Spec.ConnectionLeaseUID != "" {
		if reconciler.Service == nil {
			return errors.New("artifact capability verifier is missing")
		}
		if err := reconciler.Service.AuthorizeCollection(ctx, artifactkube.Record(object)); err != nil {
			return fmt.Errorf("authorize artifact capability before spoke write: %w", err)
		}
	}
	var finalSession breakglassv1alpha1.DebugSession
	if err := reconciler.hubGet(ctx, types.NamespacedName{Namespace: object.Spec.SessionRef.Namespace, Name: object.Spec.SessionRef.Name}, &finalSession); err != nil {
		return fmt.Errorf("read final live debug session before spoke write: %w", err)
	}
	now := time.Now
	if reconciler.Now != nil {
		now = reconciler.Now
	}
	decisionTime := now()
	liveState := backend.State(liveArtifact.Status.State)
	if liveState == "" {
		liveState = backend.StatePending
	}
	if finalSession.UID != session.UID || object.Spec.ConnectionLeaseUID != "" && (finalSession.Status.ConnectionLease == nil || string(finalSession.Status.ConnectionLease.UID) != object.Spec.ConnectionLeaseUID || finalSession.Status.ConnectionLease.Epoch != int64(object.Spec.OperationEpoch)) || !finalSession.DeletionTimestamp.IsZero() || finalSession.Spec.Cluster != session.Spec.Cluster || finalSession.Spec.TargetNamespace != session.Spec.TargetNamespace || finalSession.Status.State != breakglassv1alpha1.DebugSessionStateActive || finalSession.Status.ExpiresAt == nil || !decisionTime.Before(finalSession.Status.ExpiresAt.Time) || breakglass.DebugSessionIdleExpired(&finalSession, decisionTime) || finalSession.Annotations[quotas.AdmissionAnnotation] == quotas.Pending || liveArtifact.UID != object.UID || !liveArtifact.DeletionTimestamp.IsZero() || liveState != backend.StatePending && liveState != backend.StateUploading || liveArtifact.Spec.TargetClusterUID != object.Spec.TargetClusterUID || liveArtifact.Spec.PlanDigest != object.Spec.PlanDigest || !decisionTime.Before(liveArtifact.Spec.ExpiresAt.Time) {
		return errors.New("artifact identity changed before spoke write")
	}
	return nil
}

func (reconciler *Reconciler) persistTargetIdentity(ctx context.Context, object *breakglassv1alpha1.DebugSessionArtifact, clusterName, namespace string) error {
	current := &breakglassv1alpha1.DebugSessionArtifact{}
	if err := reconciler.hubGet(ctx, ctrlclient.ObjectKeyFromObject(object), current); err != nil {
		return err
	}
	if current.UID != object.UID {
		return errors.New("artifact was replaced while persisting target identity")
	}
	if current.Status.TargetCluster != "" && (current.Status.TargetCluster != clusterName || current.Status.TargetNamespace != namespace) {
		return errors.New("artifact target cleanup identity changed")
	}
	if current.Status.TargetCluster == clusterName && current.Status.TargetNamespace == namespace {
		return nil
	}
	current.Status.TargetCluster, current.Status.TargetNamespace = clusterName, namespace
	return reconciler.Status().Update(ctx, current)
}

func (reconciler *Reconciler) persistResourceIntent(ctx context.Context, object *breakglassv1alpha1.DebugSessionArtifact, kind, namespace, name string) (breakglassv1alpha1.ArtifactResourceReference, error) {
	current := &breakglassv1alpha1.DebugSessionArtifact{}
	if err := reconciler.hubGet(ctx, ctrlclient.ObjectKeyFromObject(object), current); err != nil {
		return breakglassv1alpha1.ArtifactResourceReference{}, err
	}
	if current.UID != object.UID {
		return breakglassv1alpha1.ArtifactResourceReference{}, errors.New("artifact was replaced while persisting resource intent")
	}
	for _, reference := range current.Status.Resources {
		if reference.Kind == kind {
			if reference.Namespace != namespace || reference.Name != name {
				return breakglassv1alpha1.ArtifactResourceReference{}, errors.New("artifact resource intent changed")
			}
			return reference, nil
		}
	}
	state := backend.State(current.Status.State)
	if !current.DeletionTimestamp.IsZero() || state == backend.StateDeleting || state == backend.StateDeleted || state == backend.StateExpired || state == backend.StateRevoked || state == backend.StateUnknown {
		return breakglassv1alpha1.ArtifactResourceReference{}, errors.New("artifact no longer accepts new resource intents")
	}
	reference := breakglassv1alpha1.ArtifactResourceReference{Kind: kind, Namespace: namespace, Name: name, OperationID: string(current.UID) + "/" + strings.ToLower(kind)}
	current.Status.Resources = append(current.Status.Resources, reference)
	if err := reconciler.Status().Update(ctx, current); err != nil {
		return breakglassv1alpha1.ArtifactResourceReference{}, fmt.Errorf("persist artifact %s intent: %w", kind, err)
	}
	return reference, nil
}

func (reconciler *Reconciler) persistResourceUID(ctx context.Context, object *breakglassv1alpha1.DebugSessionArtifact, kind string, uid types.UID, resourceVersion string) error {
	if uid == "" {
		return errors.New("created artifact resource did not return a UID")
	}
	current := &breakglassv1alpha1.DebugSessionArtifact{}
	if err := reconciler.hubGet(ctx, ctrlclient.ObjectKeyFromObject(object), current); err != nil {
		return err
	}
	if current.UID != object.UID {
		return errors.New("artifact was replaced while persisting resource UID")
	}
	found := false
	for index := range current.Status.Resources {
		if current.Status.Resources[index].Kind == kind {
			if current.Status.Resources[index].UID != "" && current.Status.Resources[index].UID != string(uid) {
				return errors.New("artifact resource UID changed")
			}
			current.Status.Resources[index].UID, current.Status.Resources[index].ResourceVersion = string(uid), resourceVersion
			found = true
		}
	}
	if !found {
		return errors.New("artifact resource intent is missing")
	}
	return reconciler.Status().Update(ctx, current)
}

func (reconciler *Reconciler) cleanupSpokeResources(ctx context.Context, object *breakglassv1alpha1.DebugSessionArtifact) error {
	if len(object.Status.Resources) == 0 {
		return nil
	}
	var targetClient ctrlclient.Client
	var target *breakglassv1alpha1.ClusterConfig
	var release func()
	var err error
	if object.Status.TargetCluster != "" {
		targetClient, target, err = reconciler.ClusterProvider.GetClientForPrivilegedOperation(ctx, object.Status.TargetCluster)
		release = func() {
			if target != nil {
				reconciler.ClusterProvider.ReleasePrivilegedOperationClusterConfig(target)
			}
		}
		if err == nil && string(target.UID) != object.Spec.TargetClusterUID {
			err = errors.New("artifact cleanup target cluster identity changed")
		}
	} else {
		_, target, targetClient, release, err = reconciler.spokeClient(ctx, object)
	}
	if err != nil {
		return err
	}
	defer release()
	ambiguous := false
	initialByOperation := make(map[string]breakglassv1alpha1.ArtifactResourceReference, len(object.Status.Resources))
	removed := make(map[string]struct{})
	updated := make(map[string]breakglassv1alpha1.ArtifactResourceReference)
	for _, reference := range object.Status.Resources {
		initialByOperation[reference.OperationID] = reference
		if err := reconciler.ClusterProvider.ValidatePrivilegedOperationClusterConfig(ctx, target); err != nil {
			return err
		}
		var resource ctrlclient.Object
		switch reference.Kind {
		case "Secret":
			resource = &corev1.Secret{}
		case "Job":
			resource = &batchv1.Job{}
		default:
			return fmt.Errorf("unsupported artifact cleanup kind %q", reference.Kind)
		}
		key := types.NamespacedName{Namespace: reference.Namespace, Name: reference.Name}
		if err := targetClient.Get(ctx, key, resource); apierrors.IsNotFound(err) {
			if reference.UID == "" {
				ambiguous = true
			} else {
				removed[reference.OperationID] = struct{}{}
			}
			continue
		} else if err != nil {
			return fmt.Errorf("get spoke artifact resource %s/%s: %w", reference.Namespace, reference.Name, err)
		}
		if reference.UID == "" {
			ambiguous = true
			continue
		}
		if string(resource.GetUID()) != reference.UID {
			removed[reference.OperationID] = struct{}{}
			continue
		}
		liveResourceVersion := resource.GetResourceVersion()
		uid := types.UID(reference.UID)
		if err := targetClient.Delete(ctx, resource, &ctrlclient.DeleteOptions{Preconditions: &metav1.Preconditions{UID: &uid, ResourceVersion: &liveResourceVersion}}); err != nil && !apierrors.IsNotFound(err) {
			return fmt.Errorf("delete spoke artifact resource %s/%s: %w", reference.Namespace, reference.Name, err)
		}
		if err := targetClient.Get(ctx, key, resource); err == nil {
			if string(resource.GetUID()) == reference.UID {
				reference.ResourceVersion = resource.GetResourceVersion()
				updated[reference.OperationID] = reference
			}
		} else if !apierrors.IsNotFound(err) {
			return fmt.Errorf("verify spoke artifact cleanup %s/%s: %w", reference.Namespace, reference.Name, err)
		} else {
			removed[reference.OperationID] = struct{}{}
		}
	}
	current := &breakglassv1alpha1.DebugSessionArtifact{}
	if err := reconciler.hubGet(ctx, ctrlclient.ObjectKeyFromObject(object), current); err != nil {
		return err
	}
	if current.UID != object.UID {
		return errors.New("artifact was replaced during cleanup")
	}
	merged := make([]breakglassv1alpha1.ArtifactResourceReference, 0, len(current.Status.Resources))
	for _, currentReference := range current.Status.Resources {
		initial, tracked := initialByOperation[currentReference.OperationID]
		if !tracked {
			merged = append(merged, currentReference)
			continue
		}
		// A newer UID is a concurrent create result; never let this cleanup
		// operation overwrite it with an older removal decision.
		if currentReference.UID != initial.UID && currentReference.UID != "" {
			merged = append(merged, currentReference)
			continue
		}
		if replacement, ok := updated[currentReference.OperationID]; ok {
			merged = append(merged, replacement)
			continue
		}
		if _, ok := removed[currentReference.OperationID]; ok {
			continue
		}
		merged = append(merged, currentReference)
	}
	current.Status.Resources = merged
	if err := reconciler.Status().Update(ctx, current); err != nil {
		return fmt.Errorf("persist artifact cleanup inventory: %w", err)
	}
	if ambiguous || len(merged) != 0 {
		return errors.New("spoke artifact cleanup is still pending")
	}
	return nil
}

var _ reconcile.Reconciler = (*Reconciler)(nil)

func (reconciler *Reconciler) hubGet(ctx context.Context, key types.NamespacedName, object ctrlclient.Object) error {
	return reconciler.LiveReader.Get(ctx, key, object)
}
