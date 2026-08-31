/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package debug

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apiequality "k8s.io/apimachinery/pkg/api/equality"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/util/retry"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/utils"
)

// KubectlDebugHandler handles kubectl-debug mode operations
type KubectlDebugHandler struct {
	client     ctrlclient.Client
	reader     ctrlclient.Reader
	ccProvider ClientProviderInterface
}

// deleteOrphanedPod removes a pod that was created on the spoke cluster but could
// not be recorded in the DebugSession status.
//
// This is required for correctness, not tidiness: cleanup
// (CleanupKubectlDebugResources / cleanupResources) iterates the status lists, so
// a pod that never made it into the status is invisible to every cleanup path and
// outlives its session indefinitely. For the node-debug pod that orphan is a
// privileged pod with hostPath "/" mounted read-write.
//
// Failures are logged and swallowed: the caller is already returning the original
// status-patch error, which is the actionable one.
func (h *KubectlDebugHandler) deleteOrphanedPod(ctx context.Context, targetClient ctrlclient.Client, pod *corev1.Pod, cause error) {
	log := zap.S().Named("kubectl-debug")

	// Use a context detached from the caller's: when the status patch failed
	// because the request context was cancelled, a cancelled context would also
	// prevent the compensating delete and leave the orphan behind anyway.
	deleteCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), orphanCleanupTimeout)
	defer cancel()

	if pod == nil || pod.UID == "" || pod.Annotations[sourceSessionUIDAnnotation] == "" {
		log.Errorw("Refusing to delete orphaned debug pod without immutable identity",
			"pod", podName(pod), "statusError", cause)
		return
	}
	live := &corev1.Pod{}
	if err := targetClient.Get(deleteCtx, ctrlclient.ObjectKeyFromObject(pod), live); err != nil {
		if !apierrors.IsNotFound(err) {
			log.Errorw("Failed to read orphaned debug pod before deletion", "pod", pod.Name, "podNamespace", pod.Namespace, "statusError", cause, "getError", err)
		}
		return
	}
	if live.UID != pod.UID || live.Annotations[sourceSessionUIDAnnotation] != pod.Annotations[sourceSessionUIDAnnotation] {
		log.Warnw("Preserved orphaned debug pod because its immutable identity changed", "pod", pod.Name, "podNamespace", pod.Namespace, "statusError", cause)
		return
	}
	uidPrecondition := metav1.NewUIDPreconditions(string(pod.UID))
	if err := targetClient.Delete(deleteCtx, live, ctrlclient.Preconditions(*uidPrecondition)); err != nil && !apierrors.IsNotFound(err) {
		log.Errorw("Failed to delete orphaned debug pod after status update failure; "+
			"the pod is not tracked in the session status and will not be cleaned up automatically",
			"pod", pod.Name,
			"podNamespace", pod.Namespace,
			"statusError", cause,
			"deleteError", err)
		return
	}

	log.Warnw("Deleted orphaned debug pod after status update failure",
		"pod", pod.Name,
		"podNamespace", pod.Namespace,
		"statusError", cause)
}

func podName(pod *corev1.Pod) string {
	if pod == nil {
		return "<nil>"
	}
	return pod.Name
}

// orphanCleanupTimeout bounds the compensating delete for a pod that could not be
// recorded in the session status.
const orphanCleanupTimeout = 30 * time.Second

const kubectlDebugOperationKindEphemeralContainer = "ephemeral-container"

// ClientProviderInterface abstracts the cluster.ClientProvider for testing
type ClientProviderInterface interface {
	GetClient(ctx context.Context, clusterName string) (ctrlclient.Client, error)
	GetClientForPrivilegedOperation(ctx context.Context, clusterName string) (ctrlclient.Client, *breakglassv1alpha1.ClusterConfig, error)
	ValidatePrivilegedOperationClusterConfig(ctx context.Context, configured *breakglassv1alpha1.ClusterConfig) error
}

type kubectlDebugOperationErrorKind string

const (
	kubectlDebugOperationErrorPolicy   kubectlDebugOperationErrorKind = "policy"
	kubectlDebugOperationErrorRequest  kubectlDebugOperationErrorKind = "request"
	kubectlDebugOperationErrorInternal kubectlDebugOperationErrorKind = "internal"
)

type kubectlDebugOperationError struct {
	kind kubectlDebugOperationErrorKind
	err  error
}

func (e *kubectlDebugOperationError) Error() string {
	return e.err.Error()
}

func (e *kubectlDebugOperationError) Unwrap() error {
	return e.err
}

func kubectlDebugPolicyErrorf(format string, args ...interface{}) error {
	return &kubectlDebugOperationError{
		kind: kubectlDebugOperationErrorPolicy,
		err:  fmt.Errorf(format, args...),
	}
}

func kubectlDebugRequestErrorf(format string, args ...interface{}) error {
	return &kubectlDebugOperationError{
		kind: kubectlDebugOperationErrorRequest,
		err:  fmt.Errorf(format, args...),
	}
}

func kubectlDebugInternalErrorf(format string, args ...interface{}) error {
	return &kubectlDebugOperationError{
		kind: kubectlDebugOperationErrorInternal,
		err:  fmt.Errorf(format, args...),
	}
}

// NewKubectlDebugHandler creates a new kubectl debug handler
func NewKubectlDebugHandler(client ctrlclient.Client, ccProvider ClientProviderInterface) *KubectlDebugHandler {
	return NewKubectlDebugHandlerWithReader(client, client, ccProvider)
}

// NewKubectlDebugHandlerWithReader creates a kubectl debug handler with a
// cached client for discovery and a live reader for the authorization fence.
// Cache state is only a candidate hint and must never be the final source of
// truth for ephemeral-container authorization.
func NewKubectlDebugHandlerWithReader(client ctrlclient.Client, reader ctrlclient.Reader, ccProvider ClientProviderInterface) *KubectlDebugHandler {
	if reader == nil {
		reader = client
	}
	return &KubectlDebugHandler{
		client:     client,
		reader:     reader,
		ccProvider: ccProvider,
	}
}

func (h *KubectlDebugHandler) patchDebugSessionStatusWithRetry(
	ctx context.Context,
	ds *breakglassv1alpha1.DebugSession,
	mutate func(*breakglassv1alpha1.DebugSessionStatus),
) error {
	var patchedStatus breakglassv1alpha1.DebugSessionStatus
	var patchedResourceVersion string

	if err := retry.RetryOnConflict(retry.DefaultRetry, func() error {
		current := &breakglassv1alpha1.DebugSession{}
		if err := h.client.Get(ctx, ctrlclient.ObjectKey{Name: ds.Name, Namespace: ds.Namespace}, current); err != nil {
			return err
		}

		base := current.DeepCopy()
		mutate(&current.Status)
		if current.Generation > 0 {
			current.Status.ObservedGeneration = current.Generation
		}

		if err := h.client.Status().Patch(ctx, current, ctrlclient.MergeFromWithOptions(base, ctrlclient.MergeFromWithOptimisticLock{})); err != nil {
			return err
		}
		patchedStatus = current.Status
		patchedResourceVersion = current.ResourceVersion
		return nil
	}); err != nil {
		return fmt.Errorf("patch kubectl-debug session status: %w", err)
	}

	ds.Status = patchedStatus
	ds.ResourceVersion = patchedResourceVersion
	return nil
}

func ensureKubectlDebugStatus(status *breakglassv1alpha1.DebugSessionStatus) *breakglassv1alpha1.KubectlDebugStatus {
	if status.KubectlDebugStatus == nil {
		status.KubectlDebugStatus = &breakglassv1alpha1.KubectlDebugStatus{}
	}
	return status.KubectlDebugStatus
}

func findKubectlDebugOperation(status *breakglassv1alpha1.DebugSessionStatus, id string) *breakglassv1alpha1.KubectlDebugOperation {
	if status == nil || status.KubectlDebugStatus == nil {
		return nil
	}
	for index := range status.KubectlDebugStatus.Operations {
		operation := &status.KubectlDebugStatus.Operations[index]
		if operation.ID == id {
			return operation
		}
	}
	return nil
}

func findMatchingEphemeralOperation(
	status *breakglassv1alpha1.DebugSessionStatus,
	targetNamespace, targetPodName string,
	targetPodUID types.UID,
	containerName, image string,
	command []string,
	securityContext *corev1.SecurityContext,
) *breakglassv1alpha1.KubectlDebugOperation {
	if status == nil || status.KubectlDebugStatus == nil {
		return nil
	}
	request := desiredEphemeralContainerForIntent(containerName, image, command, securityContext)
	requestDigest := ephemeralContainerDigest(&request)
	for index := range status.KubectlDebugStatus.Operations {
		operation := &status.KubectlDebugStatus.Operations[index]
		if operation.Kind != kubectlDebugOperationKindEphemeralContainer ||
			(operation.State != breakglassv1alpha1.KubectlDebugOperationPrepared && operation.State != breakglassv1alpha1.KubectlDebugOperationCompleted) ||
			operation.TargetPod.Namespace != targetNamespace || operation.TargetPod.Name != targetPodName || operation.TargetPod.UID != targetPodUID ||
			!ephemeralContainerIntentEqual(&operation.EphemeralContainer, containerName, image, command, true, true, securityContext, requestDigest) {
			continue
		}
		return operation
	}
	return nil
}

func securityContextDigest(securityContext *corev1.SecurityContext) string {
	encoded, err := json.Marshal(securityContext)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func ephemeralContainerDigest(ephemeralContainer *corev1.EphemeralContainer) string {
	encoded, err := json.Marshal(ephemeralContainer)
	if err != nil {
		return ""
	}
	digest := sha256.Sum256(encoded)
	return hex.EncodeToString(digest[:])
}

func desiredEphemeralContainerForIntent(name, image string, command []string, securityContext *corev1.SecurityContext) corev1.EphemeralContainer {
	return corev1.EphemeralContainer{
		EphemeralContainerCommon: corev1.EphemeralContainerCommon{
			Name:            name,
			Image:           image,
			Command:         command,
			ImagePullPolicy: corev1.PullIfNotPresent,
			TTY:             true,
			Stdin:           true,
			SecurityContext: securityContext,
		},
	}
}

func ephemeralContainerIntentEqual(
	intent *breakglassv1alpha1.KubectlDebugEphemeralContainerIntent,
	name, image string,
	command []string,
	tty bool,
	stdin bool,
	securityContext *corev1.SecurityContext,
	containerDigest string,
) bool {
	if intent == nil {
		return false
	}
	if intent.ContainerDigest != "" {
		return intent.ContainerDigest == containerDigest
	}
	return intent.Name == name && intent.Image == image &&
		apiequality.Semantic.DeepEqual(intent.Command, command) &&
		intent.TTY == tty && intent.Stdin == stdin &&
		intent.SecurityContextDigest == securityContextDigest(securityContext)
}

func newEphemeralContainerOperation(
	pod *corev1.Pod,
	ephemeralContainer corev1.EphemeralContainer,
	user string,
) breakglassv1alpha1.KubectlDebugOperation {
	return breakglassv1alpha1.KubectlDebugOperation{
		ID:    uuid.New().String(),
		Kind:  kubectlDebugOperationKindEphemeralContainer,
		State: breakglassv1alpha1.KubectlDebugOperationPrepared,
		TargetPod: breakglassv1alpha1.KubectlDebugOperationTargetPod{
			Namespace: pod.Namespace,
			Name:      pod.Name,
			UID:       pod.UID,
		},
		EphemeralContainer: breakglassv1alpha1.KubectlDebugEphemeralContainerIntent{
			Name:                  ephemeralContainer.Name,
			Image:                 ephemeralContainer.Image,
			Command:               ephemeralContainer.Command,
			ContainerDigest:       ephemeralContainerDigest(&ephemeralContainer),
			SecurityContextDigest: securityContextDigest(ephemeralContainer.SecurityContext),
			TTY:                   ephemeralContainer.TTY,
			Stdin:                 ephemeralContainer.Stdin,
		},
		RequestedBy: user,
		PreparedAt:  metav1.Now(),
	}
}

func addEphemeralContainerRefIfMissing(status *breakglassv1alpha1.DebugSessionStatus, ref breakglassv1alpha1.EphemeralContainerRef) {
	kubectlStatus := ensureKubectlDebugStatus(status)
	for _, existing := range kubectlStatus.EphemeralContainersInjected {
		if existing.Namespace == ref.Namespace && existing.PodName == ref.PodName && existing.ContainerName == ref.ContainerName {
			return
		}
	}
	kubectlStatus.EphemeralContainersInjected = append(kubectlStatus.EphemeralContainersInjected, ref)
}

// prepareEphemeralContainerOperation durably records target identity and the
// exact requested container before any target-cluster mutation occurs.
func (h *KubectlDebugHandler) prepareEphemeralContainerOperation(
	ctx context.Context,
	ds *breakglassv1alpha1.DebugSession,
	operation breakglassv1alpha1.KubectlDebugOperation,
) error {
	return h.patchDebugSessionStatusWithRetry(ctx, ds, func(status *breakglassv1alpha1.DebugSessionStatus) {
		kubectlStatus := ensureKubectlDebugStatus(status)
		for _, existing := range kubectlStatus.Operations {
			if existing.ID == operation.ID {
				return
			}
		}
		kubectlStatus.Operations = append(kubectlStatus.Operations, operation)
	})
}

func (h *KubectlDebugHandler) completeEphemeralContainerOperation(
	ctx context.Context,
	ds *breakglassv1alpha1.DebugSession,
	operationID string,
	state breakglassv1alpha1.KubectlDebugOperationState,
	message string,
	ref *breakglassv1alpha1.EphemeralContainerRef,
) error {
	if findKubectlDebugOperation(&ds.Status, operationID) == nil {
		return kubectlDebugInternalErrorf("durable ephemeral-container operation %s is missing", operationID)
	}
	return h.patchDebugSessionStatusWithRetry(ctx, ds, func(status *breakglassv1alpha1.DebugSessionStatus) {
		kubectlStatus := ensureKubectlDebugStatus(status)
		for index := range kubectlStatus.Operations {
			operation := &kubectlStatus.Operations[index]
			if operation.ID != operationID {
				continue
			}
			if operation.State != breakglassv1alpha1.KubectlDebugOperationPrepared {
				if operation.State == breakglassv1alpha1.KubectlDebugOperationCompleted && state == breakglassv1alpha1.KubectlDebugOperationCompleted {
					if ref != nil {
						addEphemeralContainerRefIfMissing(status, *ref)
						addAllowedPodIfMissing(status, breakglassv1alpha1.AllowedPodRef{Namespace: ref.Namespace, Name: ref.PodName, Ready: true})
					}
				}
				return
			}
			operation.State = state
			operation.Message = message
			if state != breakglassv1alpha1.KubectlDebugOperationPrepared {
				completedAt := metav1.Now()
				operation.CompletedAt = &completedAt
			}
			if ref != nil && state == breakglassv1alpha1.KubectlDebugOperationCompleted {
				addEphemeralContainerRefIfMissing(status, *ref)
				addAllowedPodIfMissing(status, breakglassv1alpha1.AllowedPodRef{Namespace: ref.Namespace, Name: ref.PodName, Ready: true})
			}
			return
		}
	})
}

// RecoverPendingKubectlDebugOperations resolves prepared operations after a
// controller restart or an ambiguous target API response. It only records
// evidence; it never performs a compensating target mutation. A same-named
// replacement Pod or container with a different identity is marked Unknown.
func (h *KubectlDebugHandler) RecoverPendingKubectlDebugOperations(ctx context.Context, ds *breakglassv1alpha1.DebugSession) error {
	if ds == nil || ds.Status.KubectlDebugStatus == nil {
		return nil
	}
	pending := make([]breakglassv1alpha1.KubectlDebugOperation, 0)
	for _, operation := range ds.Status.KubectlDebugStatus.Operations {
		if operation.State == breakglassv1alpha1.KubectlDebugOperationPrepared && operation.Kind == kubectlDebugOperationKindEphemeralContainer {
			pending = append(pending, operation)
		}
	}
	if len(pending) == 0 {
		return nil
	}
	if h.ccProvider == nil {
		return kubectlDebugInternalErrorf("target cluster client provider is not configured")
	}
	targetClient, err := h.ccProvider.GetClient(ctx, ds.Spec.Cluster)
	if err != nil {
		return fmt.Errorf("failed to get client for cluster %s while recovering debug operation: %w", ds.Spec.Cluster, err)
	}
	if targetClient == nil {
		return kubectlDebugInternalErrorf("target client for cluster %s is not configured", ds.Spec.Cluster)
	}

	for _, operation := range pending {
		pod := &corev1.Pod{}
		err := targetClient.Get(ctx, ctrlclient.ObjectKey{Namespace: operation.TargetPod.Namespace, Name: operation.TargetPod.Name}, pod)
		if err != nil {
			if apierrors.IsNotFound(err) {
				if outcomeErr := h.completeEphemeralContainerOperation(ctx, ds, operation.ID, breakglassv1alpha1.KubectlDebugOperationUnknown, "target Pod disappeared before the prepared operation outcome could be confirmed", nil); outcomeErr != nil {
					return outcomeErr
				}
				continue
			}
			return fmt.Errorf("read target Pod %s/%s while recovering debug operation %s: %w", operation.TargetPod.Namespace, operation.TargetPod.Name, operation.ID, err)
		}

		if pod.UID != operation.TargetPod.UID {
			if outcomeErr := h.completeEphemeralContainerOperation(ctx, ds, operation.ID, breakglassv1alpha1.KubectlDebugOperationUnknown, "target Pod UID changed before the prepared operation outcome could be confirmed", nil); outcomeErr != nil {
				return outcomeErr
			}
			continue
		}

		found := false
		matches := false
		for index := range pod.Spec.EphemeralContainers {
			container := &pod.Spec.EphemeralContainers[index]
			if container.Name != operation.EphemeralContainer.Name {
				continue
			}
			found = true
			matches = ephemeralContainerIntentEqual(
				&operation.EphemeralContainer,
				container.Name,
				container.Image,
				container.Command,
				container.TTY,
				container.Stdin,
				container.SecurityContext,
				ephemeralContainerDigest(container),
			)
			break
		}
		if !found {
			if outcomeErr := h.completeEphemeralContainerOperation(ctx, ds, operation.ID, breakglassv1alpha1.KubectlDebugOperationFailed, "target Pod does not contain the prepared ephemeral container", nil); outcomeErr != nil {
				return outcomeErr
			}
			continue
		}
		if !matches {
			if outcomeErr := h.completeEphemeralContainerOperation(ctx, ds, operation.ID, breakglassv1alpha1.KubectlDebugOperationUnknown, "target Pod contains a different ephemeral container with the prepared name", nil); outcomeErr != nil {
				return outcomeErr
			}
			continue
		}

		ref := &breakglassv1alpha1.EphemeralContainerRef{
			PodName:       operation.TargetPod.Name,
			Namespace:     operation.TargetPod.Namespace,
			ContainerName: operation.EphemeralContainer.Name,
			Image:         operation.EphemeralContainer.Image,
			InjectedAt:    operation.PreparedAt,
			InjectedBy:    operation.RequestedBy,
		}
		if outcomeErr := h.completeEphemeralContainerOperation(ctx, ds, operation.ID, breakglassv1alpha1.KubectlDebugOperationCompleted, "", ref); outcomeErr != nil {
			return outcomeErr
		}
	}
	return nil
}

func addAllowedPodIfMissing(status *breakglassv1alpha1.DebugSessionStatus, ref breakglassv1alpha1.AllowedPodRef) {
	for _, existing := range status.AllowedPods {
		if existing.Namespace == ref.Namespace && existing.Name == ref.Name {
			return
		}
	}
	status.AllowedPods = append(status.AllowedPods, ref)
}

func addDeployedResourceIfMissing(status *breakglassv1alpha1.DebugSessionStatus, ref breakglassv1alpha1.DeployedResourceRef) {
	for _, existing := range status.DeployedResources {
		if existing.APIVersion == ref.APIVersion &&
			existing.Kind == ref.Kind &&
			existing.Namespace == ref.Namespace &&
			existing.Name == ref.Name {
			return
		}
	}
	status.DeployedResources = append(status.DeployedResources, ref)
}

func terminalKubectlDebugOperations(operations []breakglassv1alpha1.KubectlDebugOperation) []breakglassv1alpha1.KubectlDebugOperation {
	terminal := make([]breakglassv1alpha1.KubectlDebugOperation, 0, len(operations))
	for _, operation := range operations {
		if operation.State == breakglassv1alpha1.KubectlDebugOperationPrepared {
			continue
		}
		terminal = append(terminal, operation)
	}
	return terminal
}

func cleanupRetainedKubectlDebugStatus(kubectlStatus *breakglassv1alpha1.KubectlDebugStatus) *breakglassv1alpha1.KubectlDebugStatus {
	if kubectlStatus == nil {
		return nil
	}
	operations := terminalKubectlDebugOperations(kubectlStatus.Operations)
	if len(operations) == 0 && len(kubectlStatus.EphemeralContainersInjected) == 0 {
		return nil
	}
	retained := &breakglassv1alpha1.KubectlDebugStatus{
		Operations: operations,
	}
	if len(kubectlStatus.EphemeralContainersInjected) > 0 {
		retained.EphemeralContainersInjected = append([]breakglassv1alpha1.EphemeralContainerRef(nil), kubectlStatus.EphemeralContainersInjected...)
	}
	return retained
}

// liveSessionForMutation re-reads the session through the uncached API reader
// immediately before a target-cluster mutation. The API controller performs
// the initial authenticated lookup, but validation and target reads can race
// lifecycle changes. The candidate's UID, namespace, cluster, resolved plan,
// participant membership, and strict future expiry therefore form one
// fail-closed mutation fence.
func (h *KubectlDebugHandler) liveSessionForMutation(
	ctx context.Context,
	candidate *breakglassv1alpha1.DebugSession,
	user string,
) (*breakglassv1alpha1.DebugSession, error) {
	if candidate == nil || candidate.Namespace == "" || candidate.Name == "" || candidate.UID == "" {
		return nil, kubectlDebugPolicyErrorf("debug session identity is incomplete")
	}
	reader := h.reader
	if reader == nil {
		reader = h.client
	}
	if reader == nil {
		return nil, kubectlDebugInternalErrorf("debug session live reader is not configured")
	}

	live := &breakglassv1alpha1.DebugSession{}
	if err := reader.Get(ctx, ctrlclient.ObjectKey{Namespace: candidate.Namespace, Name: candidate.Name}, live); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, kubectlDebugPolicyErrorf("debug session no longer exists")
		}
		return nil, kubectlDebugInternalErrorf("read live debug session %s/%s: %w", candidate.Namespace, candidate.Name, err)
	}
	if live.UID == "" || live.UID != candidate.UID || live.Namespace != candidate.Namespace ||
		live.Spec.Cluster == "" || live.Spec.Cluster != candidate.Spec.Cluster ||
		!apiequality.Semantic.DeepEqual(live.Status.ResolvedTemplate, candidate.Status.ResolvedTemplate) {
		return nil, kubectlDebugPolicyErrorf("debug session changed during mutation authorization")
	}
	if !live.DeletionTimestamp.IsZero() || live.Status.State != breakglassv1alpha1.DebugSessionStateActive ||
		live.Status.ExpiresAt == nil || !time.Now().UTC().Before(live.Status.ExpiresAt.Time) {
		return nil, kubectlDebugPolicyErrorf("debug session is no longer active")
	}
	if live.Spec.RequestedBy != user {
		allowed := false
		for _, participant := range live.Status.Participants {
			if participant.User == user && participant.LeftAt == nil &&
				(participant.Role == breakglassv1alpha1.ParticipantRoleOwner || participant.Role == breakglassv1alpha1.ParticipantRoleParticipant) {
				allowed = true
				break
			}
		}
		if !allowed {
			return nil, kubectlDebugPolicyErrorf("user is not an active debug-session participant")
		}
	}
	return live, nil
}

func (h *KubectlDebugHandler) privilegedOperationClient(
	ctx context.Context,
	clusterName string,
) (ctrlclient.Client, *breakglassv1alpha1.ClusterConfig, error) {
	if h.ccProvider == nil {
		return nil, nil, kubectlDebugInternalErrorf("target cluster client provider is not configured")
	}
	targetClient, configured, err := h.ccProvider.GetClientForPrivilegedOperation(ctx, clusterName)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to get client for cluster %s: %w", clusterName, err)
	}
	if targetClient == nil || configured == nil || configured.UID == "" {
		return nil, nil, kubectlDebugInternalErrorf("privileged target client for cluster %s is incomplete", clusterName)
	}
	return targetClient, configured, nil
}

func (h *KubectlDebugHandler) fencePrivilegedOperationClusterConfig(
	ctx context.Context,
	configured *breakglassv1alpha1.ClusterConfig,
) error {
	if err := h.ccProvider.ValidatePrivilegedOperationClusterConfig(ctx, configured); err != nil {
		return kubectlDebugPolicyErrorf("target cluster configuration changed during mutation authorization: %w", err)
	}
	return nil
}

func releasePrivilegedOperationSnapshot(provider ClientProviderInterface, configured *breakglassv1alpha1.ClusterConfig) {
	if releaser, ok := provider.(interface {
		ReleasePrivilegedOperationClusterConfig(*breakglassv1alpha1.ClusterConfig)
	}); ok {
		releaser.ReleasePrivilegedOperationClusterConfig(configured)
	}
}

// ValidateEphemeralContainerRequest validates an ephemeral container injection request
func (h *KubectlDebugHandler) ValidateEphemeralContainerRequest(
	ctx context.Context,
	ds *breakglassv1alpha1.DebugSession,
	namespace, podName, image string,
	capabilities []string,
	runAsNonRoot bool,
	privileged bool,
) error {
	template := ds.Status.ResolvedTemplate
	if template == nil {
		return kubectlDebugRequestErrorf("no resolved template in session")
	}

	if template.KubectlDebug == nil || template.KubectlDebug.EphemeralContainers == nil {
		return kubectlDebugRequestErrorf("ephemeral containers not configured in template")
	}

	ec := template.KubectlDebug.EphemeralContainers
	if !ec.Enabled {
		return kubectlDebugRequestErrorf("ephemeral containers are not enabled for this template")
	}

	// Validate namespace
	namespaceAllowed, err := h.isNamespaceAllowedForEphemeral(ctx, ds, namespace, ec.AllowedNamespaces, ec.DeniedNamespaces)
	if err != nil {
		return err
	}
	if !namespaceAllowed {
		return kubectlDebugPolicyErrorf("namespace %s is not allowed for ephemeral container injection", namespace)
	}

	// Validate image
	if !h.isImageAllowed(image, ec.AllowedImages) {
		return kubectlDebugPolicyErrorf("image %s is not in the allowed list", image)
	}

	// Validate image digest if required
	if ec.RequireImageDigest && !h.hasImageDigest(image) {
		return kubectlDebugPolicyErrorf("image must use @sha256: digest")
	}

	// Validate capabilities
	for _, cap := range capabilities {
		if !h.isCapabilityAllowed(cap, ec.MaxCapabilities) {
			return kubectlDebugPolicyErrorf("capability %s is not allowed", cap)
		}
	}

	// Validate privileged mode
	if privileged && !ec.AllowPrivileged {
		return kubectlDebugPolicyErrorf("privileged ephemeral containers are not allowed")
	}

	// Validate non-root
	if ec.RequireNonRoot && !runAsNonRoot {
		return kubectlDebugPolicyErrorf("ephemeral container must run as non-root")
	}

	return nil
}

// InjectEphemeralContainer injects an ephemeral debug container into a pod
func (h *KubectlDebugHandler) InjectEphemeralContainer(
	ctx context.Context,
	ds *breakglassv1alpha1.DebugSession,
	namespace, podName, containerName, image string,
	command []string,
	securityContext *corev1.SecurityContext,
	user string,
) error {
	// The API handler's initial read is only a candidate. Fence again before
	// reading or mutating the target cluster, then use the live object for both
	// validation state and status merge.
	live, err := h.liveSessionForMutation(ctx, ds, user)
	if err != nil {
		return err
	}
	ds = live

	// Resolve the target client together with the exact live ClusterConfig that
	// produced it. The same snapshot is checked again at the final write boundary.
	targetClient, configuredCluster, err := h.privilegedOperationClient(ctx, ds.Spec.Cluster)
	if err != nil {
		return err
	}
	defer releasePrivilegedOperationSnapshot(h.ccProvider, configuredCluster)

	// A previous request may have successfully changed the target Pod but lost
	// the follow-up status write. Resolve that durable intent before accepting a
	// new mutation request, so retries are idempotent and never duplicate a
	// completed ephemeral container.
	if err := h.RecoverPendingKubectlDebugOperations(ctx, ds); err != nil {
		return err
	}

	// Get the target pod
	pod := &corev1.Pod{}
	if err := targetClient.Get(ctx, ctrlclient.ObjectKey{Namespace: namespace, Name: podName}, pod); err != nil {
		return fmt.Errorf("failed to get pod %s/%s: %w", namespace, podName, err)
	}
	if pod.UID == "" {
		return kubectlDebugPolicyErrorf("target pod %s/%s has no UID", namespace, podName)
	}
	// Re-read the target Pod and complete its identity checks before the final
	// authorization fence. No target read may occur after the live session check.
	freshPod := &corev1.Pod{}
	if err := targetClient.Get(ctx, ctrlclient.ObjectKey{Namespace: namespace, Name: podName}, freshPod); err != nil {
		return fmt.Errorf("failed to re-read pod %s/%s before injection: %w", namespace, podName, err)
	}
	if freshPod.UID == "" || freshPod.UID != pod.UID {
		return kubectlDebugPolicyErrorf("target pod %s/%s changed during injection authorization", namespace, podName)
	}
	if pod.ResourceVersion != "" && freshPod.ResourceVersion != "" && freshPod.ResourceVersion != pod.ResourceVersion {
		return kubectlDebugPolicyErrorf("target pod %s/%s changed during injection authorization", namespace, podName)
	}
	// Namespace labels and policy may change while the target Pod is read.
	template := ds.Status.ResolvedTemplate
	if template == nil || template.KubectlDebug == nil || template.KubectlDebug.EphemeralContainers == nil {
		return kubectlDebugPolicyErrorf("ephemeral container policy is no longer available")
	}
	ecPolicy := template.KubectlDebug.EphemeralContainers
	namespaceAllowed, err := h.isNamespaceAllowedForEphemeral(ctx, ds, namespace, ecPolicy.AllowedNamespaces, ecPolicy.DeniedNamespaces)
	if err != nil {
		return err
	}
	if !namespaceAllowed {
		return kubectlDebugPolicyErrorf("namespace %s is no longer allowed for ephemeral container injection", namespace)
	}
	// Create ephemeral container spec
	ephemeralContainer := desiredEphemeralContainerForIntent(containerName, image, command, securityContext)
	if recovered := findMatchingEphemeralOperation(
		&ds.Status,
		namespace,
		podName,
		pod.UID,
		containerName,
		image,
		command,
		ephemeralContainer.SecurityContext,
	); recovered != nil && recovered.State == breakglassv1alpha1.KubectlDebugOperationCompleted {
		return nil
	}
	for _, ec := range freshPod.Spec.EphemeralContainers {
		if ec.Name == containerName {
			return fmt.Errorf("ephemeral container %s already exists in pod", containerName)
		}
	}
	// Add the ephemeral container to the request object. The target API has not
	// been mutated yet; the durable operation intent below is persisted first.
	freshPod.Spec.EphemeralContainers = append(freshPod.Spec.EphemeralContainers, ephemeralContainer)

	// This must be the last slow operation before the target mutation. Any
	// expiry, revocation, participant removal, or approved-plan change observed
	// here prevents the update; native Kubernetes requests already admitted by
	// the target API remain outside this boundary. The operation intent is
	// written immediately after this fence and before the target API call.
	live, err = h.liveSessionForMutation(ctx, ds, user)
	if err != nil {
		return err
	}
	ds = live
	operation := newEphemeralContainerOperation(freshPod, ephemeralContainer, user)
	if err := h.prepareEphemeralContainerOperation(ctx, ds, operation); err != nil {
		// No target mutation has happened if durable intent cannot be written.
		return fmt.Errorf("failed to persist ephemeral-container operation intent: %w", err)
	}

	// Persisting intent is itself a potentially slow API operation. Re-fence
	// after it succeeds so an operation that crossed expiry is never admitted;
	// the prepared intent remains for the controller to mark failed.
	live, err = h.liveSessionForMutation(ctx, ds, user)
	if err != nil {
		return err
	}
	ds = live
	if err := h.fencePrivilegedOperationClusterConfig(ctx, configuredCluster); err != nil {
		return err
	}

	// Update the pod using SubResource for ephemeral containers
	if err := targetClient.SubResource("ephemeralcontainers").Update(ctx, freshPod); err != nil {
		return fmt.Errorf("failed to inject ephemeral container: %w", err)
	}

	// Track the injected container in session status
	now := metav1.Now()
	injectedContainer := breakglassv1alpha1.EphemeralContainerRef{
		PodName:       podName,
		Namespace:     namespace,
		ContainerName: containerName,
		Image:         image,
		InjectedAt:    now,
		InjectedBy:    user,
	}
	if err := h.completeEphemeralContainerOperation(ctx, ds, operation.ID, breakglassv1alpha1.KubectlDebugOperationCompleted, "", &injectedContainer); err != nil {
		// The target update has already happened. The prepared operation remains
		// durable in status and will be resolved by the next reconciliation or
		// retry, so this path never leaves an untracked mutation.
		return fmt.Errorf("failed to persist ephemeral-container operation outcome: %w", err)
	}
	return nil
}

// CreatePodCopy creates a debug copy of a pod
func (h *KubectlDebugHandler) CreatePodCopy(
	ctx context.Context,
	ds *breakglassv1alpha1.DebugSession,
	originalNamespace, originalPodName string,
	debugImage string,
	user string,
) (*corev1.Pod, error) {
	live, err := h.liveSessionForMutation(ctx, ds, user)
	if err != nil {
		return nil, err
	}
	ds = live
	template := ds.Status.ResolvedTemplate
	if template == nil || template.KubectlDebug == nil || template.KubectlDebug.PodCopy == nil {
		return nil, kubectlDebugRequestErrorf("pod copy not configured in template")
	}

	pc := template.KubectlDebug.PodCopy
	if !pc.Enabled {
		return nil, kubectlDebugRequestErrorf("pod copy is not enabled for this template")
	}

	// Resolve the target client and retain the exact live ClusterConfig used.
	targetClient, configuredCluster, err := h.privilegedOperationClient(ctx, ds.Spec.Cluster)
	if err != nil {
		return nil, err
	}
	defer releasePrivilegedOperationSnapshot(h.ccProvider, configuredCluster)

	nsLabels, err := h.fetchNamespaceLabels(ctx, targetClient, originalNamespace)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch namespace labels for %s: %w", originalNamespace, err)
	}
	matcher := utils.NewNamespaceAllowDenyMatcher(pc.AllowedNamespaces, pc.DeniedNamespaces)
	if !matcher.IsAllowedWithLabels(originalNamespace, nsLabels) {
		return nil, kubectlDebugPolicyErrorf("namespace %s is not allowed for pod copy", originalNamespace)
	}

	// Get the original pod
	originalPod := &corev1.Pod{}
	if err := targetClient.Get(ctx, ctrlclient.ObjectKey{Namespace: originalNamespace, Name: originalPodName}, originalPod); err != nil {
		return nil, fmt.Errorf("failed to get pod %s/%s: %w", originalNamespace, originalPodName, err)
	}

	// Determine target namespace
	targetNs := pc.TargetNamespace
	if targetNs == "" {
		targetNs = "debug-copies"
	}

	// Ensure target namespace exists
	ns := &corev1.Namespace{}
	if err := targetClient.Get(ctx, ctrlclient.ObjectKey{Name: targetNs}, ns); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, kubectlDebugRequestErrorf("target namespace %s does not exist", targetNs)
		}
		return nil, fmt.Errorf("failed to check namespace: %w", err)
	}
	if ns.UID == "" {
		return nil, kubectlDebugPolicyErrorf("target namespace %s has no UID", targetNs)
	}

	// Create copy name
	copyName := fmt.Sprintf("debug-copy-%s-%s", originalPodName, ds.Name[:8])
	if len(copyName) > 63 {
		copyName = copyName[:63]
	}

	// Build the copy pod spec
	copyPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      copyName,
			Namespace: targetNs,
			Labels: map[string]string{
				DebugSessionLabelKey:                 ds.Name,
				"breakglass.telekom.com/debug-copy":  "true",
				"breakglass.telekom.com/original":    originalPodName,
				"breakglass.telekom.com/original-ns": originalNamespace,
			},
			Annotations: map[string]string{
				sourceSessionUIDAnnotation:  string(ds.UID),
				createOperationIDAnnotation: uuid.NewString(),
			},
		},
		Spec: *originalPod.Spec.DeepCopy(),
	}

	// Add custom labels from config
	for k, v := range pc.Labels {
		copyPod.Labels[k] = v
	}

	// Modify for debugging
	copyPod.Spec.RestartPolicy = corev1.RestartPolicyNever

	// Add debug container if image specified
	if debugImage != "" {
		debugContainer := corev1.Container{
			Name:    "debugger",
			Image:   debugImage,
			Command: []string{"sleep", "infinity"},
			TTY:     true,
			Stdin:   true,
		}
		copyPod.Spec.Containers = append(copyPod.Spec.Containers, debugContainer)
	}

	// Reset status-related fields
	copyPod.Spec.NodeName = ""
	copyPod.ResourceVersion = ""
	copyPod.UID = ""

	// Re-read the source Pod and complete its identity checks before the final
	// authorization fence. No target read may occur after the live session check.
	freshOriginalPod := &corev1.Pod{}
	if err := targetClient.Get(ctx, ctrlclient.ObjectKey{Namespace: originalNamespace, Name: originalPodName}, freshOriginalPod); err != nil {
		return nil, fmt.Errorf("failed to re-read pod %s/%s before copy: %w", originalNamespace, originalPodName, err)
	}
	if freshOriginalPod.UID == "" || originalPod.UID == "" || freshOriginalPod.UID != originalPod.UID {
		return nil, kubectlDebugPolicyErrorf("source pod %s/%s changed during copy authorization", originalNamespace, originalPodName)
	}
	if originalPod.ResourceVersion != "" && freshOriginalPod.ResourceVersion != "" && freshOriginalPod.ResourceVersion != originalPod.ResourceVersion {
		return nil, kubectlDebugPolicyErrorf("source pod %s/%s changed during copy authorization", originalNamespace, originalPodName)
	}
	freshNamespaceLabels, err := h.fetchNamespaceLabels(ctx, targetClient, originalNamespace)
	if err != nil {
		return nil, fmt.Errorf("failed to re-read namespace labels for %s before copy: %w", originalNamespace, err)
	}
	if !matcher.IsAllowedWithLabels(originalNamespace, freshNamespaceLabels) {
		return nil, kubectlDebugPolicyErrorf("namespace %s is no longer allowed for pod copy", originalNamespace)
	}

	// Re-read the destination namespace at the privileged boundary as well. The
	// source policy above answers who may be copied; this identity check answers
	// where the privileged copy is about to be created.
	freshTargetNamespace := &corev1.Namespace{}
	if err := targetClient.Get(ctx, ctrlclient.ObjectKey{Name: targetNs}, freshTargetNamespace); err != nil {
		return nil, fmt.Errorf("failed to re-read target namespace %s before copy: %w", targetNs, err)
	}
	if freshTargetNamespace.UID == "" || freshTargetNamespace.UID != ns.UID {
		return nil, kubectlDebugPolicyErrorf("target namespace %s changed during copy authorization", targetNs)
	}

	// Validate all target configuration and policy inputs first. The uncached
	// session fence below is then the last slow operation before the create.
	if err := h.fencePrivilegedOperationClusterConfig(ctx, configuredCluster); err != nil {
		return nil, err
	}
	live, err = h.liveSessionForMutation(ctx, ds, user)
	if err != nil {
		return nil, err
	}
	ds = live

	// Create the copy pod using Create (not SSA). An admission-time namespace
	// label change can still race this call; the target cluster's admission
	// policy remains the final authority for that unavoidable API boundary.
	if err := targetClient.Create(ctx, copyPod); err != nil {
		h.recoverAmbiguousCreatedPod(ctx, targetClient, copyPod, err)
		return nil, fmt.Errorf("failed to create pod copy: %w", err)
	}

	// Calculate expiry (supports day units like "1d")
	ttl := pc.TTL
	if ttl == "" {
		ttl = "2h"
	}
	ttlDuration, err := breakglassv1alpha1.ParseDuration(ttl)
	if err != nil {
		ttlDuration = 2 * time.Hour
	}
	expiresAt := metav1.NewTime(time.Now().UTC().Add(ttlDuration))

	// Track the copied pod in session status
	now := metav1.Now()
	copiedPod := breakglassv1alpha1.CopiedPodRef{
		OriginalPod:       originalPodName,
		OriginalNamespace: originalNamespace,
		CopyName:          copyName,
		CopyNamespace:     targetNs,
		CreatedAt:         now,
		ExpiresAt:         &expiresAt,
		UID:               string(copyPod.UID),
	}
	allowedPod := breakglassv1alpha1.AllowedPodRef{
		Namespace: targetNs,
		Name:      copyName,
		Ready:     false, // Will be updated by reconciler
	}

	if err := h.patchDebugSessionStatusWithRetry(ctx, ds, func(status *breakglassv1alpha1.DebugSessionStatus) {
		kubectlStatus := ensureKubectlDebugStatus(status)
		alreadyTracked := false
		for _, existing := range kubectlStatus.CopiedPods {
			if existing.CopyNamespace == copiedPod.CopyNamespace && existing.CopyName == copiedPod.CopyName {
				alreadyTracked = true
				break
			}
		}
		if !alreadyTracked {
			kubectlStatus.CopiedPods = append(kubectlStatus.CopiedPods, copiedPod)
		}

		addAllowedPodIfMissing(status, allowedPod)
	}); err != nil {
		// The pod exists on the spoke but is absent from the status lists that
		// cleanup iterates, so it would never be reclaimed. Delete it so
		// create+track is atomic-or-cleaned-up.
		h.deleteOrphanedPod(ctx, targetClient, copyPod, err)
		return nil, fmt.Errorf("failed to update session status: %w", err)
	}

	return copyPod, nil
}

// CreateNodeDebugPod creates a debug pod on a specific node
func (h *KubectlDebugHandler) CreateNodeDebugPod(
	ctx context.Context,
	ds *breakglassv1alpha1.DebugSession,
	nodeName string,
	user string,
) (*corev1.Pod, error) {
	live, err := h.liveSessionForMutation(ctx, ds, user)
	if err != nil {
		return nil, err
	}
	ds = live
	template := ds.Status.ResolvedTemplate
	if template == nil || template.KubectlDebug == nil || template.KubectlDebug.NodeDebug == nil {
		return nil, kubectlDebugRequestErrorf("node debug not configured in template")
	}

	nd := template.KubectlDebug.NodeDebug
	if !nd.Enabled {
		return nil, kubectlDebugRequestErrorf("node debug is not enabled for this template")
	}

	// Get the target cluster client and node before evaluating the selector. The
	// node UID is retained for the final identity fence immediately before Pod
	// creation, including when no selector is configured.
	targetClient, configuredCluster, err := h.privilegedOperationClient(ctx, ds.Spec.Cluster)
	if err != nil {
		return nil, err
	}
	defer releasePrivilegedOperationSnapshot(h.ccProvider, configuredCluster)
	node := &corev1.Node{}
	if err := targetClient.Get(ctx, ctrlclient.ObjectKey{Name: nodeName}, node); err != nil {
		return nil, fmt.Errorf("failed to get node %s: %w", nodeName, err)
	}

	// Validate node selector if configured
	if len(nd.NodeSelector) > 0 {
		// Check node selector
		for k, v := range nd.NodeSelector {
			if nodeVal, exists := node.Labels[k]; !exists || nodeVal != v {
				return nil, kubectlDebugPolicyErrorf("node %s does not match required selector %s=%s", nodeName, k, v)
			}
		}
	}

	// Determine image
	image := "busybox:stable"
	if len(nd.AllowedImages) > 0 {
		image = nd.AllowedImages[0]
	}

	// Build host namespace config
	hostNetwork := true
	hostPID := true
	hostIPC := false
	if nd.HostNamespaces != nil {
		hostNetwork = nd.HostNamespaces.HostNetwork
		hostPID = nd.HostNamespaces.HostPID
		hostIPC = nd.HostNamespaces.HostIPC
	}

	// Create the debug pod
	podName := fmt.Sprintf("node-debugger-%s-%s", nodeName, ds.Name[:8])
	if len(podName) > 63 {
		podName = podName[:63]
	}

	// Determine namespace from the resolved session namespace, then template, then default.
	namespace := ds.Spec.TargetNamespace
	if namespace == "" && template.TargetNamespace != "" {
		namespace = template.TargetNamespace
	}
	if namespace == "" {
		namespace = "breakglass-debug"
	}
	targetNamespace := &corev1.Namespace{}
	if err := targetClient.Get(ctx, ctrlclient.ObjectKey{Name: namespace}, targetNamespace); err != nil {
		return nil, fmt.Errorf("failed to get node debug namespace %s: %w", namespace, err)
	}
	if targetNamespace.UID == "" {
		return nil, kubectlDebugPolicyErrorf("node debug namespace %s has no UID", namespace)
	}
	if !namespaceAllowedForDebugPod(namespace, targetNamespace.Labels, template.NamespaceConstraints) {
		return nil, kubectlDebugPolicyErrorf("namespace %s is not allowed for node debug", namespace)
	}

	debugPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      podName,
			Namespace: namespace,
			Labels: map[string]string{
				DebugSessionLabelKey:                  ds.Name,
				"breakglass.telekom.com/node-debug":   "true",
				"breakglass.telekom.com/target-node":  nodeName,
				"breakglass.telekom.com/requested-by": sanitizeLabel(user),
			},
			Annotations: map[string]string{
				sourceSessionUIDAnnotation:  string(ds.UID),
				createOperationIDAnnotation: uuid.NewString(),
			},
		},
		Spec: corev1.PodSpec{
			NodeName:      nodeName,
			HostNetwork:   hostNetwork,
			HostPID:       hostPID,
			HostIPC:       hostIPC,
			RestartPolicy: corev1.RestartPolicyNever,
			Containers: []corev1.Container{
				{
					Name:    "debugger",
					Image:   image,
					Command: []string{"sleep", "infinity"},
					TTY:     true,
					Stdin:   true,
					SecurityContext: &corev1.SecurityContext{
						Privileged: boolPtr(true),
					},
					VolumeMounts: []corev1.VolumeMount{
						{
							Name:      "host-root",
							MountPath: "/host",
							ReadOnly:  false,
						},
					},
				},
			},
			Volumes: []corev1.Volume{
				{
					Name: "host-root",
					VolumeSource: corev1.VolumeSource{
						HostPath: &corev1.HostPathVolumeSource{
							Path: "/",
						},
					},
				},
			},
			Tolerations: []corev1.Toleration{
				{
					Operator: corev1.TolerationOpExists,
				},
			},
		},
	}

	// Re-read the target Node and complete its identity checks before the final
	// authorization fence. No target read may occur after the live session check.
	freshNode := &corev1.Node{}
	if err := targetClient.Get(ctx, ctrlclient.ObjectKey{Name: nodeName}, freshNode); err != nil {
		return nil, fmt.Errorf("failed to re-read node %s before debug pod creation: %w", nodeName, err)
	}
	if node.UID == "" || freshNode.UID == "" || node.UID != freshNode.UID {
		return nil, kubectlDebugPolicyErrorf("node %s changed during debug pod authorization", nodeName)
	}
	if node.ResourceVersion != "" && freshNode.ResourceVersion != "" && freshNode.ResourceVersion != node.ResourceVersion {
		return nil, kubectlDebugPolicyErrorf("node %s changed during debug pod authorization", nodeName)
	}
	for k, v := range nd.NodeSelector {
		if nodeVal, exists := freshNode.Labels[k]; !exists || nodeVal != v {
			return nil, kubectlDebugPolicyErrorf("node %s no longer matches required selector %s=%s", nodeName, k, v)
		}
	}
	freshTargetNamespace := &corev1.Namespace{}
	if err := targetClient.Get(ctx, ctrlclient.ObjectKey{Name: namespace}, freshTargetNamespace); err != nil {
		return nil, fmt.Errorf("failed to re-read node debug namespace %s before pod creation: %w", namespace, err)
	}
	if freshTargetNamespace.UID == "" || freshTargetNamespace.UID != targetNamespace.UID {
		return nil, kubectlDebugPolicyErrorf("node debug namespace %s changed during pod authorization", namespace)
	}
	if !namespaceAllowedForDebugPod(namespace, freshTargetNamespace.Labels, template.NamespaceConstraints) {
		return nil, kubectlDebugPolicyErrorf("namespace %s is no longer allowed for node debug", namespace)
	}

	// Validate all target configuration and policy inputs first. The uncached
	// session fence below is then the last slow operation before the create.
	if err := h.fencePrivilegedOperationClusterConfig(ctx, configuredCluster); err != nil {
		return nil, err
	}
	live, err = h.liveSessionForMutation(ctx, ds, user)
	if err != nil {
		return nil, err
	}
	ds = live

	// Create the pod using Create (not SSA). The explicit NodeName binds this
	// mutation to the re-read node identity; target admission remains authoritative.
	if err := targetClient.Create(ctx, debugPod); err != nil {
		h.recoverAmbiguousCreatedPod(ctx, targetClient, debugPod, err)
		return nil, fmt.Errorf("failed to create node debug pod: %w", err)
	}

	// Add to allowed pods and deployed resources
	allowedPod := breakglassv1alpha1.AllowedPodRef{
		Namespace: namespace,
		Name:      podName,
		NodeName:  nodeName,
		Ready:     false, // Will be updated by reconciler
	}
	deployedResource := breakglassv1alpha1.DeployedResourceRef{
		APIVersion: "v1",
		Kind:       "Pod",
		Name:       podName,
		Namespace:  namespace,
		UID:        string(debugPod.UID),
	}

	if err := h.patchDebugSessionStatusWithRetry(ctx, ds, func(status *breakglassv1alpha1.DebugSessionStatus) {
		addAllowedPodIfMissing(status, allowedPod)
		addDeployedResourceIfMissing(status, deployedResource)
	}); err != nil {
		// This pod is privileged with hostPath "/" mounted read-write. Leaving it
		// untracked means it outlives its session with no cleanup path at all, so
		// the create must be rolled back.
		h.deleteOrphanedPod(ctx, targetClient, debugPod, err)
		return nil, fmt.Errorf("failed to update session status: %w", err)
	}

	return debugPod, nil
}

// recoverAmbiguousCreatedPod handles a create response that may have been lost
// after the API server persisted the pod. It intentionally skips AlreadyExists:
// that error identifies a pre-existing object and must never trigger deletion.
// For other errors, only a live object carrying this session's immutable marker
// is eligible, and the observed UID is passed as an API delete precondition.
func (h *KubectlDebugHandler) recoverAmbiguousCreatedPod(ctx context.Context, targetClient ctrlclient.Client, pod *corev1.Pod, createErr error) {
	log := zap.S().Named("kubectl-debug")
	if pod == nil || !isAmbiguousCreateError(createErr) || pod.Annotations[sourceSessionUIDAnnotation] == "" || pod.Annotations[createOperationIDAnnotation] == "" {
		return
	}
	cleanupCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), orphanCleanupTimeout)
	defer cancel()
	live := &corev1.Pod{}
	if err := targetClient.Get(cleanupCtx, ctrlclient.ObjectKeyFromObject(pod), live); err != nil {
		if !apierrors.IsNotFound(err) {
			log.Errorw("Failed to inspect pod after ambiguous create failure", "pod", pod.Name, "podNamespace", pod.Namespace, "createError", createErr, "getError", err)
		}
		return
	}
	if live.UID == "" || live.Annotations[sourceSessionUIDAnnotation] != pod.Annotations[sourceSessionUIDAnnotation] || live.Annotations[createOperationIDAnnotation] != pod.Annotations[createOperationIDAnnotation] {
		log.Warnw("Preserved pod after ambiguous create failure because ownership could not be verified", "pod", pod.Name, "podNamespace", pod.Namespace, "createError", createErr)
		return
	}
	uidPrecondition := metav1.NewUIDPreconditions(string(live.UID))
	if err := targetClient.Delete(cleanupCtx, live, ctrlclient.Preconditions(*uidPrecondition)); err != nil && !apierrors.IsNotFound(err) {
		log.Errorw("Failed to remove pod after ambiguous create failure", "pod", pod.Name, "podNamespace", pod.Namespace, "createError", createErr, "deleteError", err)
	}
}

func isAmbiguousCreateError(err error) bool {
	if err == nil || apierrors.IsAlreadyExists(err) || apierrors.IsForbidden(err) || apierrors.IsInvalid(err) || apierrors.IsUnauthorized(err) || apierrors.IsNotFound(err) {
		return false
	}
	if apierrors.IsTimeout(err) || apierrors.IsServerTimeout(err) || errors.Is(err, context.DeadlineExceeded) {
		return true
	}
	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return true
	}
	var urlErr *url.Error
	return errors.As(err, &urlErr) && urlErr.Timeout()
}

func namespaceAllowedForDebugPod(namespace string, labels map[string]string, constraints *breakglassv1alpha1.NamespaceConstraints) bool {
	if constraints == nil {
		return true
	}
	if constraints.AllowedNamespaces.IsEmpty() {
		if namespace != constraints.DefaultNamespace {
			return false
		}
	} else if !utils.NewNamespaceMatcher(constraints.AllowedNamespaces).MatchesWithLabels(namespace, labels) {
		return false
	}
	return constraints.DeniedNamespaces.IsEmpty() ||
		!utils.NewNamespaceMatcher(constraints.DeniedNamespaces).MatchesWithLabels(namespace, labels)
}

// CleanupKubectlDebugResources cleans up kubectl-debug resources
func (h *KubectlDebugHandler) CleanupKubectlDebugResources(ctx context.Context, ds *breakglassv1alpha1.DebugSession) error {
	if ds.Status.KubectlDebugStatus == nil {
		return nil
	}
	if err := h.RecoverPendingKubectlDebugOperations(ctx, ds); err != nil {
		return fmt.Errorf("recover pending kubectl-debug operations before cleanup: %w", err)
	}

	if len(ds.Status.KubectlDebugStatus.CopiedPods) == 0 {
		// Ephemeral containers cannot be removed; without copied pods there is
		// no spoke-cluster cleanup to perform.
		return h.patchDebugSessionStatusWithRetry(ctx, ds, func(status *breakglassv1alpha1.DebugSessionStatus) {
			status.KubectlDebugStatus = cleanupRetainedKubectlDebugStatus(status.KubectlDebugStatus)
		})
	}

	targetClient, err := h.ccProvider.GetClient(ctx, ds.Spec.Cluster)
	if err != nil {
		return fmt.Errorf("failed to get client for cluster %s: %w", ds.Spec.Cluster, err)
	}

	var cleanupErrors []error
	remainingCopiedPods := make([]breakglassv1alpha1.CopiedPodRef, 0, len(ds.Status.KubectlDebugStatus.CopiedPods))

	// Cleanup copied pods
	for _, cp := range ds.Status.KubectlDebugStatus.CopiedPods {
		pod := &corev1.Pod{
			ObjectMeta: metav1.ObjectMeta{
				Name:      cp.CopyName,
				Namespace: cp.CopyNamespace,
			},
		}
		if err := deleteOwnedResource(ctx, targetClient, pod, cp.UID, ds); err != nil && !apierrors.IsNotFound(err) {
			remainingCopiedPods = append(remainingCopiedPods, cp)
			cleanupErrors = append(cleanupErrors, fmt.Errorf("delete copied pod %s/%s: %w", cp.CopyNamespace, cp.CopyName, err))
			continue
		}
	}

	// Note: Ephemeral containers cannot be removed, they remain until pod deletion
	if len(remainingCopiedPods) > 0 {
		if err := h.patchDebugSessionStatusWithRetry(ctx, ds, func(status *breakglassv1alpha1.DebugSessionStatus) {
			if status.KubectlDebugStatus == nil {
				status.KubectlDebugStatus = &breakglassv1alpha1.KubectlDebugStatus{}
			}
			status.KubectlDebugStatus.CopiedPods = remainingCopiedPods
		}); err != nil {
			cleanupErrors = append(cleanupErrors, fmt.Errorf("preserve kubectl-debug cleanup status: %w", err))
		}
		return errors.Join(cleanupErrors...)
	}

	return h.patchDebugSessionStatusWithRetry(ctx, ds, func(status *breakglassv1alpha1.DebugSessionStatus) {
		status.KubectlDebugStatus = cleanupRetainedKubectlDebugStatus(status.KubectlDebugStatus)
	})
}

// Helper functions

func (h *KubectlDebugHandler) isNamespaceAllowed(namespace string, allowed, denied *breakglassv1alpha1.NamespaceFilter) bool {
	// Use NamespaceAllowDenyMatcher for combined allow/deny logic
	matcher := utils.NewNamespaceAllowDenyMatcher(allowed, denied)
	return matcher.IsAllowed(namespace)
}

func (h *KubectlDebugHandler) isNamespaceAllowedForEphemeral(
	ctx context.Context,
	ds *breakglassv1alpha1.DebugSession,
	namespace string,
	allowed, denied *breakglassv1alpha1.NamespaceFilter,
) (bool, error) {
	matcher := utils.NewNamespaceAllowDenyMatcher(allowed, denied)
	if !namespaceFilterRequiresLabels(allowed) && !namespaceFilterRequiresLabels(denied) {
		return matcher.IsAllowed(namespace), nil
	}
	targetClient := h.client
	if h.ccProvider != nil {
		var err error
		targetClient, err = h.ccProvider.GetClient(ctx, ds.Spec.Cluster)
		if err != nil {
			return false, kubectlDebugInternalErrorf("failed to get client for cluster %s: %w", ds.Spec.Cluster, err)
		}
	}
	if targetClient == nil {
		return false, kubectlDebugInternalErrorf("failed to fetch namespace labels for %s: kubernetes client is not configured", namespace)
	}
	nsLabels, err := h.fetchNamespaceLabels(ctx, targetClient, namespace)
	if err != nil {
		if apierrors.IsNotFound(err) {
			return false, kubectlDebugRequestErrorf("namespace %s not found", namespace)
		}
		return false, kubectlDebugInternalErrorf("failed to fetch namespace labels for %s: %w", namespace, err)
	}
	return matcher.IsAllowedWithLabels(namespace, nsLabels), nil
}

func namespaceFilterRequiresLabels(filter *breakglassv1alpha1.NamespaceFilter) bool {
	return filter != nil && filter.HasSelectorTerms()
}

func (h *KubectlDebugHandler) fetchNamespaceLabels(ctx context.Context, cl ctrlclient.Client, namespace string) (map[string]string, error) {
	ns := &corev1.Namespace{}
	if err := cl.Get(ctx, ctrlclient.ObjectKey{Name: namespace}, ns); err != nil {
		return nil, err
	}
	return ns.Labels, nil
}

func (h *KubectlDebugHandler) isImageAllowed(image string, allowed []string) bool {
	if len(allowed) == 0 {
		return true // No restrictions
	}

	for _, pattern := range allowed {
		// Handle digest patterns (image@sha256:*)
		if strings.Contains(pattern, "@sha256:*") {
			base := strings.Split(pattern, "@")[0]
			if strings.HasPrefix(image, base+"@sha256:") {
				return true
			}
		}

		// Standard glob matching
		if matched, _ := filepath.Match(pattern, image); matched {
			return true
		}
	}

	return false
}

func (h *KubectlDebugHandler) hasImageDigest(image string) bool {
	return strings.Contains(image, "@sha256:")
}

func (h *KubectlDebugHandler) isCapabilityAllowed(capability string, maxCaps []string) bool {
	if len(maxCaps) == 0 {
		return true // No restrictions
	}

	for _, allowed := range maxCaps {
		if strings.EqualFold(capability, allowed) {
			return true
		}
	}

	return false
}

func boolPtr(b bool) *bool {
	return &b
}

func sanitizeLabel(value string) string {
	// Simple sanitization for Kubernetes label values
	// Replace invalid characters with underscore
	result := strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '_'
	}, value)

	// Truncate to max label length
	if len(result) > 63 {
		result = result[:63]
	}

	return result
}
