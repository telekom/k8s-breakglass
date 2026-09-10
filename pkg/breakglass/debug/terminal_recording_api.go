// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	apiresponses "github.com/telekom/k8s-breakglass/pkg/apiresponses"
	artifactstorage "github.com/telekom/k8s-breakglass/pkg/artifacts/storage"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/remotecommand"
)

const terminalRecordingDefaultRetention = 90 * 24 * time.Hour

const terminalRecordingFinalizeTimeout = 10 * time.Second

// TerminalRecordingConnectionBinding is the immutable authorization tuple
// supplied by the connection-lease service for one target stream.
type TerminalRecordingConnectionBinding struct {
	SessionUID           string
	TargetPodUID         string
	Epoch                string
	Generation           string
	ExpiresAt            time.Time
	RuntimeBindingDigest string
}

// TerminalRecordingConnection is validated before stream creation and again
// before publication. Close must revoke the target connection lease.
type TerminalRecordingConnection interface {
	Binding() TerminalRecordingConnectionBinding
	Validate(context.Context) error
	Close(context.Context) error
}

// TerminalRecordingConnectionProvider is implemented by the controller-owned
// connection lease service. A nil provider never enables recording.
type TerminalRecordingConnectionProvider interface {
	AcquireTerminalRecordingConnection(context.Context, TerminalRecordingConnectionBinding) (TerminalRecordingConnection, error)
}

func (c *DebugSessionAPIController) WithTerminalRecordingStore(store artifactstorage.Store) *DebugSessionAPIController {
	c.recordingStore = store
	return c
}

func (c *DebugSessionAPIController) WithTerminalRecordingConnections(provider TerminalRecordingConnectionProvider) *DebugSessionAPIController {
	c.recordingConnections = provider
	return c
}

func (c *DebugSessionAPIController) handleTerminalRecording(ctx *gin.Context) {
	if c.recordingStore == nil || c.recordingConnections == nil || c.ccProvider == nil {
		apiresponses.RespondServiceUnavailable(ctx, "terminal recording transport is not configured")
		return
	}
	identity, ok := debugSessionRequestIdentity(ctx)
	if !ok {
		apiresponses.RespondUnauthorized(ctx)
		return
	}
	namespace, podName, operation, err := terminalRecordingRequest(ctx)
	if err != nil {
		apiresponses.RespondBadRequest(ctx, err.Error())
		return
	}
	apiCtx, cancel := context.WithCancel(ctx.Request.Context())
	defer cancel()
	session, err := c.getDebugSessionByName(apiCtx, ctx.Param("name"), ctx.Query("namespace"))
	if err != nil {
		if apierrors.IsNotFound(err) {
			apiresponses.RespondNotFoundSimple(ctx, "debug session not found")
			return
		}
		apiresponses.RespondInternalErrorSimple(ctx, "failed to get debug session")
		return
	}
	if session.Status.State != breakglassv1alpha1.DebugSessionStateActive || session.Status.ExpiresAt == nil || !time.Now().Before(session.Status.ExpiresAt.Time) {
		apiresponses.RespondForbidden(ctx, "debug session is not active")
		return
	}
	if session.Status.ResolvedTemplate == nil || session.Status.ResolvedTemplate.Audit == nil || !session.Status.ResolvedTemplate.Audit.EnableTerminalRecording {
		apiresponses.RespondForbidden(ctx, "terminal recording is not required by this session")
		return
	}
	if !c.canUserOperateDebugResources(session, identity) {
		apiresponses.RespondForbidden(ctx, "user is not allowed to record this debug session")
		return
	}
	if !session.Status.AllowedPodOperations.IsOperationAllowed(operation) {
		apiresponses.RespondForbidden(ctx, "terminal operation is not allowed for this session")
		return
	}
	targetUID, ok := allowedTargetPodUID(session, namespace, podName)
	if !ok {
		apiresponses.RespondForbidden(ctx, "target Pod is not allowed by this session")
		return
	}

	restConfig, configured, err := c.ccProvider.GetRESTConfigForPrivilegedOperation(apiCtx, session.Spec.Cluster)
	if err != nil {
		apiresponses.RespondInternalErrorSimple(ctx, "failed to resolve target cluster")
		return
	}
	defer c.ccProvider.ReleasePrivilegedOperationClusterConfig(configured)
	kubeClient, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		apiresponses.RespondInternalErrorSimple(ctx, "failed to create target cluster client")
		return
	}
	pod, err := kubeClient.CoreV1().Pods(namespace).Get(apiCtx, podName, metav1.GetOptions{})
	if err != nil || pod == nil || string(pod.UID) != targetUID {
		apiresponses.RespondForbidden(ctx, "target Pod identity changed")
		return
	}

	binding := TerminalRecordingConnectionBinding{SessionUID: string(session.UID), TargetPodUID: targetUID, ExpiresAt: session.Status.ExpiresAt.Time}
	connection, err := c.recordingConnections.AcquireTerminalRecordingConnection(apiCtx, binding)
	if err != nil {
		apiresponses.RespondForbidden(ctx, "terminal recording connection is not available")
		return
	}
	defer func() {
		closeCtx, closeCancel := context.WithTimeout(context.WithoutCancel(ctx.Request.Context()), 5*time.Second)
		defer closeCancel()
		_ = connection.Close(closeCtx)
	}()
	binding = connection.Binding()
	if !terminalRecordingBindingMatches(binding, session, targetUID) {
		apiresponses.RespondForbidden(ctx, "terminal recording connection binding is invalid")
		return
	}
	if err := connection.Validate(apiCtx); err != nil {
		apiresponses.RespondForbidden(ctx, "terminal recording connection is no longer authorized")
		return
	}

	executor, err := newTerminalRecordingExecutor(restConfig, namespace, podName, operation, ctx.Query("container"), ctx.QueryArray("command"))
	if err != nil {
		apiresponses.RespondBadRequest(ctx, err.Error())
		return
	}
	startedAt := time.Now().UTC()
	recorder := NewTerminalRecorder(defaultTerminalRecordingMaxBytes)
	ctx.Header("Content-Type", "application/octet-stream")
	ctx.Header("Trailer", "X-Breakglass-Recording-ID, X-Breakglass-Recording-SHA256")
	recording, streamErr := StreamTerminal(apiCtx, executor, ctx.Request.Body, ctx.Writer, ctx.Writer, recorder)
	if streamErr != nil {
		apiresponses.RespondBadGateway(ctx, "terminal stream failed")
		return
	}
	finalizeCtx, finalizeCancel := context.WithTimeout(context.WithoutCancel(ctx.Request.Context()), terminalRecordingFinalizeTimeout)
	defer finalizeCancel()
	validatedBinding := connection.Binding()
	if err := connection.Validate(finalizeCtx); err != nil || !terminalRecordingBindingMatches(validatedBinding, session, targetUID) || !terminalRecordingBindingsEqual(validatedBinding, binding) {
		apiresponses.RespondForbidden(ctx, "terminal recording connection expired")
		return
	}
	ref, metadata, err := persistTerminalRecording(finalizeCtx, c.recordingStore, session, pod, operation, ctx.Query("container"), binding, startedAt, recording)
	if err != nil {
		apiresponses.RespondInternalErrorSimple(ctx, "failed to finalize terminal recording")
		return
	}
	if err := c.patchDebugSessionStatusWithOptimisticLock(finalizeCtx, session, func(status *breakglassv1alpha1.DebugSessionStatus) {
		kubectlStatus := ensureKubectlDebugStatus(status)
		kubectlStatus.TerminalRecordings = append(kubectlStatus.TerminalRecordings, ref)
	}); err != nil {
		_ = c.recordingStore.DeleteVersion(finalizeCtx, terminalRecordingObject(ref), artifactstorage.Version{VersionID: metadata.VersionID, RuntimeBindingDigest: metadata.RuntimeBindingDigest, Size: metadata.Size, SHA256: metadata.SHA256, ETag: metadata.ETag, ProviderChecksum: metadata.ProviderChecksum, ModifiedAt: metadata.ModifiedAt})
		apiresponses.RespondInternalErrorSimple(ctx, "failed to record terminal metadata")
		return
	}
	ctx.Header("X-Breakglass-Recording-ID", ref.ID)
	ctx.Header("X-Breakglass-Recording-SHA256", ref.SHA256)
}

func terminalRecordingBindingMatches(binding TerminalRecordingConnectionBinding, session *breakglassv1alpha1.DebugSession, targetUID string) bool {
	return binding.SessionUID == string(session.UID) && binding.TargetPodUID == targetUID && binding.Epoch != "" && binding.Generation != "" && binding.RuntimeBindingDigest != "" && !binding.ExpiresAt.IsZero() && !binding.ExpiresAt.After(session.Status.ExpiresAt.Time) && time.Now().Before(binding.ExpiresAt)
}

func terminalRecordingBindingsEqual(left, right TerminalRecordingConnectionBinding) bool {
	return left.SessionUID == right.SessionUID && left.TargetPodUID == right.TargetPodUID && left.Epoch == right.Epoch && left.Generation == right.Generation && left.RuntimeBindingDigest == right.RuntimeBindingDigest && left.ExpiresAt.Equal(right.ExpiresAt)
}

func (c *DebugSessionAPIController) handleReplayTerminalRecording(ctx *gin.Context) {
	if c.recordingStore == nil {
		apiresponses.RespondServiceUnavailable(ctx, "terminal recording storage is not configured")
		return
	}
	identity, ok := debugSessionRequestIdentity(ctx)
	if !ok {
		apiresponses.RespondUnauthorized(ctx)
		return
	}
	requestCtx := ctx.Request.Context()
	session, err := c.getDebugSessionByName(requestCtx, ctx.Param("name"), ctx.Query("namespace"))
	if err != nil {
		if apierrors.IsNotFound(err) {
			apiresponses.RespondNotFoundSimple(ctx, "debug session not found")
			return
		}
		apiresponses.RespondInternalErrorSimple(ctx, "failed to get debug session")
		return
	}
	canRead, err := c.canReadDebugSession(requestCtx, session, identity)
	if err != nil || !canRead {
		apiresponses.RespondForbidden(ctx, "user is not allowed to read this debug session")
		return
	}
	var ref *breakglassv1alpha1.TerminalRecordingRef
	if session.Status.KubectlDebugStatus != nil {
		for i := range session.Status.KubectlDebugStatus.TerminalRecordings {
			candidate := &session.Status.KubectlDebugStatus.TerminalRecordings[i]
			if candidate.ID == ctx.Param("id") {
				ref = candidate
				break
			}
		}
	}
	if ref == nil {
		apiresponses.RespondNotFoundSimple(ctx, "terminal recording not found")
		return
	}
	if !time.Now().Before(ref.ExpiresAt.Time) {
		ctx.Status(http.StatusGone)
		return
	}
	if ref.Backend != c.recordingStore.Backend() || ref.BackendInstanceID != c.recordingStore.BackendInstanceID() {
		apiresponses.RespondServiceUnavailable(ctx, "terminal recording storage identity changed")
		return
	}
	object := terminalRecordingObject(*ref)
	expected := artifactstorage.Metadata{BackendInstanceID: ref.BackendInstanceID, Key: ref.ID, VersionID: ref.VersionID, RuntimeBindingDigest: ref.RuntimeBindingDigest, Size: ref.Size, SHA256: ref.SHA256}
	reader, metadata, err := c.recordingStore.OpenVersion(requestCtx, object, expected)
	if err != nil {
		apiresponses.RespondNotFoundSimple(ctx, "terminal recording is unavailable")
		return
	}
	defer reader.Close()
	if metadata.BackendInstanceID != ref.BackendInstanceID || metadata.Key != ref.ID || metadata.VersionID != ref.VersionID || metadata.RuntimeBindingDigest != ref.RuntimeBindingDigest || metadata.Size != ref.Size || metadata.SHA256 != ref.SHA256 {
		apiresponses.RespondServiceUnavailable(ctx, "terminal recording metadata changed")
		return
	}
	ctx.Header("Content-Type", "application/octet-stream")
	ctx.Header("X-Breakglass-Recording-SHA256", metadata.SHA256)
	if _, err := io.CopyN(ctx.Writer, reader, ref.Size); err != nil && !errors.Is(err, io.EOF) {
		return
	}
}

func terminalRecordingRequest(ctx *gin.Context) (string, string, string, error) {
	namespace, podName := strings.TrimSpace(ctx.Query("podNamespace")), strings.TrimSpace(ctx.Query("podName"))
	if namespace == "" || podName == "" {
		return "", "", "", fmt.Errorf("podNamespace and podName are required")
	}
	operation := strings.ToLower(strings.TrimSpace(ctx.Query("operation")))
	if operation != "exec" && operation != "attach" {
		return "", "", "", fmt.Errorf("operation must be exec or attach")
	}
	if operation == "exec" && len(ctx.QueryArray("command")) == 0 {
		return "", "", "", fmt.Errorf("exec requires at least one command")
	}
	return namespace, podName, operation, nil
}

func allowedTargetPodUID(session *breakglassv1alpha1.DebugSession, namespace, podName string) (string, bool) {
	for _, pod := range session.Status.AllowedPods {
		if pod.Namespace == namespace && pod.Name == podName && pod.UID != "" {
			return pod.UID, true
		}
	}
	return "", false
}

func newTerminalRecordingExecutor(restConfig *rest.Config, namespace, podName, operation, container string, command []string) (remotecommand.Executor, error) {
	client, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("create target client: %w", err)
	}
	request := client.CoreV1().RESTClient().Post().Resource("pods").Namespace(namespace).Name(podName).SubResource(operation)
	if operation == "exec" {
		request.VersionedParams(&corev1.PodExecOptions{Container: container, Command: command, Stdin: true, Stdout: true, Stderr: true, TTY: true}, scheme.ParameterCodec)
	} else {
		request.VersionedParams(&corev1.PodAttachOptions{Container: container, Stdin: true, Stdout: true, Stderr: true, TTY: true}, scheme.ParameterCodec)
	}
	executor, err := remotecommand.NewSPDYExecutor(restConfig, http.MethodPost, request.URL())
	if err != nil {
		return nil, fmt.Errorf("create target terminal executor: %w", err)
	}
	return executor, nil
}

func persistTerminalRecording(ctx context.Context, store artifactstorage.Store, session *breakglassv1alpha1.DebugSession, pod *corev1.Pod, operation, container string, binding TerminalRecordingConnectionBinding, startedAt time.Time, recording TerminalRecording) (breakglassv1alpha1.TerminalRecordingRef, artifactstorage.Metadata, error) {
	artifactID := sha256Hex(string(session.UID) + ":" + string(pod.UID) + ":" + uuid.NewString())
	object := artifactstorage.Object{Key: artifactID, RuntimeBindingDigest: binding.RuntimeBindingDigest, Size: int64(len(recording.Bytes)), SHA256: recording.SHA256}
	metadata, err := store.PutIfAbsent(ctx, object, bytes.NewReader(recording.Bytes))
	if err != nil {
		return breakglassv1alpha1.TerminalRecordingRef{}, metadata, fmt.Errorf("publish terminal recording: %w", err)
	}
	retention := terminalRecordingDefaultRetention
	if session.Status.ResolvedTemplate != nil && session.Status.ResolvedTemplate.Audit != nil && session.Status.ResolvedTemplate.Audit.RecordingRetention != "" {
		if parsed, parseErr := breakglassv1alpha1.ParseDuration(session.Status.ResolvedTemplate.Audit.RecordingRetention); parseErr == nil && parsed > 0 {
			retention = parsed
		}
	}
	completedAt := time.Now().UTC()
	return breakglassv1alpha1.TerminalRecordingRef{ID: artifactID, Namespace: pod.Namespace, PodName: pod.Name, ContainerName: container, Operation: operation, SHA256: recording.SHA256, Size: int64(len(recording.Bytes)), Backend: store.Backend(), BackendInstanceID: store.BackendInstanceID(), RuntimeBindingDigest: binding.RuntimeBindingDigest, VersionID: metadata.VersionID, StartedAt: metav1.NewTime(startedAt), CompletedAt: metav1.NewTime(completedAt), ExpiresAt: metav1.NewTime(completedAt.Add(retention))}, metadata, nil
}

func terminalRecordingObject(ref breakglassv1alpha1.TerminalRecordingRef) artifactstorage.Object {
	return artifactstorage.Object{Key: ref.ID, RuntimeBindingDigest: ref.RuntimeBindingDigest, Size: ref.Size, SHA256: ref.SHA256}
}

func sha256Hex(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
