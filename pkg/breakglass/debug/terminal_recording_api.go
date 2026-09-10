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
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
)

const terminalRecordingDefaultRetention = 90 * 24 * time.Hour

const terminalRecordingFinalizeTimeout = 10 * time.Second

// Each recorder is bounded to 512 MiB, including framing. Limit live streams
// per serving process so authenticated clients cannot allocate unbounded buffers.
const maximumConcurrentTerminalRecordings = 2

// TerminalRecordingConnectionBinding is the immutable authorization tuple
// supplied by the connection-lease service for one target stream.
type TerminalRecordingConnectionBinding struct {
	Namespace            string
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

type terminalTargetResolver func(context.Context, *breakglassv1alpha1.DebugSession, string, string, string) (*rest.Config, *corev1.Pod, error)

type terminalExecutorFactory func(*rest.Config, string, string, string, string, []string) (remotecommand.Executor, error)

func (c *DebugSessionAPIController) WithTerminalRecordingStore(store artifactstorage.Store) *DebugSessionAPIController {
	c.recordingStore = store
	return c
}

func (c *DebugSessionAPIController) WithTerminalRecordingConnections(provider TerminalRecordingConnectionProvider) *DebugSessionAPIController {
	c.recordingConnections = provider
	return c
}

func (c *DebugSessionAPIController) handleTerminalRecording(ctx *gin.Context) {
	if c.recordingStore == nil || c.recordingConnections == nil || (c.ccProvider == nil && c.terminalTargetResolver == nil) {
		apiresponses.RespondServiceUnavailable(ctx, "terminal recording transport is not configured")
		return
	}
	if c.recordingStreams.Add(1) > maximumConcurrentTerminalRecordings {
		c.recordingStreams.Add(-1)
		ctx.Status(http.StatusTooManyRequests)
		return
	}
	defer c.recordingStreams.Add(-1)
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

	var restConfig *rest.Config
	var pod *corev1.Pod
	var validateTarget func(context.Context) error
	if c.terminalTargetResolver != nil {
		restConfig, pod, err = c.terminalTargetResolver(apiCtx, session, namespace, podName, targetUID)
		validateTarget = func(checkCtx context.Context) error {
			_, current, checkErr := c.terminalTargetResolver(checkCtx, session, namespace, podName, targetUID)
			if checkErr != nil {
				return checkErr
			}
			if current == nil || string(current.UID) != targetUID || !current.DeletionTimestamp.IsZero() {
				return fmt.Errorf("terminal target identity changed")
			}
			return nil
		}
	} else {
		var configured *breakglassv1alpha1.ClusterConfig
		restConfig, configured, err = c.ccProvider.GetRESTConfigForPrivilegedOperation(apiCtx, session.Spec.Cluster)
		if err == nil {
			defer c.ccProvider.ReleasePrivilegedOperationClusterConfig(configured)
			kubeClient, clientErr := kubernetes.NewForConfig(restConfig)
			if clientErr != nil {
				err = clientErr
			} else {
				pod, err = kubeClient.CoreV1().Pods(namespace).Get(apiCtx, podName, metav1.GetOptions{})
				validateTarget = func(checkCtx context.Context) error {
					if checkErr := c.ccProvider.ValidatePrivilegedOperationClusterConfig(checkCtx, configured); checkErr != nil {
						return checkErr
					}
					current, checkErr := kubeClient.CoreV1().Pods(namespace).Get(checkCtx, podName, metav1.GetOptions{})
					if checkErr != nil {
						return checkErr
					}
					if string(current.UID) != targetUID || !current.DeletionTimestamp.IsZero() {
						return fmt.Errorf("terminal target identity changed")
					}
					return nil
				}
			}
		}
	}
	if err != nil {
		apiresponses.RespondInternalErrorSimple(ctx, "failed to resolve target cluster")
		return
	}
	if pod == nil || string(pod.UID) != targetUID {
		apiresponses.RespondForbidden(ctx, "target Pod identity changed")
		return
	}

	profileDigest, err := ProfileDigestForSession(session)
	if err != nil {
		apiresponses.RespondInternalErrorSimple(ctx, "failed to resolve terminal recording profile")
		return
	}
	binding := TerminalRecordingConnectionBinding{Namespace: session.Namespace, SessionUID: string(session.UID), TargetPodUID: targetUID, RuntimeBindingDigest: strings.TrimPrefix(profileDigest, "sha256:"), ExpiresAt: session.Status.ExpiresAt.Time}
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
	connection = authorizedTerminalConnection{TerminalRecordingConnection: connection, authorize: c.terminalRecordingAuthority(session, identity, namespace, podName, targetUID, operation, validateTarget)}
	binding = connection.Binding()
	if !terminalRecordingBindingMatches(binding, session, targetUID) || binding.RuntimeBindingDigest != strings.TrimPrefix(profileDigest, "sha256:") {
		apiresponses.RespondForbidden(ctx, "terminal recording connection binding is invalid")
		return
	}
	if err := connection.Validate(apiCtx); err != nil {
		apiresponses.RespondForbidden(ctx, "terminal recording connection is no longer authorized")
		return
	}

	executorFactory := c.terminalExecutorFactory
	if executorFactory == nil {
		executorFactory = newTerminalRecordingExecutor
	}
	executor, err := executorFactory(restConfig, namespace, podName, operation, ctx.Query("container"), ctx.QueryArray("command"))
	if err != nil {
		apiresponses.RespondBadRequest(ctx, err.Error())
		return
	}
	startedAt := time.Now().UTC()
	recorder := NewTerminalRecorder(defaultTerminalRecordingMaxBytes)
	if err := http.NewResponseController(ctx.Writer).EnableFullDuplex(); err != nil {
		apiresponses.RespondServiceUnavailable(ctx, "full-duplex terminal transport is unavailable")
		return
	}
	ctx.Header("Content-Type", "application/octet-stream")
	ctx.Header("Trailer", "X-Breakglass-Recording-ID, X-Breakglass-Recording-SHA256, X-Breakglass-Recording-Status")
	streamWriter := &terminalRecordingFlushWriter{writer: ctx.Writer}
	guardedInput := authorizedRecordingReader{ctx: apiCtx, reader: ctx.Request.Body, authorize: connection.Validate}
	guardedOutput := authorizedRecordingWriter{ctx: apiCtx, writer: streamWriter, authorize: connection.Validate}
	recording, streamErr := streamTerminalWithLease(apiCtx, connection, binding.ExpiresAt, executor, guardedInput, guardedOutput, guardedOutput, recorder)
	finalizeCtx, finalizeCancel := context.WithTimeout(context.WithoutCancel(ctx.Request.Context()), terminalRecordingFinalizeTimeout)
	defer finalizeCancel()
	validatedBinding := connection.Binding()
	if err := connection.Validate(finalizeCtx); err != nil || !terminalRecordingBindingMatches(validatedBinding, session, targetUID) || !terminalRecordingBindingsEqual(validatedBinding, binding) {
		ctx.Header("X-Breakglass-Recording-Status", "rejected")
		apiresponses.RespondForbidden(ctx, "terminal recording connection expired")
		return
	}
	ref, _, err := persistTerminalRecording(finalizeCtx, c.recordingStore, session, pod, operation, ctx.Query("container"), binding, startedAt, recording)
	if err != nil {
		ctx.Header("X-Breakglass-Recording-Status", "failed")
		apiresponses.RespondInternalErrorSimple(ctx, "failed to finalize terminal recording")
		return
	}
	if err := c.patchDebugSessionStatusWithOptimisticLock(finalizeCtx, session, func(status *breakglassv1alpha1.DebugSessionStatus) {
		kubectlStatus := ensureKubectlDebugStatus(status)
		kubectlStatus.TerminalRecordings = append(kubectlStatus.TerminalRecordings, ref)
	}); err != nil {
		// The immutable artifact is the evidence of the operation. Keep it when
		// status publication conflicts so a later reconciliation can inventory it.
		ctx.Header("X-Breakglass-Recording-Status", "published-status-pending")
		apiresponses.RespondInternalErrorSimple(ctx, "failed to record terminal metadata")
		return
	}
	ctx.Header("X-Breakglass-Recording-ID", ref.ID)
	ctx.Header("X-Breakglass-Recording-SHA256", ref.SHA256)
	if streamErr != nil {
		ctx.Header("X-Breakglass-Recording-Status", "failed")
		return
	}
	ctx.Header("X-Breakglass-Recording-Status", "completed")
}

// terminalRecordingFlushWriter keeps interactive exec/attach output flowing
// through the HTTP response while retaining compatibility with buffered test
// writers and proxies that do not implement http.Flusher.
type terminalRecordingFlushWriter struct {
	writer http.ResponseWriter
}

func (w *terminalRecordingFlushWriter) Header() http.Header { return w.writer.Header() }

func (w *terminalRecordingFlushWriter) Write(payload []byte) (int, error) {
	n, err := w.writer.Write(payload)
	if flusher, ok := w.writer.(http.Flusher); ok {
		flusher.Flush()
	}
	return n, err
}

func (w *terminalRecordingFlushWriter) WriteHeader(statusCode int) { w.writer.WriteHeader(statusCode) }

func streamTerminalWithLease(ctx context.Context, connection TerminalRecordingConnection, expiresAt time.Time, executor remotecommand.Executor, stdin io.Reader, stdout, stderr io.Writer, recorder *TerminalRecorder) (TerminalRecording, error) {
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	if closer, ok := stdin.(io.Closer); ok {
		stopClose := context.AfterFunc(streamCtx, func() { _ = closer.Close() })
		defer stopClose()
	}
	if !expiresAt.IsZero() {
		timer := time.AfterFunc(time.Until(expiresAt), cancel)
		defer timer.Stop()
	}
	validationErr := make(chan error, 1)
	watchDone := make(chan struct{})
	go func() {
		defer close(watchDone)
		ticker := time.NewTicker(500 * time.Millisecond)
		defer ticker.Stop()
		for {
			select {
			case <-streamCtx.Done():
				return
			case <-ticker.C:
				validateCtx, validateCancel := context.WithTimeout(streamCtx, 2*time.Second)
				err := connection.Validate(validateCtx)
				validateCancel()
				if err != nil {
					select {
					case validationErr <- fmt.Errorf("terminal recording connection validation failed: %w", err):
					default:
					}
					cancel()
					return
				}
			}
		}
	}()
	recording, streamErr := StreamTerminal(streamCtx, executor, stdin, stdout, stderr, recorder)
	cancel()
	<-watchDone
	select {
	case err := <-validationErr:
		return recording, err
	default:
		return recording, streamErr
	}
}

func terminalRecordingBindingMatches(binding TerminalRecordingConnectionBinding, session *breakglassv1alpha1.DebugSession, targetUID string) bool {
	return binding.Namespace == session.Namespace && binding.SessionUID == string(session.UID) && binding.TargetPodUID == targetUID && binding.Epoch != "" && binding.Generation != "" && binding.RuntimeBindingDigest != "" && !binding.ExpiresAt.IsZero() && !binding.ExpiresAt.After(session.Status.ExpiresAt.Time) && time.Now().Before(binding.ExpiresAt)
}

func terminalRecordingBindingsEqual(left, right TerminalRecordingConnectionBinding) bool {
	return left.Namespace == right.Namespace && left.SessionUID == right.SessionUID && left.TargetPodUID == right.TargetPodUID && left.Epoch == right.Epoch && left.Generation == right.Generation && left.RuntimeBindingDigest == right.RuntimeBindingDigest && left.ExpiresAt.Equal(right.ExpiresAt)
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
	replayCtx, cancel := context.WithDeadline(requestCtx, ref.ExpiresAt.Time)
	defer cancel()
	reader, metadata, err := c.recordingStore.OpenVersion(replayCtx, object, expected)
	if err != nil {
		apiresponses.RespondNotFoundSimple(ctx, "terminal recording is unavailable")
		return
	}
	defer reader.Close()
	if metadata.BackendInstanceID != ref.BackendInstanceID || metadata.Key != ref.ID || metadata.VersionID != ref.VersionID || metadata.RuntimeBindingDigest != ref.RuntimeBindingDigest || metadata.Size != ref.Size || metadata.SHA256 != ref.SHA256 {
		apiresponses.RespondServiceUnavailable(ctx, "terminal recording metadata changed")
		return
	}
	if !time.Now().Before(ref.ExpiresAt.Time) {
		ctx.Status(http.StatusGone)
		return
	}
	authorize := func(checkCtx context.Context) error {
		checkCtx, cancel := context.WithTimeout(checkCtx, 2*time.Second)
		defer cancel()
		live := &breakglassv1alpha1.DebugSession{}
		if err := c.reader().Get(checkCtx, ctrlclient.ObjectKeyFromObject(session), live); err != nil {
			return err
		}
		if live.UID != session.UID || !live.DeletionTimestamp.IsZero() {
			return fmt.Errorf("recording session identity changed")
		}
		allowed, err := c.canReadDebugSession(checkCtx, live, identity)
		if err != nil || !allowed {
			return fmt.Errorf("recording reader authority changed")
		}
		if live.Status.KubectlDebugStatus == nil {
			return fmt.Errorf("recording reference was revoked")
		}
		for _, current := range live.Status.KubectlDebugStatus.TerminalRecordings {
			if current.ID == ref.ID && current == *ref && time.Now().Before(current.ExpiresAt.Time) {
				return nil
			}
		}
		return fmt.Errorf("recording reference expired or changed")
	}
	if err := authorize(requestCtx); err != nil {
		ctx.Status(http.StatusForbidden)
		return
	}
	stopClose := context.AfterFunc(replayCtx, func() { _ = reader.Close() })
	defer stopClose()
	guarded := authorizedRecordingReader{ctx: replayCtx, reader: reader, authorize: authorize}
	ctx.Header("Content-Type", "application/octet-stream")
	ctx.Header("X-Breakglass-Recording-SHA256", metadata.SHA256)
	if _, err := io.CopyN(authorizedRecordingWriter{ctx: replayCtx, writer: ctx.Writer, authorize: authorize}, guarded, ref.Size); err != nil && !errors.Is(err, io.EOF) {
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
	return breakglassv1alpha1.TerminalRecordingRef{ID: artifactID, Namespace: pod.Namespace, PodName: pod.Name, PodUID: string(pod.UID), ContainerName: container, Operation: operation, SHA256: recording.SHA256, Size: int64(len(recording.Bytes)), Backend: store.Backend(), BackendInstanceID: store.BackendInstanceID(), RuntimeBindingDigest: binding.RuntimeBindingDigest, VersionID: metadata.VersionID, StartedAt: metav1.NewTime(startedAt), CompletedAt: metav1.NewTime(completedAt), ExpiresAt: metav1.NewTime(completedAt.Add(retention))}, metadata, nil
}

func terminalRecordingObject(ref breakglassv1alpha1.TerminalRecordingRef) artifactstorage.Object {
	return artifactstorage.Object{Key: ref.ID, RuntimeBindingDigest: ref.RuntimeBindingDigest, Size: ref.Size, SHA256: ref.SHA256}
}

func sha256Hex(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
