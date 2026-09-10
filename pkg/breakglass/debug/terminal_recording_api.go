// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	apiresponses "github.com/telekom/k8s-breakglass/pkg/apiresponses"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/backend"
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
	TargetClusterUID     string
	LeaseUID             string
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

type terminalTargetResolver func(context.Context, *breakglassv1alpha1.DebugSession, string, string, string) (*rest.Config, *corev1.Pod, string, error)

type terminalExecutorFactory func(*rest.Config, string, string, string, string, []string) (remotecommand.Executor, error)

func (c *DebugSessionAPIController) WithTerminalRecordingArtifacts(service *backend.Service) *DebugSessionAPIController {
	c.recordingArtifacts = service
	return c
}

func (c *DebugSessionAPIController) WithTerminalRecordingConnections(provider TerminalRecordingConnectionProvider) *DebugSessionAPIController {
	c.recordingConnections = provider
	return c
}

func (c *DebugSessionAPIController) handleTerminalRecording(ctx *gin.Context) {
	if c.recordingArtifacts == nil || c.recordingConnections == nil || (c.ccProvider == nil && c.terminalTargetResolver == nil) {
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
	if session.Status.State != breakglassv1alpha1.DebugSessionStateActive || isDebugSessionExpired(session, time.Now().UTC()) {
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
	var targetClusterUID string
	var validateTarget func(context.Context) error
	if c.terminalTargetResolver != nil {
		restConfig, pod, targetClusterUID, err = c.terminalTargetResolver(apiCtx, session, namespace, podName, targetUID)
		validateTarget = func(checkCtx context.Context) error {
			_, current, currentClusterUID, checkErr := c.terminalTargetResolver(checkCtx, session, namespace, podName, targetUID)
			if checkErr != nil {
				return checkErr
			}
			if currentClusterUID != targetClusterUID || current == nil || string(current.UID) != targetUID || !current.DeletionTimestamp.IsZero() {
				return fmt.Errorf("terminal target identity changed")
			}
			return nil
		}
	} else {
		var configured *breakglassv1alpha1.ClusterConfig
		restConfig, configured, err = c.ccProvider.GetRESTConfigForPrivilegedOperation(apiCtx, session.Spec.Cluster)
		if err == nil {
			targetClusterUID = string(configured.UID)
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
	if targetClusterUID == "" || pod == nil || string(pod.UID) != targetUID {
		apiresponses.RespondForbidden(ctx, "target Pod identity changed")
		return
	}

	profileDigest, err := ProfileDigestForSession(session)
	if err != nil {
		apiresponses.RespondInternalErrorSimple(ctx, "failed to resolve terminal recording profile")
		return
	}
	binding := TerminalRecordingConnectionBinding{Namespace: session.Namespace, SessionUID: string(session.UID), TargetPodUID: targetUID, TargetClusterUID: targetClusterUID, RuntimeBindingDigest: strings.TrimPrefix(profileDigest, "sha256:"), ExpiresAt: session.Status.ExpiresAt.Time}
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
	if !terminalRecordingBindingMatches(binding, session, targetUID) || binding.TargetClusterUID != targetClusterUID || binding.RuntimeBindingDigest != strings.TrimPrefix(profileDigest, "sha256:") {
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
	if err := http.NewResponseController(ctx.Writer).EnableFullDuplex(); err != nil {
		apiresponses.RespondServiceUnavailable(ctx, "full-duplex terminal transport is unavailable")
		return
	}
	epoch, err := strconv.ParseUint(binding.Epoch, 10, 64)
	if err != nil || epoch == 0 {
		apiresponses.RespondForbidden(ctx, "invalid recording lease epoch")
		return
	}
	retention := terminalRecordingDefaultRetention
	if configured := session.Status.ResolvedTemplate.Audit.RecordingRetention; configured != "" {
		retention, err = breakglassv1alpha1.ParseDuration(configured)
		if err != nil || retention <= 0 {
			apiresponses.RespondForbidden(ctx, "invalid recording retention")
			return
		}
	}
	plan, err := json.Marshal(struct {
		Operation, Container string
		Command              []string
	}{operation, ctx.Query("container"), ctx.QueryArray("command")})
	if err != nil {
		apiresponses.RespondInternalErrorSimple(ctx, "failed to bind recording operation")
		return
	}
	metadata := backend.RecordingMetadata{FormatVersion: 1, StartedAt: time.Now().UTC(), StreamExpiresAt: binding.ExpiresAt, PodNamespace: namespace, PodName: podName, PodUID: targetUID, ContainerName: ctx.Query("container"), Operation: operation, LeaseUID: binding.LeaseUID, LeaseEpoch: binding.Epoch, Generation: binding.Generation}
	reservation, err := c.recordingArtifacts.ReserveRecording(apiCtx, backend.Record{
		Namespace: session.Namespace, SessionName: session.Name, SessionUID: string(session.UID), TargetClusterUID: targetClusterUID,
		TargetPodNamespace: namespace, TargetPodName: podName, TargetPodUID: targetUID,
		TargetIdentityDigest: sha256Hex(namespace + "\x00" + podName + "\x00" + targetUID), RuntimeBindingDigest: binding.RuntimeBindingDigest,
		PlanDigest: sha256Hex(string(plan)), OperationEpoch: epoch, MaxBytes: defaultTerminalRecordingMaxBytes,
		ExpiresAt: binding.ExpiresAt.Add(retention), Recording: &metadata,
	}, connection.Validate)
	if err != nil {
		apiresponses.RespondServiceUnavailable(ctx, "failed to reserve terminal evidence")
		return
	}
	metadata = *reservation.Recording
	recorder := NewTerminalRecorder(reservation.MaxBytes)
	ctx.Header("Content-Type", "application/octet-stream")
	ctx.Header("Trailer", "X-Breakglass-Recording-ID, X-Breakglass-Recording-SHA256, X-Breakglass-Recording-Status")
	streamWriter := &terminalRecordingFlushWriter{writer: ctx.Writer}
	guardedInput := authorizedRecordingReader{ctx: apiCtx, reader: ctx.Request.Body, authorize: connection.Validate}
	guardedOutput := authorizedRecordingWriter{ctx: apiCtx, writer: streamWriter, authorize: connection.Validate}
	responseControl := http.NewResponseController(ctx.Writer)
	_ = responseControl.SetReadDeadline(binding.ExpiresAt)
	_ = responseControl.SetWriteDeadline(binding.ExpiresAt)
	requestBody := ctx.Request.Body
	abortTransport := func() {
		// A canceled SPDY executor must also unblock an HTTP client that stopped
		// reading output or left its request body open.
		_ = responseControl.SetWriteDeadline(time.Now())
		_ = responseControl.SetReadDeadline(time.Now())
		_ = requestBody.Close()
	}
	recording, streamErr := streamTerminalWithLease(apiCtx, connection, binding.ExpiresAt, executor, guardedInput, guardedOutput, guardedOutput, recorder, abortTransport)
	finalizeCtx, finalizeCancel := context.WithTimeout(context.WithoutCancel(ctx.Request.Context()), terminalRecordingFinalizeTimeout)
	defer finalizeCancel()
	metadata.FinishedAt = time.Now().UTC()
	metadata.Complete = streamErr == nil && apiCtx.Err() == nil && metadata.FinishedAt.Before(binding.ExpiresAt)
	metadata.Frames = recording.Frames
	// Publication preserves already-admitted evidence after disconnection or expiry.
	// The durable reservation, not a now-revoked stream lease, fences this write.
	var published backend.PublicRecord
	for attempt := 0; attempt < 3; attempt++ {
		published, err = c.recordingArtifacts.FinalizeRecording(finalizeCtx, reservation, bytes.NewReader(recording.Bytes), metadata)
		if err == nil || finalizeCtx.Err() != nil {
			break
		}
	}
	ctx.Header("X-Breakglass-Recording-ID", reservation.ArtifactID)
	if err != nil {
		ctx.Header("X-Breakglass-Recording-Status", "finalization-pending")
		return
	}
	ctx.Header("X-Breakglass-Recording-SHA256", published.SHA256)
	if !metadata.Complete {
		ctx.Header("X-Breakglass-Recording-Status", "incomplete")
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

func streamTerminalWithLease(ctx context.Context, connection TerminalRecordingConnection, expiresAt time.Time, executor remotecommand.Executor, stdin io.Reader, stdout, stderr io.Writer, recorder *TerminalRecorder, abortTransport func()) (TerminalRecording, error) {
	streamCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	stopAbort := func() {}
	if abortTransport != nil {
		abortDone := make(chan struct{})
		stop := context.AfterFunc(streamCtx, func() { defer close(abortDone); abortTransport() })
		stopped := false
		stopAbort = func() {
			if stopped {
				return
			}
			stopped = true
			if !stop() {
				<-abortDone
			}
		}
	}
	defer stopAbort()
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
	stopAbort()
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
	return binding.Namespace == session.Namespace && binding.SessionUID == string(session.UID) && binding.TargetPodUID == targetUID && binding.LeaseUID != "" && binding.Epoch != "" && binding.Generation != "" && binding.RuntimeBindingDigest != "" && !binding.ExpiresAt.IsZero() && !binding.ExpiresAt.After(session.Status.ExpiresAt.Time) && time.Now().Before(binding.ExpiresAt)
}

func (c *DebugSessionAPIController) recordingReplayAuthority(session *breakglassv1alpha1.DebugSession, identity debugSessionReadIdentity) func(context.Context) error {
	return func(ctx context.Context) error {
		checkCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
		defer cancel()
		var live breakglassv1alpha1.DebugSession
		if err := c.reader().Get(checkCtx, ctrlclient.ObjectKeyFromObject(session), &live); err != nil {
			return fmt.Errorf("read recording session: %w", err)
		}
		if live.UID != session.UID || !live.DeletionTimestamp.IsZero() {
			return backend.ErrForbidden
		}
		allowed, err := c.canReadDebugSession(checkCtx, &live, identity)
		if err != nil {
			return fmt.Errorf("authorize recording replay: %w", err)
		}
		if !allowed {
			return backend.ErrForbidden
		}
		return nil
	}
}

func (c *DebugSessionAPIController) handleListTerminalRecordings(ctx *gin.Context) {
	if c.recordingArtifacts == nil {
		apiresponses.RespondServiceUnavailable(ctx, "terminal recording storage is not configured")
		return
	}
	identity, ok := debugSessionRequestIdentity(ctx)
	if !ok {
		apiresponses.RespondUnauthorized(ctx)
		return
	}
	session, err := c.getDebugSessionByName(ctx.Request.Context(), ctx.Param("name"), ctx.Query("namespace"))
	if err != nil {
		apiresponses.RespondNotFoundSimple(ctx, "debug session not found")
		return
	}
	records, err := c.recordingArtifacts.Recordings(ctx.Request.Context(), session.Namespace, session.Name, string(session.UID), c.recordingReplayAuthority(session, identity))
	if err != nil {
		apiresponses.RespondForbidden(ctx, "recordings are not available to this user")
		return
	}
	ctx.JSON(http.StatusOK, records)
}

func (c *DebugSessionAPIController) handleReplayTerminalRecording(ctx *gin.Context) {
	if c.recordingArtifacts == nil {
		apiresponses.RespondServiceUnavailable(ctx, "terminal recording storage is not configured")
		return
	}
	identity, ok := debugSessionRequestIdentity(ctx)
	if !ok {
		apiresponses.RespondUnauthorized(ctx)
		return
	}
	session, err := c.getDebugSessionByName(ctx.Request.Context(), ctx.Param("name"), ctx.Query("namespace"))
	if err != nil {
		apiresponses.RespondNotFoundSimple(ctx, "debug session not found")
		return
	}
	authorize := c.recordingReplayAuthority(session, identity)
	if err := authorize(ctx.Request.Context()); err != nil {
		apiresponses.RespondForbidden(ctx, "recording access denied")
		return
	}
	reservation, err := c.recordingArtifacts.Recording(ctx.Request.Context(), session.Namespace, session.Name, ctx.Param("id"))
	if err != nil || reservation.SessionUID != string(session.UID) {
		apiresponses.RespondNotFoundSimple(ctx, "terminal recording not found")
		return
	}
	replayCtx, cancel := context.WithDeadline(ctx.Request.Context(), reservation.ExpiresAt)
	defer cancel()
	reader, record, err := c.recordingArtifacts.DownloadRecording(replayCtx, reservation, authorize)
	if err != nil {
		if errors.Is(err, backend.ErrExpired) {
			ctx.Status(http.StatusGone)
		} else {
			apiresponses.RespondForbidden(ctx, "terminal recording unavailable")
		}
		return
	}
	defer reader.Close()
	stopClose := context.AfterFunc(replayCtx, func() { _ = reader.Close() })
	defer stopClose()
	ctx.Header("Content-Type", "application/octet-stream")
	ctx.Header("X-Breakglass-Recording-SHA256", record.SHA256)
	_, _ = io.CopyN(authorizedRecordingWriter{ctx: replayCtx, writer: ctx.Writer, authorize: authorize}, reader, record.Size)
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

func sha256Hex(value string) string {
	digest := sha256.Sum256([]byte(value))
	return hex.EncodeToString(digest[:])
}
