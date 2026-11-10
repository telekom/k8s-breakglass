// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/backend"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/kube"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/storage/local"
	"github.com/telekom/k8s-breakglass/pkg/artifacts/token"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/serializer"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	clienttesting "k8s.io/client-go/testing"
	"k8s.io/client-go/tools/remotecommand"
	ctrlclient "sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
	"sigs.k8s.io/controller-runtime/pkg/client/interceptor"
)

type terminalRecordingRouteConnection struct {
	binding TerminalRecordingConnectionBinding
}

func (c terminalRecordingRouteConnection) Binding() TerminalRecordingConnectionBinding {
	return c.binding
}
func (terminalRecordingRouteConnection) Validate(context.Context) error { return nil }
func (terminalRecordingRouteConnection) Close(context.Context) error    { return nil }

type terminalRecordingRouteProvider struct{}

func (terminalRecordingRouteProvider) AcquireTerminalRecordingConnection(_ context.Context, binding TerminalRecordingConnectionBinding) (TerminalRecordingConnection, error) {
	binding.Epoch, binding.Generation, binding.LeaseUID = "1", "1", "lease-uid"
	return terminalRecordingRouteConnection{binding: binding}, nil
}

func TestRegisteredTerminalRouteStreamsAndPublishesRecording(t *testing.T) {
	for _, outcome := range []string{"complete", "failed", "revoked", "disconnect"} {
		t.Run(outcome, func(t *testing.T) {
			incomplete := outcome != "complete"
			gin.SetMode(gin.TestMode)
			now := metav1.Now()
			expiresAt := metav1.NewTime(now.Add(time.Hour))
			execAllowed := true
			session := &breakglassv1alpha1.DebugSession{
				ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "hub", UID: types.UID("session-uid")},
				Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "spoke", RequestedBy: "owner"},
				Status: breakglassv1alpha1.DebugSessionStatus{
					State:                breakglassv1alpha1.DebugSessionStateActive,
					ExpiresAt:            &expiresAt,
					ResolvedTemplate:     &breakglassv1alpha1.DebugSessionTemplateSpec{Audit: &breakglassv1alpha1.DebugSessionAuditConfig{EnableTerminalRecording: true}},
					Participants:         []breakglassv1alpha1.DebugSessionParticipant{{User: "alice", Role: breakglassv1alpha1.ParticipantRoleParticipant, JoinedAt: now}},
					AllowedPods:          []breakglassv1alpha1.AllowedPodRef{{Namespace: "target", Name: "pod", UID: "pod-uid"}},
					AllowedPodOperations: &breakglassv1alpha1.AllowedPodOperations{Exec: &execAllowed},
				},
			}
			service, cli := terminalArtifactFixture(t, session)
			controller := NewDebugSessionAPIController(zap.NewNop().Sugar(), cli, nil, nil).
				WithAPIReader(cli).
				WithTerminalRecordingArtifacts(service).
				WithTerminalRecordingMaxBytes(1024).
				WithTerminalRecordingConnections(terminalRecordingRouteProvider{})
			auditEvents := NewMockAuditEmitter(true)
			controller.WithAuditService(auditEvents)
			controller.terminalTargetResolver = func(context.Context, *breakglassv1alpha1.DebugSession, string, string, string) (*rest.Config, *corev1.Pod, string, error) {
				return &rest.Config{}, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "target", Name: "pod", UID: types.UID("pod-uid")}}, "cluster-uid", nil
			}
			controller.terminalExecutorFactory = func(*rest.Config, string, string, string, string, []string) (remotecommand.Executor, error) {
				return interactiveTerminalExecutor{before: func() error {
					var reservations breakglassv1alpha1.DebugSessionArtifactList
					if err := cli.List(context.Background(), &reservations); err != nil {
						return err
					}
					if len(reservations.Items) != 1 || reservations.Items[0].UID == "" {
						return fmt.Errorf("target execution started without durable reservation")
					}
					return nil
				}, after: func() error {
					if incomplete {
						var live breakglassv1alpha1.DebugSession
						if err := cli.Get(context.Background(), ctrlclient.ObjectKeyFromObject(session), &live); err != nil {
							return err
						}
						live.Status.State = breakglassv1alpha1.DebugSessionStateTerminated
						if err := cli.Status().Update(context.Background(), &live); err != nil {
							return err
						}
						if outcome == "failed" {
							return io.ErrUnexpectedEOF
						}
						return nil
					}
					return nil
				}}, nil
			}
			router := debugSessionAPITestRouter(t, controller, "alice", "", nil)
			server := httptest.NewServer(router)
			defer server.Close()
			input, inputWriter := io.Pipe()
			defer input.Close()
			defer inputWriter.Close()
			requestCtx, requestCancel := context.WithCancel(context.Background())
			defer requestCancel()
			req, err := http.NewRequestWithContext(requestCtx, http.MethodPost, server.URL+"/api/v1/debugSessions/session/terminal?namespace=hub&podNamespace=target&podName=pod&operation=exec&command=sh", input)
			require.NoError(t, err)
			httpClient := &http.Client{Timeout: 5 * time.Second}
			response, err := httpClient.Do(req)
			require.NoError(t, err)
			defer response.Body.Close()
			require.Equal(t, http.StatusOK, response.StatusCode)
			prompt := make([]byte, len("prompt"))
			_, err = io.ReadFull(response.Body, prompt)
			require.NoError(t, err)
			require.Equal(t, "prompt", string(prompt))
			artifactID := ""
			if outcome == "disconnect" {
				requestCancel()
				_ = inputWriter.Close()
				_ = response.Body.Close()
				require.Eventually(t, func() bool {
					records, err := service.Recordings(context.Background(), session.Namespace, session.Name, string(session.UID), func(context.Context) error { return nil })
					if err != nil || len(records) != 1 {
						return false
					}
					artifactID = records[0].ArtifactID
					return true
				}, 5*time.Second, 20*time.Millisecond)
			} else {
				// The prompt must arrive before request input is supplied or closed.
				_, err = io.WriteString(inputWriter, "input")
				require.NoError(t, err)
				require.NoError(t, inputWriter.Close())
				rest, err := io.ReadAll(response.Body)
				require.NoError(t, err)
				require.Equal(t, "input", string(rest))
				artifactID = response.Trailer.Get("X-Breakglass-Recording-ID")
				require.NotEmpty(t, artifactID)
			}
			stored := &breakglassv1alpha1.DebugSession{}
			require.NoError(t, cli.Get(context.Background(), ctrlclient.ObjectKeyFromObject(session), stored))
			require.Nil(t, stored.Status.KubectlDebugStatus)
			record, err := service.Recording(context.Background(), session.Namespace, session.Name, artifactID)
			require.NoError(t, err)
			var events []*audit.Event
			require.Eventually(t, func() bool { events = auditEvents.GetEvents(); return len(events) == 2 }, 5*time.Second, 20*time.Millisecond)
			auditEvents.ClearEvents()
			require.Equal(t, audit.EventDebugSessionTerminalRecordingStarted, events[0].Type)
			require.Equal(t, audit.EventDebugSessionTerminalRecordingFinalized, events[1].Type)
			for _, event := range events {
				require.Equal(t, "alice", event.Actor.User)
				require.Equal(t, string(session.UID), event.Target.UID)
				require.Equal(t, artifactID, event.Details["recordingId"])
				require.NotEmpty(t, event.RequestContext.CorrelationID)
				require.NotContains(t, fmt.Sprint(event.Details), "prompt", "terminal bytes must never reach audit")
				require.True(t, audit.IsSensitiveEvent(event.Type))
			}
			require.Equal(t, record.SHA256, events[1].Details["sha256"])
			require.Equal(t, !incomplete, events[1].Details["complete"])
			require.Equal(t, events[0].RequestContext.CorrelationID, events[1].RequestContext.CorrelationID)
			require.Equal(t, backend.StateAvailable, record.State)
			require.Equal(t, int64(1024), record.MaxBytes)
			require.Equal(t, "lease-uid", record.ConnectionLeaseUID)
			require.Equal(t, "pod-uid", record.Recording.PodUID)
			require.Equal(t, !incomplete, record.Recording.Complete)
			require.NotEmpty(t, record.ArtifactUID)
			replayURL := server.URL + "/api/v1/debugSessions/session/terminal/" + record.ArtifactID + "?namespace=hub"
			replay, err := httpClient.Get(replayURL)
			require.NoError(t, err)
			replayed, err := io.ReadAll(replay.Body)
			require.NoError(t, err)
			require.NoError(t, replay.Body.Close())
			require.Equal(t, http.StatusOK, replay.StatusCode)
			require.Equal(t, record.SHA256, sha256Hex(string(replayed)))
			require.Contains(t, string(replayed), "prompt")
			if outcome != "disconnect" {
				require.Contains(t, string(replayed), "input")
			}
			listing, err := httpClient.Get(server.URL + "/api/v1/debugSessions/session/terminal?namespace=hub")
			require.NoError(t, err)
			listed, err := io.ReadAll(listing.Body)
			require.NoError(t, err)
			require.NoError(t, listing.Body.Close())
			require.Equal(t, http.StatusOK, listing.StatusCode)
			require.Contains(t, string(listed), record.ArtifactID)
			accessed := auditEvents.GetEvents()
			require.Len(t, accessed, 2, "replay and list are audited")
			for _, event := range accessed {
				require.Equal(t, audit.EventDebugSessionTerminalRecordingAccessed, event.Type)
				require.Equal(t, "alice", event.Actor.User)
				require.Equal(t, string(session.UID), event.Target.UID)
				require.NotContains(t, fmt.Sprint(event.Details), "prompt", "terminal bytes must never reach audit")
				require.True(t, audit.IsSensitiveEvent(event.Type))
			}
			require.Equal(t, "replay", accessed[0].Details["access"])
			require.Equal(t, record.ArtifactID, accessed[0].Details["recordingId"])
			require.Equal(t, record.SHA256, accessed[0].Details["sha256"])
			require.Equal(t, "list", accessed[1].Details["access"])
			require.Equal(t, []string{record.ArtifactID}, accessed[1].Details["recordingIds"])
			auditEvents.mu.Lock()
			auditEvents.syncErr = fmt.Errorf("sink unavailable")
			auditEvents.mu.Unlock()
			for _, url := range []string{replayURL, server.URL + "/api/v1/debugSessions/session/terminal?namespace=hub"} {
				unaudited, err := httpClient.Get(url)
				require.NoError(t, err)
				body, err := io.ReadAll(unaudited.Body)
				require.NoError(t, err)
				require.NoError(t, unaudited.Body.Close())
				require.Equal(t, http.StatusServiceUnavailable, unaudited.StatusCode, "reads are refused when their access cannot be audited")
				require.NotContains(t, string(body), "prompt")
				require.NotContains(t, string(body), record.ArtifactID)
			}
			auditEvents.mu.Lock()
			auditEvents.syncErr = nil
			// Revoke the reader while its access event is delivered: no data.
			// Removing alice as participant while her access event is delivered.
			auditEvents.onSync = func(*audit.Event) {
				var live breakglassv1alpha1.DebugSession
				require.NoError(t, cli.Get(context.Background(), ctrlclient.ObjectKeyFromObject(session), &live))
				live.Status.Participants = nil
				require.NoError(t, cli.Status().Update(context.Background(), &live))
			}
			auditEvents.mu.Unlock()
			revoked, err := httpClient.Get(server.URL + "/api/v1/debugSessions/session/terminal?namespace=hub")
			require.NoError(t, err)
			revokedBody, err := io.ReadAll(revoked.Body)
			require.NoError(t, err)
			require.NoError(t, revoked.Body.Close())
			require.Equal(t, http.StatusForbidden, revoked.StatusCode, "a reader revoked during audit delivery gets no data")
			require.NotContains(t, string(revokedBody), record.ArtifactID)
			auditEvents.mu.Lock()
			auditEvents.onSync = nil
			auditEvents.mu.Unlock()
			var restored breakglassv1alpha1.DebugSession
			require.NoError(t, cli.Get(context.Background(), ctrlclient.ObjectKeyFromObject(session), &restored))
			restored.Status.Participants = session.Status.Participants
			require.NoError(t, cli.Status().Update(context.Background(), &restored))
			require.NotContains(t, string(listed), `"backendInstanceID"`)
			require.NotContains(t, string(listed), `"versionID"`)
			require.NoError(t, cli.Delete(context.Background(), stored))
			denied, err := httpClient.Get(replayURL)
			require.NoError(t, err)
			require.Equal(t, http.StatusNotFound, denied.StatusCode)
			require.NoError(t, denied.Body.Close())
			durable, err := service.Recording(context.Background(), session.Namespace, session.Name, record.ArtifactID)
			require.NoError(t, err)
			require.Equal(t, backend.StateAvailable, durable.State)
		})
	}
}

// interactiveTerminalExecutor follows the real protocol order: output first,
// then read input. A buffered HTTP transport deadlocks this exchange.
type interactiveTerminalExecutor struct{ before, after func() error }

func (interactiveTerminalExecutor) Stream(remotecommand.StreamOptions) error { return nil }
func (e interactiveTerminalExecutor) StreamWithContext(_ context.Context, options remotecommand.StreamOptions) error {
	if e.before != nil {
		if err := e.before(); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(options.Stdout, "prompt"); err != nil {
		return err
	}
	input, err := io.ReadAll(options.Stdin)
	if err != nil {
		return err
	}
	_, err = options.Stdout.Write(input)
	if err == nil && e.after != nil {
		return e.after()
	}
	return err
}

func TestRecordingInputLimitDoesNotForwardUnrecordedBytes(t *testing.T) {
	recorder := NewTerminalRecorder(terminalRecordingFrameHeaderSize + 2)
	input := &recordingReader{reader: strings.NewReader("unrecorded command"), recorder: recorder, direction: TerminalRecordingInput}
	var target bytes.Buffer
	_, err := io.Copy(&target, input)
	require.Error(t, err)
	require.Empty(t, target.Bytes())
}

type terminalDenyCollector struct{}

func (terminalDenyCollector) AuthorizeArtifact(context.Context, backend.SessionBinding) error {
	return backend.ErrForbidden
}
func terminalArtifactFixture(t *testing.T, session *breakglassv1alpha1.DebugSession) (*backend.Service, ctrlclient.Client) {
	t.Helper()
	root, err := filepath.EvalSymlinks(t.TempDir())
	require.NoError(t, err)
	cfg := local.Config{ExplicitlyEnabled: true, PrivateRootAcknowledged: true, ArtifactRoot: filepath.Join(root, "objects"), StagingRoot: filepath.Join(root, "staging"), InstanceID: "terminal-recording-test", ExpectedUID: os.Getuid(), ExpectedGID: os.Getgid(), ServingReplicas: 1, AccessMode: local.AccessModeReadWriteOnce, DeploymentStrategy: local.StrategyRecreate, EncryptionAcknowledged: true, SnapshotPolicy: local.SnapshotsProhibited}
	require.NoError(t, os.Mkdir(cfg.ArtifactRoot, 0700))
	require.NoError(t, os.Mkdir(cfg.StagingRoot, 0700))
	require.NoError(t, local.ProvisionSentinels(cfg))
	store, err := local.Open(cfg)
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, store.Close()) })
	var next atomic.Int64
	hub := interceptor.NewClient(fake.NewClientBuilder().WithScheme(Scheme).WithObjectTracker(clienttesting.NewObjectTracker(Scheme, serializer.NewCodecFactory(Scheme).UniversalDecoder())).WithObjects(session).WithStatusSubresource(session, &breakglassv1alpha1.DebugSessionArtifact{}).Build(), interceptor.Funcs{Create: func(ctx context.Context, cl ctrlclient.WithWatch, obj ctrlclient.Object, opts ...ctrlclient.CreateOption) error {
		if obj.GetUID() == "" {
			obj.SetUID(types.UID(fmt.Sprintf("artifact-%d", next.Add(1))))
		}
		return cl.Create(ctx, obj, opts...)
	}})
	repo, err := kube.NewRepositoryInNamespace(hub, "controller")
	require.NoError(t, err)
	keys, err := token.NewKeyring("https://breakglass.example", "artifact", "key", []token.Key{{ID: "key", Secret: bytes.Repeat([]byte{1}, 32)}}, token.Limits{MaxTTL: 15 * time.Minute})
	require.NoError(t, err)
	service, err := backend.New(backend.Config{Repository: repo, Store: store, Authorizer: terminalDenyCollector{}, Tokens: keys, StagingDir: cfg.StagingRoot})
	require.NoError(t, err)
	return service, hub
}

func TestTerminalFlushWriterPreservesUntrustedBytesAsBinary(t *testing.T) {
	payload := []byte("<script>alert(document.domain)</script>\x00\x1b[31m")
	for _, explicitHeader := range []bool{false, true} {
		response := httptest.NewRecorder()
		response.Header().Set("Content-Type", "text/html")
		writer := &terminalRecordingFlushWriter{writer: response}
		if explicitHeader {
			writer.WriteHeader(http.StatusOK)
		}
		n, err := writer.Write(payload)
		require.NoError(t, err)
		require.Equal(t, len(payload), n)
		require.Equal(t, payload, response.Body.Bytes())
		result := response.Result()
		defer result.Body.Close()
		require.Equal(t, "application/octet-stream", result.Header.Get("Content-Type"))
		require.Equal(t, "nosniff", result.Header.Get("X-Content-Type-Options"))
	}
}

func TestTerminalRouteRejectsActiveSessionWithoutExpiry(t *testing.T) {
	session := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "hub", UID: "uid"}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive}}
	service, cli := terminalArtifactFixture(t, session)
	controller := NewDebugSessionAPIController(zap.NewNop().Sugar(), cli, nil, nil).WithAPIReader(cli).WithTerminalRecordingArtifacts(service).WithTerminalRecordingConnections(terminalRecordingRouteProvider{}).WithAuditService(NewMockAuditEmitter(true))
	controller.terminalTargetResolver = func(context.Context, *breakglassv1alpha1.DebugSession, string, string, string) (*rest.Config, *corev1.Pod, string, error) {
		t.Fatal("target lookup must not occur without session expiry")
		return nil, nil, "", nil
	}
	router := debugSessionAPITestRouter(t, controller, "alice", "", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodPost, "/api/v1/debugSessions/session/terminal?namespace=hub&podNamespace=target&podName=pod&operation=exec&command=sh", nil))
	require.Equal(t, http.StatusForbidden, response.Code)
	require.False(t, terminalRecordingBindingMatches(TerminalRecordingConnectionBinding{}, session, "pod"))
}

func TestTerminalRouteRejectsWithoutWaitingForOpenInput(t *testing.T) {
	gin.SetMode(gin.TestMode)
	controller := NewDebugSessionAPIController(zap.NewNop().Sugar(), nil, nil, nil)
	server := httptest.NewServer(debugSessionAPITestRouter(t, controller, "alice", "", nil))
	defer server.Close()
	input, inputWriter := io.Pipe()
	defer inputWriter.Close()
	req, err := http.NewRequest(http.MethodPost, server.URL+"/api/v1/debugSessions/session/terminal?podNamespace=n&podName=p&operation=exec&command=sh", input)
	require.NoError(t, err)
	// An interactive client keeps stdin open; the rejection must still arrive.
	response, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
	require.NoError(t, err)
	require.NoError(t, response.Body.Close())
	require.Equal(t, http.StatusServiceUnavailable, response.StatusCode)
}

type conflictingRecordingProvider struct{}

func (conflictingRecordingProvider) AcquireTerminalRecordingConnection(context.Context, TerminalRecordingConnectionBinding) (TerminalRecordingConnection, error) {
	return nil, fmt.Errorf("publish: %w", ErrTerminalRecordingGenerationConflict)
}

func TestTerminalRouteFailsClosedWithoutAuditAndRetriesPublishRace(t *testing.T) {
	gin.SetMode(gin.TestMode)
	now := metav1.Now()
	expiresAt := metav1.NewTime(now.Add(time.Hour))
	execAllowed := true
	session := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "session", Namespace: "hub", UID: types.UID("session-uid")},
		Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "spoke", RequestedBy: "owner"},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateActive, ExpiresAt: &expiresAt,
			ResolvedTemplate:     &breakglassv1alpha1.DebugSessionTemplateSpec{Audit: &breakglassv1alpha1.DebugSessionAuditConfig{EnableTerminalRecording: true}},
			Participants:         []breakglassv1alpha1.DebugSessionParticipant{{User: "alice", Role: breakglassv1alpha1.ParticipantRoleParticipant, JoinedAt: now}},
			AllowedPods:          []breakglassv1alpha1.AllowedPodRef{{Namespace: "target", Name: "pod", UID: "pod-uid"}},
			AllowedPodOperations: &breakglassv1alpha1.AllowedPodOperations{Exec: &execAllowed},
		},
	}
	executed := false
	var service *backend.Service
	var cli ctrlclient.Client
	newController := func(audited *MockAuditEmitter, provider TerminalRecordingConnectionProvider) *httptest.Server {
		service, cli = terminalArtifactFixture(t, session)
		controller := NewDebugSessionAPIController(zap.NewNop().Sugar(), cli, nil, nil).WithAPIReader(cli).
			WithTerminalRecordingArtifacts(service).WithTerminalRecordingConnections(provider)
		if audited != nil {
			controller.WithAuditService(audited)
		}
		controller.terminalTargetResolver = func(context.Context, *breakglassv1alpha1.DebugSession, string, string, string) (*rest.Config, *corev1.Pod, string, error) {
			return &rest.Config{}, &corev1.Pod{ObjectMeta: metav1.ObjectMeta{Namespace: "target", Name: "pod", UID: types.UID("pod-uid")}}, "cluster-uid", nil
		}
		controller.terminalExecutorFactory = func(*rest.Config, string, string, string, string, []string) (remotecommand.Executor, error) {
			return interactiveTerminalExecutor{before: func() error { executed = true; return nil }}, nil
		}
		return httptest.NewServer(debugSessionAPITestRouter(t, controller, "alice", "", nil))
	}
	post := func(server *httptest.Server) (int, http.Header) {
		response, err := http.Post(server.URL+"/api/v1/debugSessions/session/terminal?namespace=hub&podNamespace=target&podName=pod&operation=exec&command=sh", "application/octet-stream", strings.NewReader(""))
		require.NoError(t, err)
		defer response.Body.Close()
		_, _ = io.Copy(io.Discard, response.Body)
		return response.StatusCode, response.Header
	}
	for name, audited := range map[string]*MockAuditEmitter{"no audit service": nil, "audit disabled": NewMockAuditEmitter(false)} {
		t.Run(name, func(t *testing.T) {
			server := newController(audited, terminalRecordingRouteProvider{})
			defer server.Close()
			status, _ := post(server)
			require.Equal(t, http.StatusServiceUnavailable, status, "no stream may start without its audit index")
			require.False(t, executed)
		})
	}
	t.Run("start event undeliverable", func(t *testing.T) {
		undeliverable := NewMockAuditEmitter(true)
		undeliverable.syncErr = fmt.Errorf("sink unavailable")
		server := newController(undeliverable, terminalRecordingRouteProvider{})
		defer server.Close()
		status, _ := post(server)
		require.Equal(t, http.StatusServiceUnavailable, status)
		require.False(t, executed, "the target never runs without a delivered start event")
		var reservations breakglassv1alpha1.DebugSessionArtifactList
		require.NoError(t, cli.List(context.Background(), &reservations))
		require.Len(t, reservations.Items, 1)
		require.NotEqual(t, string(backend.StatePending), string(reservations.Items[0].Status.State), "a failed start releases its reservation slot")
		records, err := service.Recordings(context.Background(), session.Namespace, session.Name, string(session.UID), func(context.Context) error { return nil })
		require.NoError(t, err)
		require.Empty(t, records, "no recording is advertised for a start that never ran")
	})
	t.Run("revoked during start event delivery", func(t *testing.T) {
		executed = false
		revoking := NewMockAuditEmitter(true)
		server := newController(revoking, &revocableRecordingProvider{})
		defer server.Close()
		revoking.onSync = func(event *audit.Event) {
			if event.Type == audit.EventDebugSessionTerminalRecordingStarted {
				revokedRecordingConnections.Store(true)
			}
		}
		defer revokedRecordingConnections.Store(false)
		status, _ := post(server)
		require.Equal(t, http.StatusForbidden, status)
		require.False(t, executed, "authority is rechecked after audit delivery, before execution")
	})
	t.Run("publish race", func(t *testing.T) {
		server := newController(NewMockAuditEmitter(true), conflictingRecordingProvider{})
		defer server.Close()
		status, header := post(server)
		require.Equal(t, http.StatusServiceUnavailable, status)
		require.Equal(t, "1", header.Get("Retry-After"))
		require.False(t, executed)
	})
}

var revokedRecordingConnections atomic.Bool

type revocableRecordingConnection struct {
	terminalRecordingRouteConnection
}

func (revocableRecordingConnection) Validate(context.Context) error {
	if revokedRecordingConnections.Load() {
		return fmt.Errorf("revoked")
	}
	return nil
}

type revocableRecordingProvider struct{}

func (*revocableRecordingProvider) AcquireTerminalRecordingConnection(ctx context.Context, binding TerminalRecordingConnectionBinding) (TerminalRecordingConnection, error) {
	connection, err := terminalRecordingRouteProvider{}.AcquireTerminalRecordingConnection(ctx, binding)
	if err != nil {
		return nil, err
	}
	return revocableRecordingConnection{connection.(terminalRecordingRouteConnection)}, nil
}
