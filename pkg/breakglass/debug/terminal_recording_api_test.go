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
				WithTerminalRecordingConnections(terminalRecordingRouteProvider{})
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
			require.Equal(t, backend.StateAvailable, record.State)
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
