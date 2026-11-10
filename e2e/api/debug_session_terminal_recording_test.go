//go:build e2e

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
	bgclient "github.com/telekom/k8s-breakglass/pkg/bgctl/client"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/recording"
)

// TestDebugSessionTerminalRecordingE2E proves the recorded terminal path on a
// real cluster with the configured artifact backend: a participant runs an
// interactive exec through the controller, the recording is retrievable by the
// owner with an intact hash chain and the typed input/emitted output, an
// unrelated user cannot list or replay it, and a credential rotation during
// a stream aborts it and publishes the evidence as incomplete.
func TestDebugSessionTerminalRecordingE2E(t *testing.T) {
	s := helpers.SetupTest(t, helpers.WithLongTimeout())
	ctx := s.Ctx
	requesterUser := helpers.TestUsers.SecurityRequester
	requester := s.TC.ClientForUser(requesterUser)
	outsider := s.TC.ClientForUser(helpers.TestUsers.UnauthorizedUser)

	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("terminal-recording")},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			Mode: breakglassv1alpha1.DebugSessionModeWorkload, TargetNamespace: s.Namespace,
			Allowed:              &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{s.Cluster}, Groups: requesterUser.Groups},
			AllowedPodOperations: &breakglassv1alpha1.AllowedPodOperations{Exec: ptr.To(true)},
			Audit:                &breakglassv1alpha1.DebugSessionAuditConfig{EnableTerminalRecording: true, RecordingRetention: "1h"},
			PodTemplateString: `apiVersion: v1
kind: Pod
metadata:
  name: terminal-recording-target
spec:
  containers:
  - name: shell
    image: busybox:latest
    imagePullPolicy: IfNotPresent
    command: ["sleep", "3600"]
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      runAsNonRoot: true
      runAsUser: 65532
      seccompProfile:
        type: RuntimeDefault
`,
		},
	}
	require.NoError(t, s.CreateResource(template))
	session, err := requester.CreateDebugSession(ctx, t, helpers.DebugSessionRequest{TemplateRef: template.Name, Cluster: s.Cluster, RequestedDuration: "30m", Reason: "terminal recording e2e"})
	require.NoError(t, err)
	s.Cleanup.Add(session)
	t.Cleanup(func() { _ = requester.TerminateDebugSession(context.Background(), t, session.Name) })
	active := helpers.WaitForDebugSessionState(t, ctx, s.Client, session.Name, session.Namespace, breakglassv1alpha1.DebugSessionStateActive, helpers.WaitForStateTimeout)
	require.Eventually(t, func() bool {
		if s.Client.Get(ctx, client.ObjectKeyFromObject(active), active) != nil {
			return false
		}
		return len(active.Status.AllowedPods) > 0 && active.Status.AllowedPods[0].Ready
	}, helpers.WaitForStateTimeout, time.Second, "recorded debug pod must become Ready")
	pod := active.Status.AllowedPods[0]
	base := "/api/debugSessions/" + url.PathEscape(session.Name) + "/terminal"
	sessionQuery := "?namespace=" + url.QueryEscape(session.Namespace)

	t.Run("record retrieve verify", func(t *testing.T) {
		const typed = "hello-recording"
		var result helpers.TerminalStreamResult
		// The first stream of a session publishes the credential generation; a
		// concurrent controller lease update can make that attempt conflict.
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			streamCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()
			var streamErr error
			result, streamErr = requester.StreamRecordedTerminal(streamCtx, helpers.TerminalStreamRequest{
				Session: session.Name, SessionNamespace: session.Namespace, PodNamespace: pod.Namespace, PodName: pod.Name,
				Command:  []string{"sh", "-c", `read line; echo "recorded:$line"`},
				Interact: typeAfterOutput(typed+"\n", "recorded:"+typed),
			})
			require.NoError(c, streamErr)
			require.Equal(c, http.StatusOK, result.StatusCode, result.Body)
		}, helpers.WaitForStateTimeout, 2*time.Second)
		require.Contains(t, result.Output, "recorded:"+typed)
		require.Equal(t, "completed", result.Status)
		require.NotEmpty(t, result.RecordingID)
		require.Len(t, result.SHA256, 64)

		status, listed, err := requester.GetRaw(ctx, base+sessionQuery)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status, string(listed))
		require.Contains(t, string(listed), result.RecordingID)

		status, replay, err := requester.GetRaw(ctx, base+"/"+url.PathEscape(result.RecordingID)+sessionQuery)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status, string(replay))
		digest := sha256.Sum256(replay)
		require.Equal(t, result.SHA256, hex.EncodeToString(digest[:]), "replayed bytes must match the published digest")
		parsed, err := recording.Parse(bytes.NewReader(replay))
		require.NoError(t, err, "the replayed recording must have an intact hash chain")
		frames := parsed.Frames
		require.Equal(t, result.SHA256, parsed.SHA256)
		var input, output strings.Builder
		for _, frame := range frames {
			require.EqualValues(t, 2, frame.Version, "new recordings carry timing")
			switch frame.Direction {
			case 'i':
				input.Write(frame.Payload)
			case 'o':
				output.Write(frame.Payload)
			default:
				t.Fatalf("unexpected frame direction %q", frame.Direction)
			}
		}
		require.Equal(t, typed+"\n", input.String(), "typed input is recorded exactly")
		require.Contains(t, output.String(), "recorded:"+typed, "emitted output is recorded")

		var listing []helpers.TerminalRecordingListing
		require.NoError(t, json.Unmarshal(listed, &listing))
		var entry *helpers.TerminalRecordingListing
		for i := range listing {
			if listing[i].ArtifactID == result.RecordingID {
				entry = &listing[i]
			}
		}
		require.NotNil(t, entry)
		require.Equal(t, result.SHA256, entry.SHA256)
		require.NotNil(t, entry.Recording)
		require.True(t, entry.Recording.Complete)
		require.Equal(t, pod.Name, entry.Recording.PodName)
		require.EqualValues(t, len(frames), entry.Recording.Frames)

		t.Run("unauthorized reader denied", func(t *testing.T) {
			status, body, err := outsider.GetRaw(ctx, base+"/"+url.PathEscape(result.RecordingID)+sessionQuery)
			require.NoError(t, err)
			require.Equal(t, http.StatusForbidden, status, string(body))
			require.NotContains(t, string(body), typed)
			status, body, err = outsider.GetRaw(ctx, base+sessionQuery)
			require.NoError(t, err)
			require.Equal(t, http.StatusForbidden, status, string(body))
		})
		t.Run("unauthorized participant cannot record", func(t *testing.T) {
			streamCtx, cancel := context.WithTimeout(ctx, time.Minute)
			defer cancel()
			denied, err := outsider.StreamRecordedTerminal(streamCtx, helpers.TerminalStreamRequest{Session: session.Name, SessionNamespace: session.Namespace, PodNamespace: pod.Namespace, PodName: pod.Name, Command: []string{"sh"}})
			require.NoError(t, err)
			require.Equal(t, http.StatusForbidden, denied.StatusCode, denied.Body)
		})
	})

	t.Run("bgctl client records resize and timing", func(t *testing.T) {
		bg, err := bgclient.New(bgclient.WithServer(helpers.GetAPIBaseURL()), bgclient.WithToken(requester.AuthToken))
		require.NoError(t, err)
		stdin, stdinWriter := io.Pipe()
		resize := make(chan bgclient.TerminalSize, 1)
		resize <- bgclient.TerminalSize{Width: 101, Height: 31}
		const pause = 1500 * time.Millisecond
		out := &markerWriter{marker: "start", seen: make(chan struct{})}
		go func() {
			// Pace from the command's first output, not from request start,
			// so connection setup latency cannot shorten the measured gap.
			select {
			case <-out.seen:
			case <-time.After(time.Minute):
			}
			time.Sleep(pause)
			_, _ = io.WriteString(stdinWriter, "timed\n")
			time.Sleep(time.Second)
			_ = stdinWriter.Close()
		}()
		streamCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		result, err := bg.Terminal(streamCtx, bgclient.TerminalRequest{
			Session: session.Name, Namespace: session.Namespace, PodNamespace: pod.Namespace, PodName: pod.Name,
			Command: []string{"sh", "-c", `echo start; read line; stty size; echo "got:$line"`},
			Stdin:   stdin, Stdout: out, Resize: resize,
		})
		require.NoError(t, err)
		require.Equal(t, "completed", result.Status, out.String())
		require.Contains(t, out.String(), "31 101", "the initial size reaches the target TTY")
		require.Contains(t, out.String(), "got:timed")

		var raw bytes.Buffer
		published, err := bg.DebugSessions().DownloadRecording(ctx, session.Name, session.Namespace, result.RecordingID, &raw)
		require.NoError(t, err)
		require.Equal(t, result.SHA256, published)
		rec, err := recording.Parse(&raw)
		require.NoError(t, err)
		require.Equal(t, published, rec.SHA256)
		var resized, firstOutput, typed *recording.Frame
		for i := range rec.Frames {
			frame := &rec.Frames[i]
			switch {
			case frame.Direction == recording.Resize && resized == nil:
				resized = frame
			case frame.Direction == recording.Output && firstOutput == nil:
				firstOutput = frame
			case frame.Direction == recording.Input && typed == nil:
				typed = frame
			}
		}
		require.NotNil(t, resized, "the resize is recorded")
		require.JSONEq(t, `{"width":101,"height":31}`, string(resized.Payload))
		require.NotNil(t, firstOutput)
		require.NotNil(t, typed)
		require.Equal(t, "timed\n", string(typed.Payload))
		require.GreaterOrEqual(t, typed.Offset-firstOutput.Offset, pause, "frame offsets reflect real time between output and typed input")

		var cast bytes.Buffer
		require.NoError(t, rec.WriteAsciicast(&cast, recording.AsciicastOptions{}))
		require.Contains(t, strings.SplitN(cast.String(), "\n", 2)[0], `"width":101`)
		require.Contains(t, cast.String(), "got:timed")
	})

	t.Run("credential rotation aborts stream", func(t *testing.T) {
		secretKey := clusterCredentialSecret(t, ctx, s.Client, s.Cluster)
		started := make(chan struct{})
		rotated := make(chan struct{})
		go func() {
			defer close(rotated)
			select {
			case <-started:
			case <-ctx.Done():
				return
			}
			var secret corev1.Secret
			if err := s.Client.Get(ctx, secretKey, &secret); err != nil {
				t.Errorf("read credential secret: %v", err)
				return
			}
			patch := client.MergeFrom(secret.DeepCopy())
			if secret.Annotations == nil {
				secret.Annotations = map[string]string{}
			}
			secret.Annotations["e2e.breakglass.telekom.com/terminal-recording-rotation"] = fmt.Sprint(time.Now().UnixNano())
			if err := s.Client.Patch(ctx, &secret, patch); err != nil {
				t.Errorf("rotate credential secret: %v", err)
			}
		}()
		streamCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		result, err := requester.StreamRecordedTerminal(streamCtx, helpers.TerminalStreamRequest{
			Session: session.Name, SessionNamespace: session.Namespace, PodNamespace: pod.Namespace, PodName: pod.Name,
			Command: []string{"sh", "-c", `echo ready; sleep 90; echo not-aborted`},
			Interact: func(output <-chan string, _ io.Writer) error {
				defer close(started)
				for chunk := range output {
					if strings.Contains(chunk, "ready") {
						return nil
					}
				}
				return fmt.Errorf("stream ended before it was ready")
			},
		})
		<-rotated
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, result.StatusCode, result.Body)
		require.NotContains(t, result.Output, "not-aborted", "a rotated credential must abort the live stream")
		require.True(t, result.Aborted || result.Status == "incomplete", "the stream must not complete normally: %+v", result)
		var aborted helpers.TerminalRecordingListing
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			status, body, err := requester.GetRaw(ctx, base+sessionQuery)
			require.NoError(c, err)
			require.Equal(c, http.StatusOK, status, string(body))
			var listing []helpers.TerminalRecordingListing
			require.NoError(c, json.Unmarshal(body, &listing))
			found := false
			for _, entry := range listing {
				if entry.Recording != nil && !entry.Recording.Complete && entry.State == "Available" {
					aborted, found = entry, true
				}
			}
			require.True(c, found, "evidence captured before the abort is published as incomplete: %s", body)
		}, time.Minute, 2*time.Second)
		status, replay, err := requester.GetRaw(ctx, base+"/"+url.PathEscape(aborted.ArtifactID)+sessionQuery)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status, string(replay))
		parsed, err := recording.Parse(bytes.NewReader(replay))
		require.NoError(t, err)
		var output strings.Builder
		for _, frame := range parsed.Frames {
			output.Write(frame.Payload)
		}
		require.Contains(t, output.String(), "ready")
		require.NotContains(t, output.String(), "not-aborted")
	})
}

// markerWriter collects output and signals once marker was written.
type markerWriter struct {
	mu     sync.Mutex
	buf    bytes.Buffer
	marker string
	seen   chan struct{}
	once   sync.Once
}

func (w *markerWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.buf.Write(p)
	if strings.Contains(w.buf.String(), w.marker) {
		w.once.Do(func() { close(w.seen) })
	}
	return len(p), nil
}

func (w *markerWriter) String() string {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.String()
}

func typeAfterOutput(input, until string) func(<-chan string, io.Writer) error {
	return func(output <-chan string, stdin io.Writer) error {
		// Type only after the remote shell has produced its first byte, as a user would.
		select {
		case <-output:
		case <-time.After(2 * time.Second):
		}
		if _, err := io.WriteString(stdin, input); err != nil {
			return err
		}
		// Keep stdin open until the command answered: ending a TTY's stdin
		// early can end the exec before the shell read the line.
		var seen strings.Builder
		timeout := time.After(time.Minute)
		for {
			select {
			case chunk, ok := <-output:
				if !ok {
					return nil
				}
				seen.WriteString(chunk)
				if strings.Contains(seen.String(), until) {
					return nil
				}
			case <-timeout:
				return fmt.Errorf("no %q in terminal output %q", until, seen.String())
			}
		}
	}
}

// clusterCredentialSecret mirrors the controller's credential selection:
// kubeconfig, OIDC client/refresh Secret, or the IdentityProvider's Keycloak Secret.
func clusterCredentialSecret(t *testing.T, ctx context.Context, cli client.Client, cluster string) client.ObjectKey {
	t.Helper()
	var configs breakglassv1alpha1.ClusterConfigList
	require.NoError(t, cli.List(ctx, &configs))
	for _, config := range configs.Items {
		if config.Name != cluster {
			continue
		}
		refs := []*breakglassv1alpha1.SecretKeyReference{config.Spec.KubeconfigSecretRef}
		if oidc := config.Spec.OIDCAuth; oidc != nil {
			refs = append(refs, oidc.ClientSecretRef, oidc.RefreshTokenSecretRef)
		}
		if fromIDP := config.Spec.OIDCFromIdentityProvider; fromIDP != nil {
			refs = append(refs, fromIDP.ClientSecretRef, fromIDP.RefreshTokenSecretRef)
			var idp breakglassv1alpha1.IdentityProvider
			if fromIDP.ClientSecretRef == nil && fromIDP.RefreshTokenSecretRef == nil && cli.Get(ctx, client.ObjectKey{Name: fromIDP.Name}, &idp) == nil && idp.Spec.Keycloak != nil {
				refs = append(refs, &idp.Spec.Keycloak.ClientSecretRef)
			}
		}
		for _, ref := range refs {
			if ref != nil && ref.Name != "" {
				return client.ObjectKey{Namespace: ref.Namespace, Name: ref.Name}
			}
		}
		t.Fatalf("ClusterConfig %s has no credential Secret", cluster)
	}
	t.Fatalf("ClusterConfig %s not found", cluster)
	return client.ObjectKey{}
}
