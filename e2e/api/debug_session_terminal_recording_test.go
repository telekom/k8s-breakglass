//go:build e2e

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/util/retry"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
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

	ensureAuditPipeline(t, ctx, s)

	session, pod := recordedSession(t, ctx, s, requester, requesterUser.Groups, s.Cluster)
	base := "/api/debugSessions/" + url.PathEscape(session.Name) + "/terminal"
	sessionQuery := "?namespace=" + url.QueryEscape(session.Namespace)

	t.Run("record retrieve verify", func(t *testing.T) {
		const typed = "hello-recording"
		var result helpers.TerminalStreamResult
		streamCID := uuid.NewString()
		// The first stream of a session publishes the credential generation; a
		// concurrent controller lease update can make that attempt conflict.
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			streamCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
			defer cancel()
			var streamErr error
			result, streamErr = requester.StreamRecordedTerminal(streamCtx, helpers.TerminalStreamRequest{
				Session: session.Name, SessionNamespace: session.Namespace, PodNamespace: pod.Namespace, PodName: pod.Name,
				Command:  []string{"sh", "-c", `read line; echo "recorded:$line"`},
				Interact: typeAfterOutput(typed+"\n", "recorded:"+typed), CorrelationID: streamCID,
			})
			require.NoError(c, streamErr)
			require.Equal(c, http.StatusOK, result.StatusCode, result.Body)
		}, helpers.WaitForStateTimeout, 2*time.Second)
		require.Contains(t, result.Output, "recorded:"+typed)
		require.Equal(t, "completed", result.Status)
		require.NotEmpty(t, result.RecordingID)
		require.Len(t, result.SHA256, 64)

		listCID, replayCID := uuid.NewString(), uuid.NewString()
		status, listed, err := requester.GetRawWithCID(ctx, base+sessionQuery, listCID)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status, string(listed))
		require.Contains(t, string(listed), result.RecordingID)

		status, replay, err := requester.GetRawWithCID(ctx, base+"/"+url.PathEscape(result.RecordingID)+sessionQuery, replayCID)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status, string(replay))
		digest := sha256.Sum256(replay)
		require.Equal(t, result.SHA256, hex.EncodeToString(digest[:]), "replayed bytes must match the published digest")
		frames, err := helpers.ParseTerminalRecording(replay)
		require.NoError(t, err, "the replayed recording must have an intact hash chain")
		var input, output strings.Builder
		for _, frame := range frames {
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

		t.Run("audit events acknowledged by the sink", func(t *testing.T) {
			// Delivery is synchronous: the events are at the receiver once the
			// responses were returned.
			byType := func(cid string) map[string]helpers.ReceivedAuditEvent {
				events, err := helpers.AuditEventsByCorrelation(ctx, cid)
				require.NoError(t, err)
				found := map[string]helpers.ReceivedAuditEvent{}
				for _, event := range events {
					found[event.Type] = event
				}
				return found
			}
			stream := byType(streamCID)
			require.Contains(t, stream, "debug_session.terminal_recording_started")
			finalized := stream["debug_session.terminal_recording_finalized"]
			require.Equal(t, result.RecordingID, finalized.Details["recordingId"])
			require.Equal(t, result.SHA256, finalized.Details["sha256"])
			require.Equal(t, true, finalized.Details["complete"])
			require.NotContains(t, fmt.Sprint(stream), typed, "terminal bytes never reach audit")
			listedEvent := byType(listCID)["debug_session.terminal_recording_accessed"]
			require.Equal(t, "list", listedEvent.Details["access"])
			replayed := byType(replayCID)["debug_session.terminal_recording_accessed"]
			require.Equal(t, "replay", replayed.Details["access"])
			require.Equal(t, result.RecordingID, replayed.Details["recordingId"])
			require.Equal(t, result.SHA256, replayed.Details["sha256"])
			require.Equal(t, requesterUser.Email, replayed.Actor.User)
		})

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

	t.Run("credential rotation aborts stream", func(t *testing.T) {
		key := clusterCredentialSecret(t, ctx, s.Client, s.Cluster)
		assertRotationAborts(t, ctx, s, requester, session, pod, "credential_changed", func() {
			annotate(t, ctx, s.Client, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name}})
		})
	})

	t.Run("audit sink unavailable fails closed", func(t *testing.T) {
		breakAuditSinks(t, ctx, s)
		// Wait until the controller runs the broken pipeline (listing refused),
		// then prove streams and reads both fail closed.
		require.Eventually(t, func() bool {
			status, _, err := requester.GetRaw(ctx, base+sessionQuery)
			return err == nil && status == http.StatusServiceUnavailable
		}, 2*time.Minute, 2*time.Second, "reads are refused once access cannot be audited")
		status, body, err := requester.GetRaw(ctx, base+sessionQuery)
		require.NoError(t, err)
		require.Equal(t, http.StatusServiceUnavailable, status)
		require.NotContains(t, string(body), "artifactID", "no recording metadata without an audited read")
		streamCtx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		marker := "audit-down-" + uuid.NewString()
		result, err := requester.StreamRecordedTerminal(streamCtx, helpers.TerminalStreamRequest{
			Session: session.Name, SessionNamespace: session.Namespace, PodNamespace: pod.Namespace, PodName: pod.Name,
			Command: []string{"sh", "-c", "echo " + marker},
		})
		require.NoError(t, err)
		require.Equal(t, http.StatusServiceUnavailable, result.StatusCode, result.Body)
		require.NotContains(t, result.Output, marker, "nothing executes without a delivered start event")
	})
}

// recordedSession creates an active recorded workload session on cluster.
func recordedSession(t *testing.T, ctx context.Context, s *helpers.TestSetup, requester *helpers.APIClient, groups []string, cluster string) (*breakglassv1alpha1.DebugSession, breakglassv1alpha1.AllowedPodRef) {
	t.Helper()
	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("terminal-recording")},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			Mode: breakglassv1alpha1.DebugSessionModeWorkload, TargetNamespace: s.Namespace,
			Allowed:              &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{cluster}, Groups: groups},
			AllowedPodOperations: &breakglassv1alpha1.AllowedPodOperations{Exec: ptr.To(true)},
			Audit:                &breakglassv1alpha1.DebugSessionAuditConfig{EnableTerminalRecording: true, RecordingRetention: "1h"},
			PodTemplateString:    recordedPodTemplate,
		},
	}
	require.NoError(t, s.CreateResource(template))
	session, err := requester.CreateDebugSession(ctx, t, helpers.DebugSessionRequest{TemplateRef: template.Name, Cluster: cluster, RequestedDuration: "30m", Reason: "terminal recording e2e"})
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
	return active, active.Status.AllowedPods[0]
}

const recordedPodTemplate = `apiVersion: v1
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
`

// annotate makes a metadata-only change, which changes resourceVersion.
func annotate(t *testing.T, ctx context.Context, cli client.Client, obj client.Object) {
	t.Helper()
	require.NoError(t, cli.Get(ctx, client.ObjectKeyFromObject(obj), obj))
	patch := client.MergeFrom(obj.DeepCopyObject().(client.Object))
	annotations := obj.GetAnnotations()
	if annotations == nil {
		annotations = map[string]string{}
	}
	annotations["e2e.breakglass.telekom.com/terminal-recording-rotation"] = fmt.Sprint(time.Now().UnixNano())
	obj.SetAnnotations(annotations)
	require.NoError(t, cli.Patch(ctx, obj, patch))
}

// assertRotationAborts runs a long recorded stream, applies change once the
// stream is running, and proves the stream was cut by the named fence: the
// client sees no completion, the evidence is published incomplete, and the
// acknowledged finalized audit event says complete=false with that reason.
func assertRotationAborts(t *testing.T, ctx context.Context, s *helpers.TestSetup, requester *helpers.APIClient, session *breakglassv1alpha1.DebugSession, pod breakglassv1alpha1.AllowedPodRef, reason string, change func()) {
	t.Helper()
	started := make(chan struct{})
	changed := make(chan struct{})
	go func() {
		defer close(changed)
		select {
		case <-started:
			change()
		case <-ctx.Done():
		}
	}()
	cid := uuid.NewString()
	var result helpers.TerminalStreamResult
	// A previous stream's claim or a generation published by another replica
	// can make the first attempt fail retryably.
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		streamCtx, cancel := context.WithTimeout(ctx, 2*time.Minute)
		defer cancel()
		var err error
		result, err = requester.StreamRecordedTerminal(streamCtx, helpers.TerminalStreamRequest{
			Session: session.Name, SessionNamespace: session.Namespace, PodNamespace: pod.Namespace, PodName: pod.Name,
			Command: []string{"sh", "-c", `echo ready; sleep 90; echo not-aborted`}, CorrelationID: cid,
			Interact: func(output <-chan string, _ io.Writer) error {
				var seen strings.Builder
				for chunk := range output {
					seen.WriteString(chunk)
					if strings.Contains(seen.String(), "ready") {
						close(started)
						return nil
					}
				}
				return fmt.Errorf("stream ended before it was ready")
			},
		})
		require.NoError(c, err)
		require.Equal(c, http.StatusOK, result.StatusCode, result.Body)
	}, time.Minute, 2*time.Second)
	<-changed
	require.NotContains(t, result.Output, "not-aborted", "the change must abort the live stream")
	require.NotEqual(t, "completed", result.Status, "an aborted stream never reports completion: %+v", result)

	var finalized helpers.ReceivedAuditEvent
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		events, err := helpers.AuditEventsByCorrelation(ctx, cid)
		require.NoError(c, err)
		found := false
		for _, event := range events {
			if event.Type == "debug_session.terminal_recording_finalized" {
				finalized, found = event, true
			}
		}
		require.True(c, found, "the finalized event is delivered: %+v", events)
	}, time.Minute, 2*time.Second)
	require.Equal(t, false, finalized.Details["complete"])
	require.Equal(t, reason, finalized.Details["abortReason"], "the expected fence ended the stream")

	recordingID, _ := finalized.Details["recordingId"].(string)
	require.NotEmpty(t, recordingID)
	base := "/api/debugSessions/" + url.PathEscape(session.Name) + "/terminal"
	sessionQuery := "?namespace=" + url.QueryEscape(session.Namespace)
	status, body, err := requester.GetRaw(ctx, base+sessionQuery)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status, string(body))
	var listing []helpers.TerminalRecordingListing
	require.NoError(t, json.Unmarshal(body, &listing))
	var entry *helpers.TerminalRecordingListing
	for i := range listing {
		if listing[i].ArtifactID == recordingID {
			entry = &listing[i]
		}
	}
	require.NotNil(t, entry, "the aborted stream's evidence is retained")
	require.NotNil(t, entry.Recording)
	require.False(t, entry.Recording.Complete)
	status, replay, err := requester.GetRaw(ctx, base+"/"+url.PathEscape(recordingID)+sessionQuery)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status, string(replay))
	frames, err := helpers.ParseTerminalRecording(replay)
	require.NoError(t, err)
	var output strings.Builder
	for _, frame := range frames {
		output.Write(frame.Payload)
	}
	require.Contains(t, output.String(), "ready")
	require.NotContains(t, output.String(), "not-aborted")
}

// breakAuditSinks points every webhook sink at an address nothing listens on
// and restores the originals afterwards.
func breakAuditSinks(t *testing.T, ctx context.Context, s *helpers.TestSetup) {
	t.Helper()
	var configs breakglassv1alpha1.AuditConfigList
	require.NoError(t, s.Client.List(ctx, &configs))
	originals := map[string]breakglassv1alpha1.AuditConfigSpec{}
	for i := range configs.Items {
		config := &configs.Items[i]
		if !config.Spec.Enabled {
			continue
		}
		originals[config.Name] = *config.Spec.DeepCopy()
		spec := config.Spec.DeepCopy()
		var sinks []breakglassv1alpha1.AuditSinkConfig
		for _, sink := range spec.Sinks {
			// Only sinks that confirm delivery count; disabling the others
			// leaves the dead webhook as the sole confirming sink.
			if sink.Type == breakglassv1alpha1.AuditSinkTypeWebhook {
				sink.Webhook.URL = "http://127.0.0.1:9/audit"
				sink.Webhook.TimeoutSeconds = 2
				sinks = append(sinks, sink)
			}
		}
		if len(sinks) == 0 {
			spec.Enabled = false
		} else {
			spec.Sinks = sinks
		}
		patch := client.MergeFrom(config.DeepCopy())
		config.Spec = *spec
		require.NoError(t, s.Client.Patch(ctx, config, patch))
	}
	t.Cleanup(func() {
		for name, spec := range originals {
			require.NoError(t, retry.RetryOnConflict(retry.DefaultRetry, func() error {
				var config breakglassv1alpha1.AuditConfig
				if err := s.Client.Get(context.Background(), client.ObjectKey{Name: name}, &config); err != nil {
					return client.IgnoreNotFound(err)
				}
				config.Spec = spec
				return s.Client.Update(context.Background(), &config)
			}), "restore AuditConfig %s", name)
		}
		ensureAuditPipeline(t, context.Background(), s)
	})
	// The controller reloads AuditConfigs asynchronously; the caller polls
	// until requests are refused.
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

// TestDebugSessionTerminalRecordingIdPInputsE2E proves, on a real OIDC spoke
// (multi-cluster lane), that changing any non-primary credential input of an
// oidcFromIdentityProvider ClusterConfig aborts a live recorded stream: the
// IdentityProvider object, the CA Secret, and the IdentityProvider's Keycloak
// Secret that the controller falls back to without an explicit client secret.
func TestDebugSessionTerminalRecordingIdPInputsE2E(t *testing.T) {
	if !helpers.IsMultiClusterEnabled() {
		t.Skip("needs an OIDC-authenticated spoke (multi-cluster lane)")
	}
	s := helpers.SetupTest(t, helpers.WithLongTimeout())
	ctx := s.Ctx
	ensureAuditPipeline(t, ctx, s)
	requesterUser := helpers.TestUsers.SecurityRequester
	requester := s.TC.ClientForUser(requesterUser)

	var idps breakglassv1alpha1.IdentityProviderList
	require.NoError(t, s.Client.List(ctx, &idps))
	var idp *breakglassv1alpha1.IdentityProvider
	for i := range idps.Items {
		if idps.Items[i].Spec.Keycloak != nil && idps.Items[i].Spec.Keycloak.ClientSecretRef.Name != "" {
			idp = &idps.Items[i]
		}
	}
	require.NotNil(t, idp, "the multi-cluster fixture provides an IdentityProvider with a Keycloak service account")
	// A dedicated, empty CA Secret: the controller pins the spoke CA into it
	// on first use (TOFU), so it is a live input of this ClusterConfig.
	caSecret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("recording-ca"), Namespace: s.Namespace, Labels: helpers.E2ETestLabels()}}
	require.NoError(t, s.CreateResource(caSecret))
	name := helpers.GenerateUniqueName("recording-idp")
	cc := helpers.NewClusterConfigBuilder(name, s.Namespace).WithOIDCFromIdentityProvider(idp.Name, helpers.GetOIDCEnabledAPIServerURL()).Build()
	cc.Spec.OIDCFromIdentityProvider.ClientID = idp.Spec.Keycloak.ClientID
	cc.Spec.OIDCFromIdentityProvider.AllowTOFU = true
	cc.Spec.OIDCFromIdentityProvider.CASecretRef = &breakglassv1alpha1.SecretKeyReference{Name: caSecret.Name, Namespace: caSecret.Namespace, Key: breakglassv1alpha1.DefaultCASecretKey}
	require.NoError(t, s.CreateResource(cc))
	require.NoError(t, waitForClusterConfigConditionReady(t, ctx, s.Client, name, s.Namespace, 2*time.Minute), "the oidcFromIdentityProvider ClusterConfig must authenticate to the spoke")

	session, pod := recordedSession(t, ctx, s, requester, requesterUser.Groups, name)
	keycloak := idp.Spec.Keycloak.ClientSecretRef
	for change, object := range map[string]client.Object{
		"identity provider":        &breakglassv1alpha1.IdentityProvider{ObjectMeta: metav1.ObjectMeta{Name: idp.Name}},
		"ca secret":                &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: caSecret.Namespace, Name: caSecret.Name}},
		"keycloak fallback secret": &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: keycloak.Namespace, Name: keycloak.Name}},
	} {
		t.Run(change, func(t *testing.T) {
			assertRotationAborts(t, ctx, s, requester, session, pod, "credential_changed", func() { annotate(t, ctx, s.Client, object) })
		})
	}
}
