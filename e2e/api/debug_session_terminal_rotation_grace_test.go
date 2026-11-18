//go:build e2e

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

const rotationGraceE2E = 20 * time.Second

// TestDebugSessionTerminalRecordingRotationGraceE2E proves, on a real
// controller, that an active recorded session survives a controller rollover
// with its connection lease unchanged, and the opt-in blue/green credential
// rotation (artifacts.credentialRotationGrace): after a rotation a new stream
// runs immediately while the running stream keeps working until the grace
// deadline, then is cut. The default (no grace) is covered by
// TestDebugSessionTerminalRecordingE2E "credential rotation aborts stream".
//
// It reconfigures and restarts the controller, so CI runs it in its own step.
func TestDebugSessionTerminalRecordingRotationGraceE2E(t *testing.T) {
	if os.Getenv("E2E_TERMINAL_ROTATION_GRACE") != "true" {
		t.Skip("reconfigures and restarts the controller; set E2E_TERMINAL_ROTATION_GRACE=true")
	}
	s := helpers.SetupTest(t, helpers.WithLongTimeout())
	ctx := s.Ctx
	requesterUser := helpers.TestUsers.SecurityRequester
	requester := s.TC.ClientForUser(requesterUser)
	ensureAuditPipeline(t, ctx, s)

	session, pod := recordedSession(t, ctx, s, requester, requesterUser.Groups, s.Cluster)
	stream := func(c *assert.CollectT, command string, interact func(<-chan string, io.Writer) error, cid string) helpers.TerminalStreamResult {
		streamCtx, cancel := context.WithTimeout(ctx, 3*time.Minute)
		defer cancel()
		result, err := requester.StreamRecordedTerminal(streamCtx, helpers.TerminalStreamRequest{
			Session: session.Name, SessionNamespace: session.Namespace, PodNamespace: pod.Namespace, PodName: pod.Name,
			Command: []string{"sh", "-c", command}, Interact: interact, CorrelationID: cid,
		})
		require.NoError(c, err)
		require.Equal(c, http.StatusOK, result.StatusCode, result.Body)
		return result
	}
	short := func(marker string) {
		t.Helper()
		// A concurrent generation publish can make an attempt fail retryably.
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			result := stream(c, "echo "+marker, nil, "")
			require.Equal(c, "completed", result.Status)
			require.Contains(c, result.Output, marker)
		}, helpers.WaitForStateTimeout, 2*time.Second)
	}
	liveLease := func() breakglassv1alpha1.DebugSessionConnectionLease {
		t.Helper()
		live := &breakglassv1alpha1.DebugSession{}
		require.NoError(t, s.Client.Get(ctx, client.ObjectKeyFromObject(session), live))
		require.Equal(t, breakglassv1alpha1.DebugSessionStateActive, live.Status.State)
		require.NotNil(t, live.Status.ConnectionLease, "a recorded session holds a connection lease")
		return *live.Status.ConnectionLease
	}

	short("before-rollover")
	before := liveLease()

	t.Run("active session survives controller rollover", func(t *testing.T) {
		setCredentialRotationGrace(t, ctx, rotationGraceE2E.String())
		after := liveLease()
		require.Equal(t, before.UID, after.UID, "the session keeps its Lease across the rollover")
		require.Equal(t, before.Epoch, after.Epoch, "a rollover never re-fences the session")
		short("after-rollover")
	})

	t.Run("rotation keeps the running stream until the grace deadline", func(t *testing.T) {
		key := clusterCredentialSecret(t, ctx, s.Client, s.Cluster)
		var once sync.Once
		started := make(chan struct{})
		type outcome struct {
			rotated, greenDone time.Time
		}
		rotation := make(chan outcome, 1)
		go func() {
			select {
			case <-started:
			case <-ctx.Done():
				return
			}
			annotate(t, ctx, s.Client, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Namespace: key.Namespace, Name: key.Name}})
			rotated := time.Now()
			// New streams bind to the new generation while the old one drains.
			short("green")
			rotation <- outcome{rotated: rotated, greenDone: time.Now()}
		}()

		cid := uuid.NewString()
		var blue helpers.TerminalStreamResult
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			blue = stream(c, `echo ready; i=0; while [ $i -lt 120 ]; do sleep 1; i=$((i+1)); echo tick-$i; done; echo not-aborted`,
				func(output <-chan string, _ io.Writer) error {
					var seen strings.Builder
					for chunk := range output {
						seen.WriteString(chunk)
						if strings.Contains(seen.String(), "ready") {
							once.Do(func() { close(started) })
							return nil
						}
					}
					return fmt.Errorf("stream ended before it was ready")
				}, cid)
		}, time.Minute, 2*time.Second)
		blueDone := time.Now()

		var got outcome
		select {
		case got = <-rotation:
		case <-time.After(time.Minute):
			t.Fatal("no new-generation stream completed after the rotation")
		}
		require.True(t, got.greenDone.Before(blueDone), "the new stream ran while the old one was still draining")
		drained := blueDone.Sub(got.rotated)
		t.Logf("old stream drained %s after the rotation (grace %s)", drained, rotationGraceE2E)
		require.GreaterOrEqual(t, drained, rotationGraceE2E/2, "the old stream keeps working inside the grace period")
		require.Less(t, drained, rotationGraceE2E+30*time.Second, "the old stream is cut at the grace deadline")
		require.NotContains(t, blue.Output, "not-aborted")
		require.NotEqual(t, "completed", blue.Status)

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
		require.Contains(t, []any{"credential_changed", "lease_changed"}, finalized.Details["abortReason"], "a credential or lease fence ended the stream")
	})
}

// setCredentialRotationGrace sets artifacts.credentialRotationGrace in the
// controller config and restarts the controller; cleanup restores the
// original config and restarts again.
func setCredentialRotationGrace(t *testing.T, ctx context.Context, grace string) {
	t.Helper()
	ns := helpers.GetTestNamespace()
	kubectl := func(stdin string, args ...string) string {
		command := exec.CommandContext(ctx, "kubectl", append([]string{"-n", ns}, args...)...)
		if stdin != "" {
			command.Stdin = strings.NewReader(stdin)
		}
		out, err := command.CombinedOutput()
		require.NoError(t, err, string(out))
		return string(out)
	}
	name := strings.TrimSpace(kubectl("", "get", "deployment", "breakglass-manager", "-o", `jsonpath={.spec.template.spec.volumes[?(@.name=="config")].configMap.name}`))
	require.NotEmpty(t, name)
	var configMap map[string]any
	require.NoError(t, json.Unmarshal([]byte(kubectl("", "get", "configmap", name, "-o", "json")), &configMap))
	data := configMap["data"].(map[string]any)
	original := data["config.yaml"].(string)
	require.Contains(t, original, "\nartifacts:\n", "the artifact fixture configures terminal recording")
	require.NotContains(t, original, "credentialRotationGrace")
	apply := func(config string) {
		data["config.yaml"] = config
		body, err := json.Marshal(configMap)
		require.NoError(t, err)
		kubectl(string(body), "replace", "-f", "-")
		kubectl("", "rollout", "restart", "deployment/breakglass-manager")
		kubectl("", "rollout", "status", "deployment/breakglass-manager", "--timeout=180s")
		require.NoError(t, helpers.NewAPIClient().WaitForAPIReady(ctx, 2*time.Minute))
	}
	t.Cleanup(func() {
		// The configmap object carries the resourceVersion read above; drop it
		// so the restore replaces the current object.
		delete(configMap["metadata"].(map[string]any), "resourceVersion")
		apply(original)
	})
	delete(configMap["metadata"].(map[string]any), "resourceVersion")
	apply(strings.Replace(original, "\nartifacts:\n", "\nartifacts:\n  credentialRotationGrace: "+grace+"\n", 1))
}
