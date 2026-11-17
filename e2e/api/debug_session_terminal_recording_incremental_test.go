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
	"os"
	"os/exec"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"sigs.k8s.io/controller-runtime/pkg/client"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/recording"
)

// TestDebugSessionTerminalRecordingIncrementalE2E covers the opt-in incremental
// flush (artifacts.terminalRecordingSegmentBytes, set to its 64 KiB minimum by
// e2e/fixtures/artifacts/setup.sh) against the real local and S3 backends:
// a backend failure mid-stream fails the stream closed, and a controller
// killed mid-stream leaves a committed prefix that is published as an
// incomplete, verifiable recording and removed again at retention expiry.
func TestDebugSessionTerminalRecordingIncrementalE2E(t *testing.T) {
	backend := os.Getenv("E2E_ARTIFACT_BACKEND")
	require.Contains(t, []string{"local", "s3"}, backend, "run e2e/fixtures/artifacts/setup.sh (and select-s3.sh) first")
	s := helpers.SetupTest(t, helpers.WithLongTimeout())
	ctx, ns := s.Ctx, s.Namespace
	ensureAuditPipeline(t, ctx, s)
	requesterUser := helpers.TestUsers.SecurityRequester
	requester := s.TC.ClientForUser(requesterUser)

	// Runs in the fixture sidecar, which shares the artifact volume and can
	// reach the provider; the same hooks the artifact lifecycle test uses.
	fixture := func(args ...string) string {
		base := []string{"-n", ns, "exec", "deployment/breakglass-manager", "-c", "artifact-tls", "--"}
		out, err := exec.CommandContext(ctx, "kubectl", append(base, args...)...).CombinedOutput()
		require.NoError(t, err, string(out))
		return string(out)
	}
	files := func() []string {
		args := []string{"find", "/artifacts/objects", "-type", "f"}
		if backend == "s3" {
			args = []string{"/fixture", "s3-inventory"}
		}
		var found []string
		for _, name := range strings.Fields(fixture(args...)) {
			if !strings.HasSuffix(name, "/.breakglass-artifact-instance-v1") {
				found = append(found, name)
			}
		}
		slices.Sort(found)
		return found
	}
	// Segments and manifests are backend objects: new files appear while a
	// recording is committed and must all be gone once it expired.
	baseline := files()
	newFiles := func() []string {
		return slices.DeleteFunc(files(), func(name string) bool { return slices.Contains(baseline, name) })
	}
	inject := func() (restore func()) {
		if backend == "s3" {
			fixture("touch", "/artifacts/provider-outage")
			return func() { fixture("rm", "-f", "/artifacts/provider-outage") }
		}
		fixture("chmod", "000", "/artifacts/objects")
		return func() { fixture("chmod", "700", "/artifacts/objects") }
	}
	base := func(session *breakglassv1alpha1.DebugSession) (string, string) {
		return "/api/debugSessions/" + url.PathEscape(session.Name) + "/terminal", "?namespace=" + url.QueryEscape(session.Namespace)
	}
	list := func(session *breakglassv1alpha1.DebugSession) (int, []helpers.TerminalRecordingListing) {
		path, query := base(session)
		status, body, err := requester.GetRaw(ctx, path+query)
		if err != nil || status != http.StatusOK {
			return status, nil
		}
		var listing []helpers.TerminalRecordingListing
		require.NoError(t, json.Unmarshal(body, &listing))
		return status, listing
	}
	// bigOutput writes well over one 64 KiB segment before the marker.
	bigOutput := func(tail string) []string {
		return []string{"sh", "-c", `echo ready; read line; head -c 400000 /dev/zero | tr '\0' a; echo ` + tail + `; sleep 300`}
	}
	// stream runs bigOutput once the first output arrived; inject, when set,
	// runs between "ready" and the bulk output.
	stream := func(session *breakglassv1alpha1.DebugSession, pod breakglassv1alpha1.AllowedPodRef, cid, tail string, between func()) helpers.TerminalStreamResult {
		var result helpers.TerminalStreamResult
		// The first stream of a session can conflict with a concurrent lease update.
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			streamCtx, cancel := context.WithTimeout(ctx, 4*time.Minute)
			defer cancel()
			var err error
			result, err = requester.StreamRecordedTerminal(streamCtx, helpers.TerminalStreamRequest{
				Session: session.Name, SessionNamespace: session.Namespace, PodNamespace: pod.Namespace, PodName: pod.Name,
				Command: bigOutput(tail), CorrelationID: cid,
				Interact: func(output <-chan string, stdin io.Writer) error {
					var seen strings.Builder
					deadline := time.After(time.Minute)
					for !strings.Contains(seen.String(), "ready") {
						select {
						case chunk, ok := <-output:
							if !ok {
								return fmt.Errorf("stream ended before it was ready: %q", seen.String())
							}
							seen.WriteString(chunk)
						case <-deadline:
							return fmt.Errorf("no ready marker in %q", seen.String())
						}
					}
					if between != nil {
						between()
					}
					if _, err := io.WriteString(stdin, "go\n"); err != nil {
						return err
					}
					// Keep stdin open until the stream ends or is cut.
					for range output {
					}
					return nil
				},
			})
			require.NoError(c, err)
			require.Equal(c, http.StatusOK, result.StatusCode, result.Body)
		}, 5*time.Minute, 2*time.Second)
		return result
	}

	t.Run("backend failure mid-stream fails closed", func(t *testing.T) {
		session, pod := recordedSessionFor(t, ctx, s, requester, requesterUser.Groups, s.Cluster, "10m", "1h")
		var restore func()
		t.Cleanup(func() {
			if restore != nil {
				restore()
			}
		})
		cid := uuid.NewString()
		result := stream(session, pod, cid, "after-backend-failure", func() { restore = inject() })
		require.NotEqual(t, "completed", result.Status, "a stream whose evidence cannot be stored never completes: %+v", result)
		require.NotContains(t, result.Output, "after-backend-failure", "no bytes pass once they cannot be recorded")

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			events, err := helpers.AuditEventsByCorrelation(ctx, cid)
			require.NoError(c, err)
			stages := []any{}
			for _, event := range events {
				if event.Type == "debug_session.terminal_recording_failed" {
					stages = append(stages, event.Details["stage"])
				}
			}
			require.Contains(c, stages, "flush", "the flush failure is audited: %+v", events)
		}, time.Minute, 2*time.Second)

		restore()
		restore = nil
		// Whatever evidence exists afterwards is incomplete, never a complete recording.
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			status, listing := list(session)
			require.Equal(c, http.StatusOK, status)
			for _, entry := range listing {
				require.NotNil(c, entry.Recording)
				require.False(c, entry.Recording.Complete, "no complete recording after a mid-stream backend failure")
			}
		}, helpers.WaitForStateTimeout, 2*time.Second)
	})

	t.Run("controller killed mid-stream publishes the committed prefix, retention removes it", func(t *testing.T) {
		// The first subtest's incomplete evidence stays until its own retention.
		baseline = files()
		session, pod := recordedSessionFor(t, ctx, s, requester, requesterUser.Groups, s.Cluster, "3m", "1m")
		require.NotNil(t, session.Status.ExpiresAt)

		cid := uuid.NewString()
		done := make(chan helpers.TerminalStreamResult, 1)
		go func() { done <- stream(session, pod, cid, "unreached", nil) }()
		// The prefix is committed once its segments exist in the backend, so the
		// kill below cannot race the first flush.
		require.Eventually(t, func() bool { return len(newFiles()) > 0 }, 2*time.Minute, 2*time.Second, "segments are flushed while the stream runs")
		killControllerPod(t, ctx, ns, requester)
		select {
		case result := <-done:
			require.NotEqual(t, "completed", result.Status, "the killed stream never completes: %+v", result)
			require.NotContains(t, result.Output, "unreached")
		case <-time.After(time.Minute):
		}

		// Recovery only publishes after the stream's binding (session) expired.
		var entry helpers.TerminalRecordingListing
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			status, listing := list(session)
			require.Equal(c, http.StatusOK, status)
			require.Len(c, listing, 1)
			entry = listing[0]
			require.NotNil(c, entry.Recording)
			require.NotEmpty(c, entry.SHA256, "the prefix is published")
		}, time.Until(session.Status.ExpiresAt.Time)+helpers.WaitForStateTimeout, 5*time.Second)
		require.False(t, entry.Recording.Complete, "a prefix recovered after a crash is incomplete")

		path, query := base(session)
		status, replay, err := requester.GetRaw(ctx, path+"/"+url.PathEscape(entry.ArtifactID)+query)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status, string(replay))
		digest := sha256.Sum256(replay)
		require.Equal(t, entry.SHA256, hex.EncodeToString(digest[:]))
		parsed, err := recording.Parse(bytes.NewReader(replay))
		require.NoError(t, err, "the recovered prefix has an intact hash chain")
		var output strings.Builder
		for _, frame := range parsed.Frames {
			if frame.Direction == recording.Output {
				output.Write(frame.Payload)
			}
		}
		require.Contains(t, output.String(), "aaaa", "committed output is readable")
		require.NotContains(t, output.String(), "unreached")

		// Retention: the recording and every segment/manifest disappear.
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			var artifact breakglassv1alpha1.DebugSessionArtifact
			list := &breakglassv1alpha1.DebugSessionArtifactList{}
			require.NoError(c, s.Client.List(ctx, list, client.InNamespace(ns)))
			for _, item := range list.Items {
				if item.Spec.ArtifactID == entry.ArtifactID {
					artifact = item
				}
			}
			require.Contains(c, []breakglassv1alpha1.ArtifactLifecycleState{"", breakglassv1alpha1.ArtifactStateExpired, breakglassv1alpha1.ArtifactStateDeleted}, artifact.Status.State, "retention expiry ends the recording")
			require.Empty(c, newFiles(), "recording object, segments and manifests are removed")
		}, 3*time.Minute+helpers.WaitForStateTimeout, 5*time.Second)
	})
}

// killControllerPod force-deletes the controller Pod (no graceful shutdown,
// like a crash or OOM kill) and waits, with bounded polls, until a different
// Pod is Ready and the API answers through the runner's port-forward again.
func killControllerPod(t *testing.T, ctx context.Context, ns string, api *helpers.APIClient) {
	t.Helper()
	pods := func() []corev1.Pod {
		out, err := exec.CommandContext(ctx, "kubectl", "-n", ns, "get", "pods", "-l", "app=breakglass", "-o", "json").Output()
		require.NoError(t, err)
		var podList corev1.PodList
		require.NoError(t, json.Unmarshal(out, &podList))
		return podList.Items
	}
	old := map[string]bool{}
	for _, pod := range pods() {
		old[string(pod.UID)] = true
	}
	require.NotEmpty(t, old)
	out, err := exec.CommandContext(ctx, "kubectl", "-n", ns, "delete", "pod", "-l", "app=breakglass", "--grace-period=0", "--force", "--wait=false").CombinedOutput()
	require.NoError(t, err, string(out))
	require.Eventually(t, func() bool {
		current := pods()
		if len(current) != 1 || old[string(current[0].UID)] || !current[0].DeletionTimestamp.IsZero() {
			return false
		}
		for _, condition := range current[0].Status.Conditions {
			if condition.Type == corev1.PodReady && condition.Status == corev1.ConditionTrue {
				return true
			}
		}
		return false
	}, 4*time.Minute, 2*time.Second, "a replacement controller Pod must become Ready")
	require.Eventually(t, func() bool {
		status, _, err := api.GetRaw(ctx, "/api/config")
		return err == nil && status == http.StatusOK
	}, 2*time.Minute, 2*time.Second, "the API must answer again through the port-forward")
}
