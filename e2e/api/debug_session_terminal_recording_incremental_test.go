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

// recoveryGrace mirrors the artifact controller's wait after a stream's expiry
// before it publishes the committed prefix (terminalRecordingRecoveryGrace),
// plus one 30s reconcile interval.
const recoveryGrace = 90 * time.Second

// TestDebugSessionTerminalRecordingIncrementalE2E covers the opt-in incremental
// flush (artifacts.terminalRecordingSegmentBytes, set to its 64 KiB minimum by
// e2e/fixtures/artifacts/setup.sh in the multi-cluster lanes; the
// single-cluster lanes keep the default in-memory path) against the real local
// and S3 backends: a backend failure mid-stream fails the stream closed, and a
// controller killed mid-stream leaves a committed prefix that the artifact
// controller publishes as an incomplete, verifiable, audited recording, which
// retention removes again.
func TestDebugSessionTerminalRecordingIncrementalE2E(t *testing.T) {
	if os.Getenv("E2E_RECORDING_SEGMENT_BYTES") == "" {
		t.Skip("incremental flush is enabled only in the multi-cluster artifact lanes")
	}
	backend := os.Getenv("E2E_ARTIFACT_BACKEND")
	require.Contains(t, []string{"local", "s3"}, backend, "run e2e/fixtures/artifacts/setup.sh (and select-s3.sh) first")
	// Session expiry, recovery grace and retention alone take about 8 minutes.
	s := helpers.SetupTest(t, helpers.WithTimeout(20*time.Minute))
	ctx, ns := s.Ctx, s.Namespace
	ensureAuditPipeline(t, ctx, s)
	requesterUser := helpers.TestUsers.SecurityRequester
	requester := s.TC.ClientForUser(requesterUser)

	// Tokens live 5 minutes and these subtests run longer; streams and GetRaw
	// bypass the client's 401 refresh, so refresh explicitly.
	fresh := func() {
		if token := requester.RefreshToken(ctx); token != "" {
			requester.AuthToken = token
		}
	}
	get := func(path string) (int, []byte, error) {
		status, body, err := requester.GetRaw(ctx, path)
		if err == nil && status == http.StatusUnauthorized {
			fresh()
			status, body, err = requester.GetRaw(ctx, path)
		}
		return status, body, err
	}

	// Runs in the fixture sidecar, which shares the artifact volume and can
	// reach the provider; the same hooks the artifact lifecycle test uses.
	fixture := func(args ...string) (string, error) {
		base := []string{"-n", ns, "exec", "deployment/breakglass-manager", "-c", "artifact-tls", "--"}
		out, err := exec.CommandContext(ctx, "kubectl", append(base, args...)...).CombinedOutput()
		if err != nil {
			return "", fmt.Errorf("%v: %w: %s", args, err, out)
		}
		return string(out), nil
	}
	files := func() ([]string, error) {
		args := []string{"find", "/artifacts/objects", "-type", "f"}
		if backend == "s3" {
			args = []string{"/fixture", "s3-inventory"}
		}
		out, err := fixture(args...)
		if err != nil {
			return nil, err
		}
		var found []string
		for _, name := range strings.Fields(out) {
			if !strings.HasSuffix(name, "/.breakglass-artifact-instance-v1") && !strings.HasPrefix(name, "delete:") {
				found = append(found, name)
			}
		}
		slices.Sort(found)
		return found, nil
	}
	// Segments, manifests and recordings are backend objects; count the ones
	// that appeared after baseline.
	newFiles := func(baseline []string) (int, error) {
		current, err := files()
		if err != nil {
			return 0, err
		}
		return len(slices.DeleteFunc(current, func(name string) bool { return slices.Contains(baseline, name) })), nil
	}
	inject := func() (restore func() error, err error) {
		if backend == "s3" {
			_, err = fixture("touch", "/artifacts/provider-outage")
			return func() error { _, err := fixture("rm", "-f", "/artifacts/provider-outage"); return err }, err
		}
		_, err = fixture("chmod", "000", "/artifacts/objects")
		return func() error { _, err := fixture("chmod", "700", "/artifacts/objects"); return err }, err
	}
	paths := func(session *breakglassv1alpha1.DebugSession) (string, string) {
		return "/api/debugSessions/" + url.PathEscape(session.Name) + "/terminal", "?namespace=" + url.QueryEscape(session.Namespace)
	}
	list := func(session *breakglassv1alpha1.DebugSession) (int, []helpers.TerminalRecordingListing, error) {
		path, query := paths(session)
		status, body, err := get(path + query)
		if err != nil || status != http.StatusOK {
			return status, nil, err
		}
		var listing []helpers.TerminalRecordingListing
		return status, listing, json.Unmarshal(body, &listing)
	}
	// stream runs command until it printed marker, calls between, then types
	// "go" and keeps stdin open until the stream ends. Only a lease conflict on
	// a session's first stream is retried; nothing runs on a refused attempt.
	// Callers refresh the token first (fresh is not safe off the test goroutine).
	stream := func(streamCtx context.Context, session *breakglassv1alpha1.DebugSession, pod breakglassv1alpha1.AllowedPodRef, cid, command, marker string, between func() error) (helpers.TerminalStreamResult, error) {
		for attempt := 0; ; attempt++ {
			result, err := requester.StreamRecordedTerminal(streamCtx, helpers.TerminalStreamRequest{
				Session: session.Name, SessionNamespace: session.Namespace, PodNamespace: pod.Namespace, PodName: pod.Name,
				Command: []string{"sh", "-c", command}, CorrelationID: cid,
				Interact: func(output <-chan string, stdin io.Writer) error {
					var seen strings.Builder
					deadline := time.After(2 * time.Minute)
					for !strings.Contains(seen.String(), marker) {
						select {
						case chunk, ok := <-output:
							if !ok {
								return fmt.Errorf("stream ended before %q: %q", marker, seen.String())
							}
							seen.WriteString(chunk)
						case <-deadline:
							return fmt.Errorf("no %q in %q", marker, seen.String())
						}
					}
					if between != nil {
						if err := between(); err != nil {
							return err
						}
					}
					if _, err := io.WriteString(stdin, "go\n"); err != nil {
						return err
					}
					for range output {
					}
					return nil
				},
			})
			retry := err == nil && (result.StatusCode == http.StatusConflict || result.StatusCode == http.StatusServiceUnavailable) && attempt < 10
			if !retry {
				if err == nil && result.StatusCode != http.StatusOK {
					err = fmt.Errorf("stream refused with %d: %s", result.StatusCode, result.Body)
				}
				return result, err
			}
			time.Sleep(2 * time.Second)
		}
	}

	t.Run("backend failure mid-stream fails closed", func(t *testing.T) {
		// 30m: its committed prefix is recovered long after this test, so the
		// next subtest's object counts are not disturbed.
		session, pod := recordedSessionFor(t, ctx, s, requester, requesterUser.Groups, s.Cluster, "30m", "1h")
		baseline, err := files()
		require.NoError(t, err)
		restore := func() error { return nil }
		t.Cleanup(func() { assert.NoError(t, restore()) })
		cid := uuid.NewString()
		var injectedAt time.Time
		streamCtx, cancel := context.WithTimeout(ctx, 4*time.Minute)
		defer cancel()
		fresh()
		// 200 KB before the gate: segments are committed while the backend works.
		result, err := stream(streamCtx, session, pod, cid,
			`head -c 200000 /dev/zero | tr '\0' b; echo; echo flushed; read line; head -c 400000 /dev/zero | tr '\0' a; echo after-backend-failure; sleep 300`,
			"flushed", func() (err error) {
				// A failed gate ends the stream instead of waiting for the target's sleep.
				defer func() {
					if err != nil {
						cancel()
					}
				}()
				deadline := time.Now().Add(time.Minute)
				for {
					n, err := newFiles(baseline)
					if err != nil {
						return err
					}
					if n >= 2 {
						break
					}
					if time.Now().After(deadline) {
						return fmt.Errorf("no segment was committed while the backend worked")
					}
					time.Sleep(time.Second)
				}
				r, err := inject()
				restore, injectedAt = r, time.Now()
				return err
			})
		require.NoError(t, err)
		require.False(t, injectedAt.IsZero())
		require.Less(t, time.Since(injectedAt), time.Minute, "the stream ends at the failed flush, not at the target's exit")
		require.NotEqual(t, "completed", result.Status, "a stream whose evidence cannot be stored never completes: %+v", result)
		require.NotContains(t, result.Output, "after-backend-failure", "no bytes pass once they cannot be recorded")

		require.EventuallyWithT(t, func(c *assert.CollectT) {
			events, err := helpers.AuditEventsByCorrelation(ctx, cid)
			require.NoError(c, err)
			var stages []any
			for _, event := range events {
				if event.Type == "debug_session.terminal_recording_failed" {
					stages = append(stages, event.Details["stage"])
				}
			}
			require.Contains(c, stages, "flush", "the flush failure is audited: %+v", events)
		}, time.Minute, 2*time.Second)

		require.NoError(t, restore())
		restore = func() error { return nil }
		// Publication failed with the backend; the committed prefix waits for
		// recovery after the stream binding expired, so nothing is listed.
		status, listing, err := list(session)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)
		require.Empty(t, listing, "no recording is published from a stream whose backend failed")
	})

	t.Run("controller killed mid-stream publishes the committed prefix, retention removes it", func(t *testing.T) {
		session, pod := recordedSessionFor(t, ctx, s, requester, requesterUser.Groups, s.Cluster, "3m", "3m")
		require.NotNil(t, session.Status.ExpiresAt)
		baseline, err := files()
		require.NoError(t, err)

		cid := uuid.NewString()
		type outcome struct {
			result helpers.TerminalStreamResult
			err    error
		}
		done := make(chan outcome, 1)
		streamCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		t.Cleanup(cancel)
		fresh()
		go func() {
			result, err := stream(streamCtx, session, pod, cid, `echo ready; read line; head -c 400000 /dev/zero | tr '\0' a; echo unreached; sleep 300`, "ready", nil)
			done <- outcome{result, err}
		}()
		// Segment and manifest objects: the prefix is committed before the kill.
		require.Eventually(t, func() bool { n, err := newFiles(baseline); return err == nil && n >= 2 }, 2*time.Minute, time.Second, "segments are flushed while the stream runs")
		killControllerPod(t, ctx, ns, requester)
		select {
		case o := <-done:
			require.NoError(t, o.err)
			require.NotEqual(t, "completed", o.result.Status, "the killed stream never completes: %+v", o.result)
		case <-time.After(time.Minute):
			t.Fatal("the stream did not end when its controller died")
		}

		// The stream's handler died: nothing is published before the recovery.
		status, listing, err := list(session)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status)
		require.Empty(t, listing, "nothing is published before the stream expired")

		var entry helpers.TerminalRecordingListing
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			status, listing, err := list(session)
			require.NoError(c, err)
			require.Equal(c, http.StatusOK, status)
			require.Len(c, listing, 1)
			entry = listing[0]
			require.NotNil(c, entry.Recording)
			require.NotEmpty(c, entry.SHA256, "the prefix is published")
		}, time.Until(session.Status.ExpiresAt.Time)+recoveryGrace+helpers.WaitForStateTimeout, 5*time.Second)
		require.False(t, entry.Recording.Complete, "a prefix recovered after a crash is incomplete")

		path, query := paths(session)
		status, replay, err := get(path + "/" + url.PathEscape(entry.ArtifactID) + query)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, status, string(replay))
		digest := sha256.Sum256(replay)
		require.Equal(t, entry.SHA256, hex.EncodeToString(digest[:]))
		parsed, err := recording.Parse(bytes.NewReader(replay))
		require.NoError(t, err, "the recovered prefix has an intact hash chain")
		require.EqualValues(t, len(parsed.Frames), entry.Recording.Frames)
		var output strings.Builder
		for _, frame := range parsed.Frames {
			if frame.Direction == recording.Output {
				output.Write(frame.Payload)
			}
		}
		require.Contains(t, output.String(), "ready")
		require.Contains(t, output.String(), strings.Repeat("a", 64<<10), "committed segments are readable")
		require.Less(t, strings.Count(output.String(), "a"), 400000, "the uncommitted tail is not in the prefix")
		require.NotContains(t, output.String(), "unreached")

		// The artifact controller audits the recovery after it removed the
		// segments and manifests; the dead handler published nothing.
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			events, err := helpers.AuditEvents(ctx)
			require.NoError(c, err)
			var recovered int
			for _, event := range events {
				if event.Type != "debug_session.terminal_recording_finalized" {
					continue
				}
				require.False(c, event.RequestContext != nil && event.RequestContext.CorrelationID == cid, "the killed handler published nothing")
				if event.Details["recordingId"] == entry.ArtifactID {
					require.Equal(c, true, event.Details["recovered"])
					require.Equal(c, false, event.Details["complete"])
					require.Equal(c, entry.SHA256, event.Details["sha256"])
					require.Equal(c, "system", event.Actor.User)
					recovered++
				}
			}
			require.Equal(c, 1, recovered, "the recovery is audited once")
			n, err := newFiles(baseline)
			require.NoError(c, err)
			require.Equal(c, 1, n, "after publication only the recording object remains; segments and manifests are removed")
		}, helpers.WaitForStateTimeout, 2*time.Second)

		// Retention: the recording object disappears.
		require.EventuallyWithT(t, func(c *assert.CollectT) {
			artifacts := &breakglassv1alpha1.DebugSessionArtifactList{}
			require.NoError(c, s.Client.List(ctx, artifacts, client.InNamespace(ns)))
			for _, item := range artifacts.Items {
				if item.Spec.ArtifactID == entry.ArtifactID {
					require.Contains(c, []breakglassv1alpha1.ArtifactLifecycleState{breakglassv1alpha1.ArtifactStateExpired, breakglassv1alpha1.ArtifactStateDeleted}, item.Status.State, "retention expiry ends the recording")
				}
			}
			n, err := newFiles(baseline)
			require.NoError(c, err)
			require.Zero(c, n, "the recording object is removed")
		}, time.Until(session.Status.ExpiresAt.Time.Add(3*time.Minute))+2*helpers.WaitForStateTimeout, 5*time.Second)
	})
}

// killControllerPod force-deletes the controller Pod and waits, with bounded
// polls, until a different Pod is Ready and the API answers through the
// runner's port-forward again. The kubelet may still send SIGTERM, but the
// handler's stream ends with the Pod, and the test checks the handler
// published nothing.
func killControllerPod(t *testing.T, ctx context.Context, ns string, api *helpers.APIClient) {
	t.Helper()
	pods := func() ([]corev1.Pod, error) {
		out, err := exec.CommandContext(ctx, "kubectl", "-n", ns, "get", "pods", "-l", "app=breakglass", "-o", "json").Output()
		if err != nil {
			return nil, err
		}
		var podList corev1.PodList
		return podList.Items, json.Unmarshal(out, &podList)
	}
	current, err := pods()
	require.NoError(t, err)
	old := map[string]bool{}
	for _, pod := range current {
		old[string(pod.UID)] = true
	}
	require.NotEmpty(t, old)
	out, err := exec.CommandContext(ctx, "kubectl", "-n", ns, "delete", "pod", "-l", "app=breakglass", "--grace-period=0", "--force", "--wait=false").CombinedOutput()
	require.NoError(t, err, string(out))
	require.Eventually(t, func() bool {
		current, err := pods()
		if err != nil || len(current) != 1 || old[string(current[0].UID)] || !current[0].DeletionTimestamp.IsZero() {
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
