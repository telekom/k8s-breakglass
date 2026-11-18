//go:build e2e

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/require"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestDebugSessionTerminalRecordingLimitsE2E checks the effective terminal
// recording limits on a real controller. e2e/fixtures/artifacts/setup.sh keeps
// the defaults (uploadMaxBytes, 2 streams) in the single-cluster lanes and sets
// artifacts.terminalRecordingMaxBytes/MaxConcurrent in the multi-cluster lanes,
// and exports the expected values as E2E_RECORDING_MAX_BYTES/_STREAMS.
func TestDebugSessionTerminalRecordingLimitsE2E(t *testing.T) {
	maxBytes, err := strconv.ParseInt(os.Getenv("E2E_RECORDING_MAX_BYTES"), 10, 64)
	require.NoError(t, err, "run e2e/fixtures/artifacts/setup.sh first")
	maxStreams, err := strconv.Atoi(os.Getenv("E2E_RECORDING_MAX_STREAMS"))
	require.NoError(t, err, "run e2e/fixtures/artifacts/setup.sh first")
	require.GreaterOrEqual(t, maxStreams, 2, "the byte subtests use two of the sessions")

	s := helpers.SetupTest(t, helpers.WithLongTimeout())
	ctx := s.Ctx
	ensureAuditPipeline(t, ctx, s)
	requesterUser := helpers.TestUsers.SecurityRequester
	requester := s.TC.ClientForUser(requesterUser)
	// A recorded stream holds its session's connection lease exclusively, so
	// concurrent streams need one session (and target Pod) each.
	type target struct {
		session *breakglassv1alpha1.DebugSession
		pod     breakglassv1alpha1.AllowedPodRef
	}
	targets := make([]target, maxStreams)
	for i := range targets {
		targets[i].session, targets[i].pod = recordedSession(t, ctx, s, requester, requesterUser.Groups, s.Cluster)
	}
	request := func(on target, command string, interact func(<-chan string, io.Writer) error) helpers.TerminalStreamRequest {
		session, pod := on.session, on.pod
		return helpers.TerminalStreamRequest{
			Session: session.Name, SessionNamespace: session.Namespace, PodNamespace: pod.Namespace, PodName: pod.Name,
			Command: []string{"sh", "-c", command}, Interact: interact,
		}
	}
	// Streams bypass the client's 401 refresh; start each subtest with a fresh token.
	refresh := func() {
		if token := requester.RefreshToken(ctx); token != "" {
			requester.AuthToken = token
		}
	}

	// stream retries only the refusal of a session's first stream while its
	// credential generation is published (503); nothing ran then.
	stream := func(streamCtx context.Context, req helpers.TerminalStreamRequest) (helpers.TerminalStreamResult, error) {
		for attempt := 0; ; attempt++ {
			result, err := requester.StreamRecordedTerminal(streamCtx, req)
			if err != nil || result.StatusCode != http.StatusServiceUnavailable || attempt >= 10 {
				return result, err
			}
			select {
			case <-streamCtx.Done():
				return result, streamCtx.Err()
			case <-time.After(2 * time.Second):
			}
		}
	}

	t.Run("concurrent stream limit", func(t *testing.T) {
		refresh()
		release := make(chan struct{})
		var releaseOnce sync.Once
		releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
		// A failing assertion must not leave streams holding their leases.
		t.Cleanup(releaseAll)
		type held struct {
			result helpers.TerminalStreamResult
			err    error
		}
		results := make(chan held, maxStreams)
		for i := 0; i < maxStreams; i++ {
			ready := make(chan struct{})
			on := targets[i]
			go func() {
				streamCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
				defer cancel()
				result, err := stream(streamCtx, request(on, `echo held; read line; echo released`, func(output <-chan string, stdin io.Writer) error {
					var seen strings.Builder
					for !strings.Contains(seen.String(), "held") {
						chunk, ok := <-output
						if !ok {
							return fmt.Errorf("stream ended before it was held: %q", seen.String())
						}
						seen.WriteString(chunk)
					}
					close(ready)
					<-release
					if _, err := io.WriteString(stdin, "go\n"); err != nil {
						return err
					}
					for range output {
					}
					return nil
				}))
				results <- held{result, err}
			}()
			// One stream at a time: each must hold its slot before the next starts.
			select {
			case <-ready:
			case r := <-results:
				t.Fatalf("stream %d ended before it held its slot: err=%v status=%d body=%q", i+1, r.err, r.result.StatusCode, r.result.Body)
			case <-time.After(2 * time.Minute):
				t.Fatalf("stream %d never started", i+1)
			}
		}

		extraCtx, cancel := context.WithTimeout(ctx, time.Minute)
		defer cancel()
		extra, err := requester.StreamRecordedTerminal(extraCtx, request(targets[0], `echo over-limit`, nil))
		require.NoError(t, err)
		require.Equal(t, http.StatusTooManyRequests, extra.StatusCode, "stream %d exceeds the limit of %d: %s", maxStreams+1, maxStreams, extra.Body)
		require.Contains(t, extra.Body, "too many concurrent terminal recordings", "refused by the recording limiter, not a rate limit")
		require.NotContains(t, extra.Output, "over-limit")

		releaseAll()
		for i := 0; i < maxStreams; i++ {
			select {
			case r := <-results:
				require.NoError(t, r.err)
				require.Equal(t, http.StatusOK, r.result.StatusCode, r.result.Body)
				require.Contains(t, r.result.Output, "released")
				require.Equal(t, "completed", r.result.Status)
			case <-time.After(2 * time.Minute):
				t.Fatal("a held stream did not finish after release")
			}
		}
	})

	// keepOpen holds stdin open until the stream ends, like a user watching
	// output: an exec whose TTY input ends at once may end before it ran.
	keepOpen := func(output <-chan string, _ io.Writer) error {
		for range output {
		}
		return nil
	}
	// The recording counts framing. Every recorded write re-checks authority
	// with live API reads, so a recorded terminal moves a few hundred KiB per
	// minute in Kind: the volumes stay well below 2 MiB.
	output := func(n int64, marker string) string {
		return fmt.Sprintf(`echo start; head -c %d /dev/zero | tr '\0' a; echo; echo %s`, n, marker)
	}
	// The command ends only once the client saw its marker, so no buffered
	// output is lost when the process exits.
	untilMarker := func(marker string) func(<-chan string, io.Writer) error {
		return func(output <-chan string, stdin io.Writer) error {
			var seen strings.Builder
			for chunk := range output {
				seen.WriteString(chunk)
				if strings.Contains(seen.String(), marker) {
					_, err := io.WriteString(stdin, "done\n")
					for range output {
					}
					return err
				}
			}
			return fmt.Errorf("stream ended before %q", marker)
		}
	}

	t.Run("recording within the byte limit completes", func(t *testing.T) {
		refresh()
		streamCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		// Half the limit, at most 512 KiB (throughput, #1761).
		within := min(maxBytes/2, 512<<10)
		result, err := stream(streamCtx, request(targets[0], output(within, "within-limit")+"; read x", untilMarker("within-limit")))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, result.StatusCode, result.Body)
		require.Contains(t, result.Output, "within-limit")
		require.Equal(t, "completed", result.Status)
	})

	t.Run("recording over the byte limit stops the stream", func(t *testing.T) {
		if maxBytes > 2<<20 {
			t.Skipf("the default limit (uploadMaxBytes, %d bytes) is too large to fill through a recorded terminal here (#1761); the opt-in lanes cover the cut", maxBytes)
		}
		refresh()
		streamCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		started := time.Now()
		req := request(targets[1], output(maxBytes+64<<10, "over-limit")+"; sleep 600", keepOpen)
		req.CorrelationID = uuid.NewString()
		result, err := stream(streamCtx, req)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, result.StatusCode, result.Body)
		require.NotContains(t, result.Output, "over-limit", "no unrecorded output passes the limit")
		require.Less(t, int64(len(result.Output)), maxBytes, "delivered output stays within the recording limit")
		require.Equal(t, "incomplete", result.Status, "the evidence up to the limit is published as incomplete")
		// About 2 minutes at Kind throughput (#1761); without the cut the stream
		// runs into the client's 5-minute timeout (sleep 600).
		require.Less(t, time.Since(started), 270*time.Second, "the stream ends at the limit, not at the target's exit or session expiry")
		events, err := helpers.AuditEventsByCorrelation(ctx, req.CorrelationID)
		require.NoError(t, err)
		var reasons []any
		for _, event := range events {
			if event.Type == "debug_session.terminal_recording_finalized" {
				reasons = append(reasons, event.Details["abortReason"])
			}
		}
		require.Equal(t, []any{"recording_limit"}, reasons, "the limit is audited as the abort reason")
	})
}
