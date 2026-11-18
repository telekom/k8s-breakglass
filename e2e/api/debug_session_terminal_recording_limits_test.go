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
	"testing"
	"time"

	"github.com/stretchr/testify/require"

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

	s := helpers.SetupTest(t, helpers.WithLongTimeout())
	ctx := s.Ctx
	ensureAuditPipeline(t, ctx, s)
	requesterUser := helpers.TestUsers.SecurityRequester
	requester := s.TC.ClientForUser(requesterUser)
	session, pod := recordedSession(t, ctx, s, requester, requesterUser.Groups, s.Cluster)
	request := func(command string, interact func(<-chan string, io.Writer) error) helpers.TerminalStreamRequest {
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

	t.Run("concurrent stream limit", func(t *testing.T) {
		refresh()
		release := make(chan struct{})
		type held struct {
			result helpers.TerminalStreamResult
			err    error
		}
		results := make(chan held, maxStreams)
		for i := 0; i < maxStreams; i++ {
			ready := make(chan struct{})
			go func() {
				streamCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
				defer cancel()
				result, err := requester.StreamRecordedTerminal(streamCtx, request(`echo held; read line; echo released`, func(output <-chan string, stdin io.Writer) error {
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
		extra, err := requester.StreamRecordedTerminal(extraCtx, request(`echo over-limit`, nil))
		require.NoError(t, err)
		require.Equal(t, http.StatusTooManyRequests, extra.StatusCode, "stream %d exceeds the limit of %d: %s", maxStreams+1, maxStreams, extra.Body)
		require.NotContains(t, extra.Output, "over-limit")

		close(release)
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

	// The recording counts framing; half the limit fits, the limit plus one
	// segment does not.
	output := func(n int64, marker string) string {
		return fmt.Sprintf(`head -c %d /dev/zero | tr '\0' a; echo; echo %s`, n, marker)
	}

	t.Run("recording within the byte limit completes", func(t *testing.T) {
		refresh()
		streamCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		result, err := requester.StreamRecordedTerminal(streamCtx, request(output(maxBytes/2, "within-limit"), nil))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, result.StatusCode, result.Body)
		require.Contains(t, result.Output, "within-limit")
		require.Equal(t, "completed", result.Status)
	})

	t.Run("recording over the byte limit stops the stream", func(t *testing.T) {
		refresh()
		streamCtx, cancel := context.WithTimeout(ctx, 5*time.Minute)
		defer cancel()
		started := time.Now()
		result, err := requester.StreamRecordedTerminal(streamCtx, request(output(maxBytes+64<<10, "over-limit")+"; sleep 600", nil))
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, result.StatusCode, result.Body)
		require.NotContains(t, result.Output, "over-limit", "no unrecorded output passes the limit")
		require.Less(t, int64(len(result.Output)), maxBytes, "delivered output stays within the recording limit")
		require.Equal(t, "incomplete", result.Status, "the evidence up to the limit is published as incomplete")
		require.Less(t, time.Since(started), 3*time.Minute, "the stream ends at the limit, not at the target's exit or session expiry")
	})
}
