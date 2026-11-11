// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cmd

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/creack/pty"
	"github.com/stretchr/testify/require"
	"golang.org/x/term"
)

type panicWriter struct{}

func (panicWriter) Write([]byte) (int, error) { panic("stdout failed") }

// outputWriter closes received on the first output bytes bgctl writes, which
// proves the client has the response and is streaming.
type outputWriter struct {
	once     sync.Once
	received chan struct{}
}

func (w *outputWriter) Write(p []byte) (int, error) {
	w.once.Do(func() { close(w.received) })
	return len(p), nil
}

// TestDebugTerminalRestoresTTY runs the raw-mode path on a real pseudo-terminal
// and asserts the original termios is restored after SIGTERM and after a panic.
func TestDebugTerminalRestoresTTY(t *testing.T) {
	for _, tc := range []struct {
		name      string
		interrupt bool
		noHeaders bool
		panics    bool
	}{
		// Needs the client to end its request body on cancel: the transport
		// waits for its body writer before Do returns.
		{name: "SIGTERM before response", interrupt: true, noHeaders: true},
		// Covered by the deferred restore alone: canceling the context aborts
		// the response body read.
		{name: "SIGTERM while streaming output", interrupt: true},
		{name: "panic", panics: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ptmx, tty, err := pty.Open()
			if err != nil {
				t.Skipf("no pseudo-terminal available: %v", err)
			}
			require.NoError(t, pty.Setsize(tty, &pty.Winsize{Rows: 24, Cols: 80}))
			// Like os.Stdin: a blocking, non-pollable file, so the client's
			// read deadline cannot interrupt a pending read.
			fd, err := syscall.Dup(int(tty.Fd()))
			require.NoError(t, err)
			stdin := os.NewFile(uintptr(fd), "stdin")
			t.Cleanup(func() {
				// Closing the master ends the client's still pending stdin read
				// (with EOF or EIO) so its goroutine does not outlive the test.
				_ = ptmx.Close()
				_ = stdin.Close()
				_ = tty.Close()
			})
			before, err := term.GetState(fd)
			require.NoError(t, err)

			// The first resize frame is sent after raw mode is enabled. Output
			// waits for release so the panic case cannot restore the terminal
			// before raw mode is asserted.
			streaming, release, wrote := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var releaseOnce sync.Once
			unblock := func() { releaseOnce.Do(func() { close(release) }) }
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = http.NewResponseController(w).EnableFullDuplex()
				var header [5]byte
				_, _ = io.ReadFull(r.Body, header[:])
				close(streaming)
				<-release
				if !tc.noHeaders {
					_, _ = w.Write([]byte("$ "))
					w.(http.Flusher).Flush()
				}
				close(wrote)
				_, _ = io.Copy(io.Discard, r.Body) // until the client ends the stream
			}))
			// On failure, unblock the handler and drop the connection so
			// server.Close cannot hang.
			defer server.Close()
			defer server.CloseClientConnections()
			defer unblock()

			output := &outputWriter{received: make(chan struct{})}
			var stdout io.Writer = output
			if tc.panics {
				stdout = panicWriter{}
			}
			root := NewRootCommand(Config{ConfigPath: writeTestConfigForDebug(t, server.URL), OutputWriter: stdout})
			root.SetIn(stdin)
			root.SetErr(io.Discard)
			root.SetArgs([]string{"--server", server.URL, "--token", "t", "debug", "terminal", "s1", "--pod", "ns/pod"})
			done := make(chan any, 1)
			go func() {
				defer func() { done <- recover() }()
				_ = root.Execute()
			}()
			receive(t, streaming, "the stream to start")
			raw, err := term.GetState(fd)
			require.NoError(t, err)
			require.NotEqual(t, before, raw, "raw mode must be active while streaming")
			unblock()
			receive(t, wrote, "the server to write output")
			if tc.interrupt {
				if !tc.noHeaders {
					receive(t, output.received, "bgctl to print the response output")
				}
				require.NoError(t, syscall.Kill(syscall.Getpid(), syscall.SIGTERM))
				require.Nil(t, receive(t, done, "bgctl to exit after SIGTERM"))
			} else {
				require.Equal(t, "stdout failed", receive(t, done, "bgctl to panic"))
			}
			after, err := term.GetState(fd)
			require.NoError(t, err)
			require.Equal(t, before, after, "termios must be restored")
		})
	}
}

// receive fails the test instead of hanging until the go test timeout when a
// regression leaves the command blocked.
func receive[T any](t *testing.T, ch <-chan T, what string) T {
	t.Helper()
	select {
	case v := <-ch:
		return v
	case <-time.After(10 * time.Second):
		t.Fatalf("timed out waiting for %s", what)
		panic("unreachable")
	}
}
