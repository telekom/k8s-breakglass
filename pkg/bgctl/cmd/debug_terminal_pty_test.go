// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cmd

import (
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"syscall"
	"testing"

	"github.com/creack/pty"
	"github.com/stretchr/testify/require"
	"golang.org/x/term"
)

type panicWriter struct{}

func (panicWriter) Write([]byte) (int, error) { panic("stdout failed") }

// TestDebugTerminalRestoresTTY runs the raw-mode path on a real pseudo-terminal
// and asserts the original termios is restored after SIGTERM and after a panic.
func TestDebugTerminalRestoresTTY(t *testing.T) {
	for _, tc := range []struct {
		name      string
		interrupt bool
		noHeaders bool
		stdout    io.Writer
	}{
		{name: "SIGTERM", interrupt: true, stdout: io.Discard},
		// The transport waits for its request body writer before Do returns.
		{name: "SIGTERM before response", interrupt: true, noHeaders: true, stdout: io.Discard},
		{name: "panic", stdout: panicWriter{}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ptmx, tty, err := pty.Open()
			require.NoError(t, err)
			require.NoError(t, pty.Setsize(tty, &pty.Winsize{Rows: 24, Cols: 80}))
			// Like os.Stdin: a blocking, non-pollable file, so the client's
			// read deadline cannot interrupt a pending read.
			fd, err := syscall.Dup(int(tty.Fd()))
			require.NoError(t, err)
			stdin := os.NewFile(uintptr(fd), "stdin")
			t.Cleanup(func() {
				_, _ = ptmx.Write([]byte("x")) // release the pending stdin read
				_ = stdin.Close()
				_ = tty.Close()
				_ = ptmx.Close()
			})
			before, err := term.GetState(fd)
			require.NoError(t, err)

			// The first resize frame is sent after raw mode is enabled. Output
			// waits for release so the panic case cannot restore the terminal
			// before raw mode is asserted.
			streaming, release, wrote := make(chan struct{}), make(chan struct{}), make(chan struct{})
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
			defer server.Close()

			root := NewRootCommand(Config{ConfigPath: writeTestConfigForDebug(t, server.URL), OutputWriter: tc.stdout})
			root.SetIn(stdin)
			root.SetErr(io.Discard)
			root.SetArgs([]string{"--server", server.URL, "--token", "t", "debug", "terminal", "s1", "--pod", "ns/pod"})
			done := make(chan any, 1)
			go func() {
				defer func() { done <- recover() }()
				_ = root.Execute()
			}()
			<-streaming
			raw, err := term.GetState(fd)
			require.NoError(t, err)
			require.NotEqual(t, before, raw, "raw mode must be active while streaming")
			close(release)
			<-wrote
			if tc.interrupt {
				require.NoError(t, syscall.Kill(syscall.Getpid(), syscall.SIGTERM))
				require.Nil(t, <-done)
			} else {
				require.Equal(t, "stdout failed", <-done)
			}
			after, err := term.GetState(fd)
			require.NoError(t, err)
			require.Equal(t, before, after, "termios must be restored")
		})
	}
}
