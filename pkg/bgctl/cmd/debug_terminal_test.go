// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/pkg/breakglass/debug"
)

func runDebug(t *testing.T, serverURL string, stdin io.Reader, args ...string) (string, string, error) {
	t.Helper()
	out, errOut := &bytes.Buffer{}, &bytes.Buffer{}
	root := NewRootCommand(Config{ConfigPath: writeTestConfigForDebug(t, serverURL), OutputWriter: out})
	root.SetErr(errOut)
	if stdin != nil {
		root.SetIn(stdin)
	}
	root.SetArgs(append([]string{"--server", serverURL, "--token", "test-token"}, args...))
	err := root.Execute()
	return out.String(), errOut.String(), err
}

func TestDebugTerminalCommand(t *testing.T) {
	var gotInput string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "/api/debugSessions/s1/terminal", r.URL.Path)
		require.Equal(t, "ns", r.URL.Query().Get("podNamespace"))
		require.Equal(t, "pod", r.URL.Query().Get("podName"))
		require.Equal(t, "c1", r.URL.Query().Get("container"))
		require.Equal(t, []string{"bash", "-l"}, r.URL.Query()["command"])
		require.Equal(t, debug.TerminalProtocolFramed, r.Header.Get(debug.TerminalProtocolHeader))
		require.NoError(t, http.NewResponseController(w).EnableFullDuplex())
		w.Header().Set("Trailer", "X-Breakglass-Recording-ID, X-Breakglass-Recording-SHA256, X-Breakglass-Recording-Status")
		for {
			var header [5]byte
			if _, err := io.ReadFull(r.Body, header[:]); err != nil {
				break
			}
			payload := make([]byte, binary.BigEndian.Uint32(header[1:]))
			_, _ = io.ReadFull(r.Body, payload)
			gotInput += string(payload)
		}
		_, _ = w.Write([]byte("out:" + gotInput))
		w.Header().Set("X-Breakglass-Recording-ID", "rec-1")
		w.Header().Set("X-Breakglass-Recording-SHA256", "abc")
		w.Header().Set("X-Breakglass-Recording-Status", r.URL.Query().Get("container")+"-completed")
	}))
	defer server.Close()
	out, errOut, err := runDebug(t, server.URL, strings.NewReader("whoami\n"), "debug", "terminal", "s1", "--pod", "ns/pod", "--container", "c1", "--", "bash", "-l")
	require.Error(t, err, "a non-completed recording status is reported as failure")
	require.Equal(t, "out:whoami\n", out)
	require.Contains(t, errOut, "recording rec-1: c1-completed")

	_, _, err = runDebug(t, server.URL, nil, "debug", "terminal", "s1", "--pod", "pod-without-namespace")
	require.ErrorContains(t, err, "NAMESPACE/NAME")
	_, _, err = runDebug(t, server.URL, nil, "debug", "terminal", "s1", "extra", "--pod", "ns/pod")
	require.ErrorContains(t, err, "after --")
}

func serverRecording(t *testing.T) []byte {
	t.Helper()
	recorder := debug.NewTerminalRecorder(0)
	require.NoError(t, recorder.Write(debug.TerminalRecordingResize, []byte(`{"width":100,"height":30}`)))
	require.NoError(t, recorder.Write(debug.TerminalRecordingOutput, []byte("$ ")))
	require.NoError(t, recorder.Write(debug.TerminalRecordingInput, []byte("id\r")))
	require.NoError(t, recorder.Write(debug.TerminalRecordingOutput, []byte("uid=0\r\n")))
	rec, err := recorder.Finalize()
	require.NoError(t, err)
	return rec.Bytes
}

func TestDebugRecordingsCommands(t *testing.T) {
	data := serverRecording(t)
	sum := sha256.Sum256(data)
	digest := hex.EncodeToString(sum[:])
	published := digest
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/debugSessions/s1/terminal":
			_, _ = w.Write([]byte(`[{"artifactID":"rec-1","state":"Available","size":10,"sha256":"` + digest + `","recording":{"complete":true,"frames":4,"podNamespace":"ns","podName":"pod"}}]`))
		case "/api/debugSessions/s1/terminal/rec-1":
			w.Header().Set("X-Breakglass-Recording-SHA256", published)
			_, _ = w.Write(data)
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	out, _, err := runDebug(t, server.URL, nil, "debug", "recordings", "list", "s1")
	require.NoError(t, err)
	require.Contains(t, out, "rec-1\tAvailable\tns/pod\ttrue\t4")

	out, _, err = runDebug(t, server.URL, nil, "debug", "recordings", "verify", "s1", "rec-1")
	require.NoError(t, err)
	require.Contains(t, out, "verified: 4 frames")
	require.Contains(t, out, "format v2")

	out, _, err = runDebug(t, server.URL, nil, "debug", "recordings", "export", "s1", "rec-1")
	require.NoError(t, err)
	scanner := bufio.NewScanner(strings.NewReader(out))
	require.True(t, scanner.Scan())
	var header map[string]any
	require.NoError(t, json.Unmarshal(scanner.Bytes(), &header))
	require.EqualValues(t, 100, header["width"])
	require.NotContains(t, out, `"i"`)

	file := filepath.Join(t.TempDir(), "rec.raw")
	_, _, err = runDebug(t, server.URL, nil, "debug", "recordings", "get", "s1", "rec-1", "-f", file)
	require.NoError(t, err)
	written, err := os.ReadFile(file)
	require.NoError(t, err)
	require.Equal(t, data, written)
	info, err := os.Stat(file)
	require.NoError(t, err)
	require.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	_, _, err = runDebug(t, server.URL, nil, "debug", "recordings", "get", "s1", "rec-1", "-f", file)
	require.Error(t, err, "existing files are never overwritten")

	out, _, err = runDebug(t, server.URL, nil, "debug", "recordings", "verify", "s1", "rec-1", "--expect-sha256", "sha256:"+digest)
	require.NoError(t, err, "a matching independent digest verifies")
	require.Contains(t, out, "verified")
	_, _, err = runDebug(t, server.URL, nil, "debug", "recordings", "export", "s1", "rec-1", "--expect-sha256", strings.Repeat("1", 64))
	require.ErrorContains(t, err, "does not match expected", "the server's own header is not trusted alone")

	published = strings.Repeat("0", 64)
	_, _, err = runDebug(t, server.URL, nil, "debug", "recordings", "verify", "s1", "rec-1")
	require.ErrorContains(t, err, "does not match published")
	published = digest
	data[len(data)-60] ^= 1
	_, _, err = runDebug(t, server.URL, nil, "debug", "recordings", "export", "s1", "rec-1", "--format", "raw")
	require.ErrorContains(t, err, "failed verification")
	_, _, err = runDebug(t, server.URL, nil, "debug", "recordings", "export", "s1", "rec-1", "--format", "html")
	require.ErrorContains(t, err, "unsupported format")
}
