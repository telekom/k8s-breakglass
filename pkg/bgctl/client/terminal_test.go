// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package client

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestTerminalFramesInputAndResizeAndReadsTrailers(t *testing.T) {
	var gotResize, gotInput string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, http.MethodPost, r.Method)
		require.Equal(t, "/api/debugSessions/s1/terminal", r.URL.Path)
		require.Equal(t, []string{"sh", "-c", "x"}, r.URL.Query()["command"])
		require.Equal(t, "target", r.URL.Query().Get("podNamespace"))
		require.Equal(t, terminalProtocolFramed, r.Header.Get(terminalProtocolHeader))
		require.Equal(t, "Bearer tok", r.Header.Get("Authorization"))
		require.NoError(t, http.NewResponseController(w).EnableFullDuplex())
		w.Header().Set("Trailer", "X-Breakglass-Recording-ID, X-Breakglass-Recording-SHA256, X-Breakglass-Recording-Status")
		_, _ = w.Write([]byte("prompt"))
		w.(http.Flusher).Flush()
		for {
			var header [5]byte
			if _, err := io.ReadFull(r.Body, header[:]); err != nil {
				break
			}
			payload := make([]byte, binary.BigEndian.Uint32(header[1:]))
			_, err := io.ReadFull(r.Body, payload)
			require.NoError(t, err)
			if header[0] == terminalFrameResize {
				gotResize = string(payload)
			} else {
				gotInput += string(payload)
			}
		}
		_, _ = w.Write([]byte(gotInput))
		w.Header().Set("X-Breakglass-Recording-ID", "rec-1")
		w.Header().Set("X-Breakglass-Recording-SHA256", "abc")
		w.Header().Set("X-Breakglass-Recording-Status", "completed")
	}))
	defer server.Close()
	c, err := New(WithServer(server.URL), WithToken("tok"))
	require.NoError(t, err)
	resize := make(chan TerminalSize, 1)
	resize <- TerminalSize{Width: 90, Height: 20}
	var out bytes.Buffer
	result, err := c.Terminal(context.Background(), TerminalRequest{
		Session: "s1", PodNamespace: "target", PodName: "pod", Command: []string{"sh", "-c", "x"},
		Stdin: strings.NewReader("hello"), Stdout: &out, Resize: resize,
	})
	require.NoError(t, err)
	require.Equal(t, TerminalResult{RecordingID: "rec-1", SHA256: "abc", Status: "completed"}, result)
	require.Equal(t, "prompthello", out.String())
	require.JSONEq(t, `{"width":90,"height":20}`, gotResize)
}

func TestTerminalReportsHTTPErrors(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
		_, _ = w.Write([]byte(`{"error":"terminal recording transport is not configured"}`))
	}))
	defer server.Close()
	c, err := New(WithServer(server.URL))
	require.NoError(t, err)
	_, err = c.Terminal(context.Background(), TerminalRequest{Session: "s1", PodNamespace: "n", PodName: "p", Command: []string{"sh"}})
	var httpErr *HTTPError
	require.True(t, errors.As(err, &httpErr))
	require.Equal(t, http.StatusServiceUnavailable, httpErr.StatusCode)
	require.Contains(t, httpErr.Message, "transport is not configured")
}

func TestWriteTerminalFrameSplitsLargeInput(t *testing.T) {
	var buf bytes.Buffer
	require.NoError(t, writeTerminalFrame(&buf, terminalFrameStdin, make([]byte, maxTerminalInputFrame+3)))
	require.Equal(t, 2*5+maxTerminalInputFrame+3, buf.Len())
	require.EqualValues(t, maxTerminalInputFrame, binary.BigEndian.Uint32(buf.Bytes()[1:5]))
}

func TestRecordingsListAndDownload(t *testing.T) {
	big := bytes.Repeat([]byte("x"), maxResponseBody+10)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		require.Equal(t, "hub", r.URL.Query().Get("namespace"))
		switch r.URL.Path {
		case "/api/debugSessions/s1/terminal":
			_, _ = w.Write([]byte(`[{"artifactID":"rec-1","state":"Available","sha256":"abc","recording":{"formatVersion":2,"complete":true,"podName":"pod"}}]`))
		case "/api/debugSessions/s1/terminal/rec-1":
			w.Header().Set("X-Breakglass-Recording-SHA256", "abc")
			_, _ = w.Write(big)
		case "/api/debugSessions/s1/terminal/denied":
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer server.Close()
	c, err := New(WithServer(server.URL))
	require.NoError(t, err)
	list, err := c.DebugSessions().Recordings(context.Background(), "s1", "hub")
	require.NoError(t, err)
	require.Len(t, list, 1)
	require.True(t, list[0].Recording.Complete)
	var out bytes.Buffer
	digest, err := c.DebugSessions().DownloadRecording(context.Background(), "s1", "hub", "rec-1", &out, int64(len(big)))
	require.NoError(t, err)
	require.Equal(t, "abc", digest)
	require.Equal(t, len(big), out.Len(), "downloads are not capped like JSON responses")
	_, err = c.DebugSessions().DownloadRecording(context.Background(), "s1", "hub", "rec-1", io.Discard, int64(len(big))-1)
	require.ErrorContains(t, err, "exceeds", "downloads are capped at the caller's limit")
	_, err = c.DebugSessions().DownloadRecording(context.Background(), "s1", "hub", "denied", io.Discard, 1<<20)
	var httpErr *HTTPError
	require.True(t, errors.As(err, &httpErr))
	require.Equal(t, http.StatusForbidden, httpErr.StatusCode)
}
