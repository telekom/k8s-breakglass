// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package recording

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"github.com/telekom/k8s-breakglass/pkg/breakglass/debug"
)

func recorded(t *testing.T) []byte {
	t.Helper()
	recorder := debug.NewTerminalRecorder(0)
	require.NoError(t, recorder.Write(debug.TerminalRecordingResize, []byte(`{"width":120,"height":40}`)))
	require.NoError(t, recorder.Write(debug.TerminalRecordingOutput, []byte("$ ")))
	time.Sleep(20 * time.Millisecond)
	require.NoError(t, recorder.Write(debug.TerminalRecordingInput, []byte("ls\r")))
	require.NoError(t, recorder.Write(debug.TerminalRecordingOutput, []byte("file\r\n")))
	out, err := recorder.Finalize()
	require.NoError(t, err)
	return out.Bytes
}

func TestParseVerifiesServerRecording(t *testing.T) {
	data := recorded(t)
	rec, err := Parse(bytes.NewReader(data))
	require.NoError(t, err)
	sum := sha256.Sum256(data)
	require.Equal(t, hex.EncodeToString(sum[:]), rec.SHA256)
	require.EqualValues(t, len(data), rec.Bytes)
	require.Len(t, rec.Frames, 4)
	require.Equal(t, []byte{Resize, Output, Input, Output}, []byte{rec.Frames[0].Direction, rec.Frames[1].Direction, rec.Frames[2].Direction, rec.Frames[3].Direction})
	require.GreaterOrEqual(t, rec.Frames[2].Offset-rec.Frames[1].Offset, 20*time.Millisecond, "timing is preserved")
}

func TestParseRejectsTampering(t *testing.T) {
	data := recorded(t)
	for name, mutate := range map[string]func([]byte) []byte{
		"payload byte":  func(b []byte) []byte { b[50] ^= 1; return b },
		"truncated":     func(b []byte) []byte { return b[:len(b)-3] },
		"bad direction": func(b []byte) []byte { b[1] = 'x'; return b },
		"time reversed": func(b []byte) []byte {
			// Frame 2 starts after frame 1 (50-byte header + 25-byte payload).
			binary.BigEndian.PutUint64(b[50+25+2:], 0)
			binary.BigEndian.PutUint64(b[2:], uint64(time.Hour))
			return b
		},
		"empty": func([]byte) []byte { return nil },
	} {
		t.Run(name, func(t *testing.T) {
			_, err := Parse(bytes.NewReader(mutate(append([]byte(nil), data...))))
			require.Error(t, err)
		})
	}
}

func TestLastFrameTamperingChangesDigest(t *testing.T) {
	data := recorded(t)
	original, err := Parse(bytes.NewReader(data))
	require.NoError(t, err)
	data[len(data)-1] ^= 1
	tampered, err := Parse(bytes.NewReader(data))
	require.NoError(t, err, "the chain cannot cover the last frame; the published digest does")
	require.NotEqual(t, original.SHA256, tampered.SHA256)
}

func TestParseVersionOne(t *testing.T) {
	var buf bytes.Buffer
	var previous [32]byte
	for _, frame := range []struct {
		dir     byte
		payload string
	}{{Output, "hello"}, {Input, "x"}} {
		header := make([]byte, 42)
		header[0], header[1] = 1, frame.dir
		binary.BigEndian.PutUint64(header[2:10], uint64(len(frame.payload)))
		copy(header[10:], previous[:])
		full := append(header, frame.payload...)
		previous = sha256.Sum256(full)
		buf.Write(full)
	}
	rec, err := Parse(&buf)
	require.NoError(t, err)
	require.Len(t, rec.Frames, 2)
	require.Equal(t, "hello", string(rec.Frames[0].Payload))
	require.Zero(t, rec.Frames[1].Offset)
}

func TestWriteAsciicast(t *testing.T) {
	rec, err := Parse(bytes.NewReader(recorded(t)))
	require.NoError(t, err)
	var out bytes.Buffer
	require.NoError(t, rec.WriteAsciicast(&out, AsciicastOptions{}))
	scanner := bufio.NewScanner(strings.NewReader(out.String()))
	require.True(t, scanner.Scan())
	var header map[string]any
	require.NoError(t, json.Unmarshal(scanner.Bytes(), &header))
	require.EqualValues(t, 2, header["version"])
	require.EqualValues(t, 120, header["width"])
	var events [][]any
	for scanner.Scan() {
		var event []any
		require.NoError(t, json.Unmarshal(scanner.Bytes(), &event))
		events = append(events, event)
	}
	require.Equal(t, []any{"r", "120x40"}, events[0][1:])
	require.Equal(t, "o", events[1][1])
	require.Equal(t, "file\r\n", events[2][2], "input is excluded by default")
	require.GreaterOrEqual(t, events[2][0].(float64), 0.02)

	out.Reset()
	require.NoError(t, rec.WriteAsciicast(&out, AsciicastOptions{IncludeInput: true}))
	require.Contains(t, out.String(), `"i","ls\r"`)
}
