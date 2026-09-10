// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"sync"

	"k8s.io/client-go/tools/remotecommand"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

const (
	defaultTerminalRecordingMaxBytes int64 = 512 << 20
	terminalRecordingFrameVersion          = byte(1)
	terminalRecordingDirectionInput        = byte('i')
	terminalRecordingDirectionOutput       = byte('o')
	terminalRecordingFrameHeaderSize       = 1 + 1 + 8 + sha256.Size
)

var (
	errTerminalRecordingClosed = errors.New("terminal recording is finalized")
	errTerminalRecordingLimit  = errors.New("terminal recording exceeds its byte limit")
)

// TerminalRecordingDirection identifies the endpoint that produced a frame.
// Input and output are kept separate so replay consumers cannot confuse
// terminal keystrokes with bytes emitted by the target process.
type TerminalRecordingDirection byte

const (
	TerminalRecordingInput  TerminalRecordingDirection = TerminalRecordingDirection(terminalRecordingDirectionInput)
	TerminalRecordingOutput TerminalRecordingDirection = TerminalRecordingDirection(terminalRecordingDirectionOutput)
)

// TerminalRecording is the finalized, framed terminal byte stream. The
// payload is intentionally opaque to status and audit code; callers should
// persist it only through an explicitly configured artifact store.
type TerminalRecording struct {
	Bytes  []byte
	SHA256 string
	Frames int64
}

// TerminalRecorder frames and hash-chains terminal bytes while enforcing a
// hard byte limit. It is safe for stdout and stderr writers to use
// concurrently while a remotecommand executor is streaming.
type TerminalRecorder struct {
	mu       sync.Mutex
	maxBytes int64
	bytes    bytes.Buffer
	previous [sha256.Size]byte
	closed   bool
	frames   int64
}

// NewTerminalRecorder creates a bounded recorder. A zero limit uses the
// 512 MiB default; negative limits are rejected by Write.
func NewTerminalRecorder(maxBytes int64) *TerminalRecorder {
	if maxBytes == 0 {
		maxBytes = defaultTerminalRecordingMaxBytes
	}
	return &TerminalRecorder{maxBytes: maxBytes}
}

// Write records one complete terminal frame. The frame includes the previous
// frame hash, sequence-independent direction and payload length, then payload;
// the SHA-256 chain is computed over the serialized frame.
func (r *TerminalRecorder) Write(direction TerminalRecordingDirection, payload []byte) error {
	if direction != TerminalRecordingInput && direction != TerminalRecordingOutput {
		return fmt.Errorf("invalid terminal recording direction %q", direction)
	}
	if len(payload) == 0 {
		return nil
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.closed {
		return errTerminalRecordingClosed
	}
	if r.maxBytes < 0 {
		return errTerminalRecordingLimit
	}
	frameSize := int64(terminalRecordingFrameHeaderSize) + int64(len(payload))
	if int64(r.bytes.Len()) > r.maxBytes-frameSize {
		return errTerminalRecordingLimit
	}
	frame := make([]byte, terminalRecordingFrameHeaderSize+len(payload))
	frame[0] = terminalRecordingFrameVersion
	frame[1] = byte(direction)
	binary.BigEndian.PutUint64(frame[2:10], uint64(len(payload)))
	copy(frame[10:10+sha256.Size], r.previous[:])
	copy(frame[terminalRecordingFrameHeaderSize:], payload)
	if _, err := r.bytes.Write(frame); err != nil {
		return fmt.Errorf("append terminal recording frame: %w", err)
	}
	r.previous = sha256.Sum256(frame)
	r.frames++
	return nil
}

// Finalize closes the recorder and returns an immutable copy of the framed
// bytes plus its final digest. Finalization is idempotent for the same result.
func (r *TerminalRecorder) Finalize() (TerminalRecording, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if !r.closed {
		// An empty successful terminal still has a valid framed evidence object;
		// artifact stores intentionally reject zero-byte objects.
		if r.bytes.Len() == 0 {
			if r.maxBytes < terminalRecordingFrameHeaderSize {
				return TerminalRecording{}, errTerminalRecordingLimit
			}
			frame := make([]byte, terminalRecordingFrameHeaderSize)
			frame[0], frame[1] = terminalRecordingFrameVersion, terminalRecordingDirectionOutput
			_, _ = r.bytes.Write(frame)
			r.frames = 1
		}
		r.closed = true
	}
	payload := append([]byte(nil), r.bytes.Bytes()...)
	digest := sha256.Sum256(payload)
	return TerminalRecording{Bytes: payload, SHA256: hex.EncodeToString(digest[:]), Frames: r.frames}, nil
}

// StreamTerminal executes a controller-owned Kubernetes exec/attach stream
// while recording the actual bytes crossing both directions. The caller owns
// durable publication of the finalized recording and must fail closed if that
// publication fails.
func StreamTerminal(
	ctx context.Context,
	executor remotecommand.Executor,
	stdin io.Reader,
	stdout, stderr io.Writer,
	recorder *TerminalRecorder,
) (TerminalRecording, error) {
	if executor == nil || recorder == nil {
		return TerminalRecording{}, errors.New("terminal stream requires an executor and recorder")
	}
	if stdin == nil {
		stdin = httpNoBodyReader{}
	}
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}
	streamErr := executor.StreamWithContext(ctx, remotecommand.StreamOptions{
		Stdin:  &recordingReader{reader: stdin, recorder: recorder, direction: TerminalRecordingInput},
		Stdout: io.MultiWriter(&recordingWriter{writer: stdout, recorder: recorder, direction: TerminalRecordingOutput}),
		Stderr: io.MultiWriter(&recordingWriter{writer: stderr, recorder: recorder, direction: TerminalRecordingOutput}),
		Tty:    true,
	})
	result, finalizeErr := recorder.Finalize()
	if streamErr != nil {
		return result, fmt.Errorf("stream terminal session: %w", streamErr)
	}
	if finalizeErr != nil {
		return result, fmt.Errorf("finalize terminal recording: %w", finalizeErr)
	}
	return result, nil
}

type recordingReader struct {
	reader    io.Reader
	recorder  *TerminalRecorder
	direction TerminalRecordingDirection
}

func (r *recordingReader) Read(payload []byte) (int, error) {
	n, err := r.reader.Read(payload)
	if n > 0 {
		if recordErr := r.recorder.Write(r.direction, payload[:n]); recordErr != nil {
			return 0, fmt.Errorf("record terminal input: %w", recordErr)
		}
	}
	return n, err
}

type recordingWriter struct {
	writer    io.Writer
	recorder  *TerminalRecorder
	direction TerminalRecordingDirection
}

func (w *recordingWriter) Write(payload []byte) (int, error) {
	if err := w.recorder.Write(w.direction, payload); err != nil {
		return 0, fmt.Errorf("record terminal output: %w", err)
	}
	return w.writer.Write(payload)
}

type httpNoBodyReader struct{}

func (httpNoBodyReader) Read([]byte) (int, error) { return 0, io.EOF }

// rejectUnsupportedTerminalRecording rejects recording requests until the
// terminal-byte transport is configured.
func rejectUnsupportedTerminalRecording(template *breakglassv1alpha1.DebugSessionTemplate) error {
	if template != nil && template.Spec.Audit != nil && template.Spec.Audit.EnableTerminalRecording {
		return fmt.Errorf("terminal recording requested by spec.audit.enableTerminalRecording is unavailable: terminal-byte transport is not configured")
	}
	return nil
}

func (c *DebugSessionController) ensureTerminalRecordingConfigured(template *breakglassv1alpha1.DebugSessionTemplate) error {
	if template == nil || template.Spec.Audit == nil || !template.Spec.Audit.EnableTerminalRecording {
		return nil
	}
	if !c.terminalRecordingConfigured() {
		return rejectUnsupportedTerminalRecording(template)
	}
	return nil
}
