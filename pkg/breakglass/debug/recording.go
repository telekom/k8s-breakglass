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
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"sync"
	"time"

	"k8s.io/client-go/tools/remotecommand"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

const (
	defaultTerminalRecordingMaxBytes int64 = 512 << 20
	// TerminalRecordingFormatVersion is the framing written by the recorder:
	// version | direction | monotonic offset ns (8) | length (8) | prev SHA-256 | payload.
	// Version 1 (no offset) artifacts remain verifiable by the artifact backend.
	TerminalRecordingFormatVersion   = 2
	terminalRecordingFrameVersion    = byte(TerminalRecordingFormatVersion)
	terminalRecordingDirectionInput  = byte('i')
	terminalRecordingDirectionOutput = byte('o')
	terminalRecordingDirectionResize = byte('r')
	terminalRecordingFrameHeaderSize = 1 + 1 + 8 + 8 + sha256.Size
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
	// TerminalRecordingResize frames carry a JSON {"width":W,"height":H} payload.
	TerminalRecordingResize TerminalRecordingDirection = TerminalRecordingDirection(terminalRecordingDirectionResize)
)

// TerminalRecording is the finalized, framed terminal byte stream. The
// payload is intentionally opaque to status and audit code; callers should
// persist it only through an explicitly configured artifact store.
type TerminalRecording struct {
	// Bytes is empty for a segmented recorder: the bytes are already in the
	// artifact store (see NewSegmentedTerminalRecorder).
	Bytes  []byte
	SHA256 string
	Frames int64
	// Size is the total framed size, flushed or not.
	Size int64
}

// SegmentFlusher durably persists one non-empty, frame-aligned segment plus
// the chain head after it. data is only valid for the duration of the call.
type SegmentFlusher func(data []byte, chainHead [sha256.Size]byte) error

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
	started  time.Time

	// Opt-in incremental flush; flush == nil keeps the whole stream in memory.
	flush        SegmentFlusher
	segmentBytes int
	flushed      int64
	flushErr     error
	digest       hash.Hash
	result       *TerminalRecording
}

// NewSegmentedTerminalRecorder is NewTerminalRecorder with incremental flush:
// once segmentBytes of frames are buffered, the next Write first hands them to
// flush at a frame boundary and releases them, so memory is bounded by one
// segment plus one frame. A flush error fails that Write and every later one
// (and therefore the stream) closed: the frame that needed the flush is
// neither recorded nor delivered. Everything flushed before stays committed,
// and Finalize retries the buffered, already delivered tail once.
func NewSegmentedTerminalRecorder(maxBytes, segmentBytes int64, flush SegmentFlusher) *TerminalRecorder {
	r := NewTerminalRecorder(maxBytes)
	if flush != nil && segmentBytes > 0 {
		r.flush, r.segmentBytes, r.digest = flush, int(min(segmentBytes, math.MaxInt32)), sha256.New()
	}
	return r
}

func (r *TerminalRecorder) size() int64 { return r.flushed + int64(r.bytes.Len()) }

// flushLocked hands the buffered frames to the flusher and releases them.
// After a failure only the final flush tries again; the first error stays.
func (r *TerminalRecorder) flushLocked(final bool) error {
	if r.flushErr != nil && !final {
		return r.flushErr
	}
	if r.bytes.Len() == 0 {
		return r.flushErr
	}
	if err := r.flush(r.bytes.Bytes(), r.previous); err != nil {
		if r.flushErr == nil {
			r.flushErr = fmt.Errorf("flush terminal recording segment: %w", err)
		}
		return r.flushErr
	}
	r.flushed += int64(r.bytes.Len())
	r.bytes.Reset()
	return r.flushErr
}

// FlushError reports the first failed incremental flush, if any.
func (r *TerminalRecorder) FlushError() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.flushErr
}

// NewTerminalRecorder creates a bounded recorder. A zero limit uses the
// 512 MiB default; negative limits are rejected by Write.
func NewTerminalRecorder(maxBytes int64) *TerminalRecorder {
	if maxBytes == 0 {
		maxBytes = defaultTerminalRecordingMaxBytes
	}
	return &TerminalRecorder{maxBytes: maxBytes, started: time.Now()}
}

// Write records one complete terminal frame. The frame includes the previous
// frame hash, sequence-independent direction and payload length, then payload;
// the SHA-256 chain is computed over the serialized frame.
func (r *TerminalRecorder) Write(direction TerminalRecordingDirection, payload []byte) error {
	if direction != TerminalRecordingInput && direction != TerminalRecordingOutput && direction != TerminalRecordingResize {
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
	if r.flush != nil && r.bytes.Len() >= r.segmentBytes {
		if err := r.flushLocked(false); err != nil {
			return err
		}
	}
	if r.flushErr != nil {
		return r.flushErr
	}
	frameSize, err := terminalRecordingFrameSize(len(payload))
	if err != nil {
		return err
	}
	if frameSize > math.MaxInt-r.bytes.Len() || r.size() > r.maxBytes-int64(frameSize) {
		return errTerminalRecordingLimit
	}
	frame := make([]byte, frameSize)
	frame[0] = terminalRecordingFrameVersion
	frame[1] = byte(direction)
	// time.Since uses the monotonic clock, so offsets never go backwards.
	binary.BigEndian.PutUint64(frame[2:10], uint64(time.Since(r.started)))
	binary.BigEndian.PutUint64(frame[10:18], uint64(len(payload)))
	copy(frame[18:18+sha256.Size], r.previous[:])
	copy(frame[terminalRecordingFrameHeaderSize:], payload)
	if _, err := r.bytes.Write(frame); err != nil {
		return fmt.Errorf("append terminal recording frame: %w", err)
	}
	r.previous = sha256.Sum256(frame)
	r.frames++
	if r.flush != nil {
		_, _ = r.digest.Write(frame)
	}
	return nil
}

// terminalRecordingFrameSize validates native allocation arithmetic before addition.
func terminalRecordingFrameSize(payloadLength int) (int, error) {
	if payloadLength < 0 || payloadLength > math.MaxInt-terminalRecordingFrameHeaderSize {
		return 0, errTerminalRecordingLimit
	}
	return terminalRecordingFrameHeaderSize + payloadLength, nil
}

// Finalize closes the recorder and returns an immutable copy of the framed
// bytes plus its final digest. Finalization is idempotent for the same result.
func (r *TerminalRecorder) Finalize() (TerminalRecording, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.result != nil {
		return *r.result, r.flushErr
	}
	if !r.closed {
		// An empty successful terminal still has a valid framed evidence object;
		// artifact stores intentionally reject zero-byte objects.
		if r.size() == 0 {
			if r.maxBytes < terminalRecordingFrameHeaderSize {
				return TerminalRecording{}, errTerminalRecordingLimit
			}
			frame := make([]byte, terminalRecordingFrameHeaderSize)
			frame[0], frame[1] = terminalRecordingFrameVersion, terminalRecordingDirectionOutput
			binary.BigEndian.PutUint64(frame[2:10], uint64(time.Since(r.started)))
			_, _ = r.bytes.Write(frame)
			r.frames = 1
			if r.flush != nil {
				_, _ = r.digest.Write(frame)
				r.previous = sha256.Sum256(frame)
			}
		}
		r.closed = true
	}
	if r.flush != nil {
		// Final commit of the tail; retried once after an earlier failure.
		_ = r.flushLocked(true)
		sum := r.digest.Sum(nil)
		r.result = &TerminalRecording{SHA256: hex.EncodeToString(sum), Frames: r.frames, Size: r.flushed}
		return *r.result, r.flushErr
	}
	payload := append([]byte(nil), r.bytes.Bytes()...)
	digest := sha256.Sum256(payload)
	return TerminalRecording{Bytes: payload, SHA256: hex.EncodeToString(digest[:]), Frames: r.frames, Size: int64(len(payload))}, nil
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
	return StreamTerminalWithResize(ctx, executor, stdin, stdout, stderr, nil, recorder)
}

// StreamTerminalWithResize is StreamTerminal with a client terminal size
// queue. Every size delivered to the target is recorded as a resize frame.
func StreamTerminalWithResize(
	ctx context.Context,
	executor remotecommand.Executor,
	stdin io.Reader,
	stdout, stderr io.Writer,
	sizes remotecommand.TerminalSizeQueue,
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
	streamCtx, cancel := context.WithCancelCause(ctx)
	defer cancel(nil)
	var sizeQueue remotecommand.TerminalSizeQueue
	if sizes != nil {
		sizeQueue = recordedSizeQueue{sizes: sizes, recorder: recorder, fail: cancel}
	}
	streamErr := executor.StreamWithContext(streamCtx, remotecommand.StreamOptions{
		Stdin:             &recordingReader{reader: stdin, recorder: recorder, direction: TerminalRecordingInput, fail: cancel},
		Stdout:            io.MultiWriter(&recordingWriter{writer: stdout, recorder: recorder, direction: TerminalRecordingOutput, fail: cancel}),
		Stderr:            io.MultiWriter(&recordingWriter{writer: stderr, recorder: recorder, direction: TerminalRecordingOutput, fail: cancel}),
		Tty:               true,
		TerminalSizeQueue: sizeQueue,
	})
	if cause := context.Cause(streamCtx); cause != nil && ctx.Err() == nil && (streamErr == nil || errors.Is(streamErr, context.Canceled)) {
		// The executor returns cleanly or with ctx.Err() after our own
		// cancellation; report why the stream was stopped.
		streamErr = cause
	}
	result, finalizeErr := recorder.Finalize()
	if streamErr != nil {
		return result, fmt.Errorf("stream terminal session: %w", streamErr)
	}
	if finalizeErr != nil {
		return result, fmt.Errorf("finalize terminal recording: %w", finalizeErr)
	}
	return result, nil
}

// recordingReader and recordingWriter end the whole stream (fail) when bytes
// cannot be recorded, delivered or admitted (a failed transport authority
// check): the executor only logs a copy error and discards the rest of the
// output, so without it the target would keep running with dropped output and
// a clean exit would publish the recording as complete (#1760).
type recordingReader struct {
	reader    io.Reader
	recorder  *TerminalRecorder
	direction TerminalRecordingDirection
	fail      func(error)
}

func (r *recordingReader) Read(payload []byte) (int, error) {
	n, err := r.reader.Read(payload)
	if err != nil && !errors.Is(err, io.EOF) {
		// Input that was read but not admitted is neither recorded nor forwarded.
		err = fmt.Errorf("read terminal input: %w", err)
		r.fail(err)
		return 0, err
	}
	if n > 0 {
		if recordErr := r.recorder.Write(r.direction, payload[:n]); recordErr != nil {
			recordErr = fmt.Errorf("record terminal input: %w", recordErr)
			r.fail(recordErr)
			return 0, recordErr
		}
	}
	return n, err
}

type recordingWriter struct {
	writer    io.Writer
	recorder  *TerminalRecorder
	direction TerminalRecordingDirection
	fail      func(error)
}

func (w *recordingWriter) Write(payload []byte) (int, error) {
	if err := w.recorder.Write(w.direction, payload); err != nil {
		err = fmt.Errorf("record terminal output: %w", err)
		w.fail(err)
		return 0, err
	}
	n, err := w.writer.Write(payload)
	if err != nil {
		err = fmt.Errorf("deliver terminal output: %w", err)
		w.fail(err)
	}
	return n, err
}

type recordedSizeQueue struct {
	sizes    remotecommand.TerminalSizeQueue
	recorder *TerminalRecorder
	// fail stops the stream when a size cannot be recorded.
	fail func(error)
}

// Next records the size before it is applied, so the recording never shows
// output rendered at a size it does not contain. A size that cannot be
// recorded (byte limit) ends resizing and the whole stream: the target must
// not keep running with unrecorded state, and the evidence is incomplete.
func (q recordedSizeQueue) Next() *remotecommand.TerminalSize {
	size := q.sizes.Next()
	if size == nil {
		return nil
	}
	payload, err := json.Marshal(struct {
		Width  uint16 `json:"width"`
		Height uint16 `json:"height"`
	}{size.Width, size.Height})
	if err == nil {
		err = q.recorder.Write(TerminalRecordingResize, payload)
	}
	if err != nil {
		q.fail(fmt.Errorf("record terminal resize: %w", err))
		return nil
	}
	return size
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
