// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"k8s.io/client-go/tools/remotecommand"
)

const (
	// TerminalProtocolHeader opts a terminal request into a framed request body.
	// Without it the body is raw stdin and no resize is possible.
	TerminalProtocolHeader = "X-Breakglass-Terminal-Protocol"
	// TerminalProtocolFramed frames the request body as
	// type (1 byte) | length (4 bytes, big endian) | payload. Type 0 carries
	// stdin bytes, type 1 a JSON {"width":W,"height":H} terminal size.
	TerminalProtocolFramed = "framed.v1"

	TerminalFrameStdin  byte = 0
	TerminalFrameResize byte = 1

	// MaxTerminalInputFrame bounds one client frame.
	MaxTerminalInputFrame = 64 << 10
)

var errTerminalInputFrame = errors.New("invalid terminal input frame")

// terminalSizeQueue delivers decoded client sizes to the executor.
type terminalSizeQueue struct {
	ctx   context.Context
	sizes chan remotecommand.TerminalSize
}

func (q *terminalSizeQueue) Next() *remotecommand.TerminalSize {
	select {
	case size, ok := <-q.sizes:
		if !ok {
			return nil
		}
		return &size
	case <-q.ctx.Done():
		return nil
	}
}

// decodeFramedTerminalInput splits a framed request body into stdin and a
// size queue. The returned reader ends with the body. A malformed or
// oversized frame ends stdin with an error and calls abort, because an
// executor may not surface a stdin error: the stream must stop and its
// evidence must not be classified as complete.
func decodeFramedTerminalInput(ctx context.Context, body io.Reader, abort func(error)) (io.ReadCloser, *terminalSizeQueue) {
	stdin, stdinWriter := io.Pipe()
	queue := &terminalSizeQueue{ctx: ctx, sizes: make(chan remotecommand.TerminalSize, 4)}
	go func() {
		defer close(queue.sizes)
		err := decodeTerminalFrames(ctx, body, stdinWriter, queue.sizes)
		stdinWriter.CloseWithError(err)
		if err != nil && ctx.Err() == nil && abort != nil {
			abort(err)
		}
	}()
	return stdin, queue
}

func decodeTerminalFrames(ctx context.Context, body io.Reader, stdin io.Writer, sizes chan<- remotecommand.TerminalSize) error {
	var header [5]byte
	payload := make([]byte, MaxTerminalInputFrame)
	for {
		if _, err := io.ReadFull(body, header[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("read terminal input frame: %w", err)
		}
		length := binary.BigEndian.Uint32(header[1:])
		if length > MaxTerminalInputFrame {
			return errTerminalInputFrame
		}
		if _, err := io.ReadFull(body, payload[:length]); err != nil {
			return fmt.Errorf("read terminal input frame: %w", err)
		}
		switch header[0] {
		case TerminalFrameStdin:
			if _, err := stdin.Write(payload[:length]); err != nil {
				if errors.Is(err, io.ErrClosedPipe) {
					// The executor finished and its stdin was closed: input that
					// was never consumed is not a protocol error.
					return nil
				}
				return err
			}
		case TerminalFrameResize:
			var size remotecommand.TerminalSize
			if err := json.Unmarshal(payload[:length], &size); err != nil || size.Width == 0 || size.Height == 0 {
				return errTerminalInputFrame
			}
			select {
			case sizes <- size:
			case <-ctx.Done():
				return ctx.Err()
			}
		default:
			return errTerminalInputFrame
		}
	}
}

// EncodeTerminalFrame writes one framed.v1 client frame.
func EncodeTerminalFrame(w io.Writer, frameType byte, payload []byte) error {
	if len(payload) > MaxTerminalInputFrame {
		return errTerminalInputFrame
	}
	frame := make([]byte, 5+len(payload))
	frame[0] = frameType
	binary.BigEndian.PutUint32(frame[1:5], uint32(len(payload))) // #nosec G115 -- bounded above
	copy(frame[5:], payload)
	_, err := w.Write(frame)
	return err
}
