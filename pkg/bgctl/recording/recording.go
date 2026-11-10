// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

// Package recording decodes, verifies and exports DebugSession terminal
// recordings (terminal-recording.v1 artifacts, framing versions 1 and 2).
package recording

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"
)

// Frame directions.
const (
	Input  byte = 'i'
	Output byte = 'o'
	Resize byte = 'r'
)

// MaxFramePayload bounds a single decoded frame to keep a hostile artifact
// from forcing a large allocation.
const MaxFramePayload = 64 << 20

// Frame is one verified recording frame.
type Frame struct {
	Version   byte
	Direction byte
	// Offset is the monotonic time since the stream started; zero for version 1.
	Offset  time.Duration
	Payload []byte
}

// Size is a terminal size carried by a resize frame.
type Size struct {
	Width  uint16 `json:"width"`
	Height uint16 `json:"height"`
}

// Recording is a fully verified recording.
type Recording struct {
	Frames []Frame
	// SHA256 is the digest of the complete artifact.
	SHA256 string
	Bytes  int64
}

// Parse reads and verifies a recording: frame versions are consistent,
// directions are known, every frame carries the SHA-256 of its predecessor,
// and version 2 time offsets never go backwards.
func Parse(r io.Reader) (*Recording, error) {
	digest := sha256.New()
	counted := &countingReader{r: io.TeeReader(r, digest)}
	reader := bufio.NewReader(counted)
	var previous [sha256.Size]byte
	var frames []Frame
	var version byte
	var last time.Duration
	for {
		first, err := reader.ReadByte()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, err
		}
		if len(frames) == 0 {
			version = first
		}
		if first != version || (version != 1 && version != 2) {
			return nil, fmt.Errorf("frame %d: unsupported or mixed version %d", len(frames), first)
		}
		headerSize := 1 + 1 + 8 + sha256.Size
		if version == 2 {
			headerSize += 8
		}
		header := make([]byte, headerSize)
		header[0] = first
		if _, err := io.ReadFull(reader, header[1:]); err != nil {
			return nil, fmt.Errorf("frame %d: truncated header: %w", len(frames), err)
		}
		frame := Frame{Version: version, Direction: header[1]}
		lengthAt := 2
		if version == 2 {
			offset := binary.BigEndian.Uint64(header[2:10])
			if offset > uint64(1<<63-1) || time.Duration(offset) < last {
				return nil, fmt.Errorf("frame %d: time offset is not monotonic", len(frames))
			}
			frame.Offset, last = time.Duration(offset), time.Duration(offset)
			lengthAt = 10
		}
		switch {
		case frame.Direction == Input || frame.Direction == Output:
		case frame.Direction == Resize && version == 2:
		default:
			return nil, fmt.Errorf("frame %d: invalid direction %q", len(frames), frame.Direction)
		}
		length := binary.BigEndian.Uint64(header[lengthAt : lengthAt+8])
		if length > MaxFramePayload {
			return nil, fmt.Errorf("frame %d: payload of %d bytes exceeds limit", len(frames), length)
		}
		if !bytes.Equal(header[lengthAt+8:], previous[:]) {
			return nil, fmt.Errorf("frame %d: hash chain broken", len(frames))
		}
		frame.Payload = make([]byte, length)
		if _, err := io.ReadFull(reader, frame.Payload); err != nil {
			return nil, fmt.Errorf("frame %d: truncated payload: %w", len(frames), err)
		}
		chain := sha256.New()
		chain.Write(header)
		chain.Write(frame.Payload)
		copy(previous[:], chain.Sum(nil))
		frames = append(frames, frame)
	}
	if len(frames) == 0 {
		return nil, errors.New("recording is empty")
	}
	return &Recording{Frames: frames, SHA256: hex.EncodeToString(digest.Sum(nil)), Bytes: counted.n}, nil
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// AsciicastOptions configures WriteAsciicast.
type AsciicastOptions struct {
	// IncludeInput also exports typed input as "i" events.
	IncludeInput bool
	// Width and Height are used until the first resize frame (default 80x24).
	Width, Height uint16
	Timestamp     time.Time
}

// WriteAsciicast exports the recording as asciicast v2 (asciinema). Resize
// frames become "r" events. Version 1 recordings have no timing; all events
// are placed at time zero.
func (rec *Recording) WriteAsciicast(w io.Writer, opts AsciicastOptions) error {
	width, height := opts.Width, opts.Height
	if width == 0 || height == 0 {
		width, height = 80, 24
	}
	for _, frame := range rec.Frames {
		if frame.Direction == Resize {
			var size Size
			if json.Unmarshal(frame.Payload, &size) == nil && size.Width > 0 && size.Height > 0 {
				width, height = size.Width, size.Height
			}
			break
		}
	}
	header := map[string]any{"version": 2, "width": width, "height": height}
	if !opts.Timestamp.IsZero() {
		header["timestamp"] = opts.Timestamp.Unix()
	}
	encoder := json.NewEncoder(w)
	if err := encoder.Encode(header); err != nil {
		return fmt.Errorf("write asciicast header: %w", err)
	}
	for _, frame := range rec.Frames {
		code, data := string(frame.Direction), string(frame.Payload)
		switch frame.Direction {
		case Input:
			if !opts.IncludeInput {
				continue
			}
		case Resize:
			var size Size
			if err := json.Unmarshal(frame.Payload, &size); err != nil {
				return fmt.Errorf("decode resize frame: %w", err)
			}
			data = fmt.Sprintf("%dx%d", size.Width, size.Height)
		}
		if len(frame.Payload) == 0 && frame.Direction != Resize {
			continue
		}
		if err := encoder.Encode([]any{frame.Offset.Seconds(), code, data}); err != nil {
			return fmt.Errorf("write asciicast event: %w", err)
		}
	}
	return nil
}
