// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"math"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestRecordingFrameLengthBounds(t *testing.T) {
	for _, length := range []uint64{0, 1, math.MaxInt64, math.MaxInt64 + 1, math.MaxUint64} {
		header := make([]byte, 42)
		header[0], header[1] = 1, 'o'
		binary.BigEndian.PutUint64(header[2:10], length)
		frames, err := validateRecordingFrames(context.Background(), bytes.NewReader(header), 42)
		if length == 0 {
			require.NoError(t, err)
			require.EqualValues(t, 1, frames)
		} else {
			require.Error(t, err)
			require.Zero(t, frames)
		}
	}
	header := make([]byte, 42)
	header[0], header[1] = 1, 'o'
	_, err := validateRecordingFrames(context.Background(), bytes.NewReader(header), 41)
	require.Error(t, err)
}

func v2Frames(offsets []uint64, directions string) []byte {
	var out bytes.Buffer
	var previous [32]byte
	for i, offset := range offsets {
		frame := make([]byte, 50, 51)
		frame[0], frame[1] = 2, directions[i]
		binary.BigEndian.PutUint64(frame[2:10], offset)
		binary.BigEndian.PutUint64(frame[10:18], 1)
		copy(frame[18:], previous[:])
		frame = append(frame, 'x')
		previous = sha256.Sum256(frame)
		out.Write(frame)
	}
	return out.Bytes()
}

func TestRecordingFramesVersionTwo(t *testing.T) {
	valid := v2Frames([]uint64{0, 5, 5, 9}, "rioo")
	frames, err := validateRecordingFrames(context.Background(), bytes.NewReader(valid), int64(len(valid)))
	require.NoError(t, err)
	require.EqualValues(t, 4, frames)

	reversed := v2Frames([]uint64{5, 4}, "oo")
	_, err = validateRecordingFrames(context.Background(), bytes.NewReader(reversed), int64(len(reversed)))
	require.ErrorContains(t, err, "not monotonic")

	unknown := v2Frames([]uint64{0}, "x")
	_, err = validateRecordingFrames(context.Background(), bytes.NewReader(unknown), int64(len(unknown)))
	require.Error(t, err)

	mixed := append(v2Frames([]uint64{0}, "o"), make([]byte, 42)...)
	mixed[50] = 1
	_, err = validateRecordingFrames(context.Background(), bytes.NewReader(mixed), int64(len(mixed)))
	require.Error(t, err, "versions cannot be mixed within one artifact")
}
