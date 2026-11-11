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

	// A valid, correctly chained v1 frame after a v2 frame: only the version
	// switch makes this artifact invalid.
	first := v2Frames([]uint64{0}, "o")
	previous := sha256.Sum256(first)
	v1 := make([]byte, 42, 43)
	v1[0], v1[1] = 1, 'o'
	binary.BigEndian.PutUint64(v1[2:10], 1)
	copy(v1[10:], previous[:])
	v1 = append(v1, 'x')
	mixed := append(append([]byte(nil), first...), v1...)
	_, err = validateRecordingFrames(context.Background(), bytes.NewReader(mixed), int64(len(mixed)))
	require.ErrorContains(t, err, "invalid terminal recording frame", "versions cannot be mixed within one artifact")
	v1Only := append([]byte(nil), v1...)
	copy(v1Only[10:42], make([]byte, 32))
	frames, err = validateRecordingFrames(context.Background(), bytes.NewReader(v1Only), int64(len(v1Only)))
	require.NoError(t, err, "the same v1 frame alone is valid")
	require.EqualValues(t, 1, frames)
}
