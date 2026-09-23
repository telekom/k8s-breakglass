// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package backend

import (
	"bytes"
	"context"
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
