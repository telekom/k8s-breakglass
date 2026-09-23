// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNewReadControllerRequiresLiveBindingResolver(t *testing.T) {
	if controller, err := NewReadController(nil, nil); err == nil || controller != nil {
		t.Fatal("nil service accepted")
	}
}

type revokingReader struct{ revoke func() }

func (reader revokingReader) Read(buffer []byte) (int, error) {
	n := copy(buffer, "secret")
	reader.revoke()
	return n, nil
}
func TestRequestReaderDiscardsBytesAfterParticipantRemoval(t *testing.T) {
	allowed := true
	reader := &requestAuthorizedReader{reader: revokingReader{revoke: func() { allowed = false }}, authorize: func() error {
		if !allowed {
			return errors.New("participant removed")
		}
		return nil
	}}
	buffer := bytes.Repeat([]byte{1}, 6)
	n, err := reader.Read(buffer)
	require.Error(t, err)
	require.Zero(t, n)
	require.Equal(t, make([]byte, 6), buffer)
}
