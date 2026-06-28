// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package jsonutil

import (
	"errors"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestRequireEmptyBody(t *testing.T) {
	tests := []struct {
		name    string
		body    string
		wantErr bool
	}{
		{name: "empty body"},
		{name: "whitespace only", body: " \n\r\t "},
		{name: "oversized whitespace only", body: strings.Repeat(" ", maxEmptyBodyWhitespaceBytes+1), wantErr: true},
		{name: "json object", body: "{}", wantErr: true},
		{name: "json array", body: "[]", wantErr: true},
		{name: "invalid payload", body: "not-json", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := RequireEmptyBody(strings.NewReader(tt.body))
			if tt.wantErr {
				require.Error(t, err)
				assert.True(t, errors.Is(err, ErrUnexpectedBody))
				return
			}
			require.NoError(t, err)
		})
	}
}

func TestRequireEmptyBodyNilReader(t *testing.T) {
	require.NoError(t, RequireEmptyBody(nil))
}
