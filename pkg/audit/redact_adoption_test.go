// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestLibraryRedactURLCompatibility(t *testing.T) {
	for _, test := range []struct{ raw, expected string }{
		{"https://example.com/events?", "https://example.com/events"},
		{"/events?token=secret#fragment", "/events"},
		{"https://example.com/events#%73ecret", "https://example.com/events"},
		{"://invalid", "<invalid-url>"},
		{"opaque:secret", "<invalid-url>"},
	} {
		t.Run(test.raw, func(t *testing.T) {
			require.Equal(t, test.expected, redactURL(test.raw))
		})
	}
}
