// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package naming

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPlatformNamingGolden(t *testing.T) {
	for _, test := range []struct {
		name, input, subdomain, label string
	}{
		{"email", "First.Last+Ops@EXAMPLE.COM", "first.last-ops-example.com", "first.last-ops-example.com"},
		{"group", "OIDC:Platform_ADMIN", "oidc-platform-admin", "oidc-platform-admin"},
		{"cluster", "EU-West_1.Prod", "eu-west-1.prod", "eu-west-1.prod"},
		{"separators", "..A--__..B---..", "a-.b", "a-.b"},
		{"unicode", "日本語.Équipe", "quipe", "quipe"},
		{"empty", "", "x", "x"},
		{"all invalid", "💡@_---...", "x", "x"},
		{"label truncation", strings.Repeat("a", 62) + ".suffix", strings.Repeat("a", 62) + ".suffix", strings.Repeat("a", 62)},
		{"subdomain truncation", strings.Repeat("a", 252) + "-suffix", strings.Repeat("a", 252), strings.Repeat("a", 63)},
	} {
		t.Run(test.name, func(t *testing.T) {
			require.Equal(t, test.subdomain, ToRFC1123Subdomain(test.input))
			require.Equal(t, test.label, ToRFC1123Label(test.input))
		})
	}
}
