// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package terminal

import (
	"strings"
	"unicode"
)

// SafeText replaces terminal control characters while retaining printable Unicode.
func SafeText(value string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, value)
}
