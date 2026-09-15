// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package terminal

import (
	"testing"
	"unicode"
)

func TestSafeTextAllControls(t *testing.T) {
	for r := rune(0); r <= 0x9f; r++ {
		got := SafeText(string(r))
		if unicode.IsControl(r) && got != " " {
			t.Errorf("%U retained: %q", r, got)
		}
	}
	if got := SafeText("日本語 café"); got != "日本語 café" {
		t.Fatalf("printable Unicode changed: %q", got)
	}
}
