// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import "testing"

func TestBearerTokenRequiresExactlyOneBearerCredential(t *testing.T) {
	for name, header := range map[string]string{
		"empty":         "",
		"wrong scheme":  "Basic abc",
		"missing value": "Bearer",
		"extra value":   "Bearer one two",
	} {
		t.Run(name, func(t *testing.T) {
			if got := bearerToken(header); got != "" {
				t.Fatalf("bearerToken(%q) = %q, want empty", header, got)
			}
		})
	}
	if got := bearerToken("bearer token-value"); got != "token-value" {
		t.Fatalf("bearerToken() = %q, want token-value", got)
	}
}
