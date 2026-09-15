// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

func TestRedactedHidesInlineSecrets(t *testing.T) {
	cfg := &Config{OIDCProviders: []OIDCProvider{{ClientSecret: "secret"}}, Contexts: []Context{{OIDC: &InlineOIDC{ClientSecret: "inline"}}}}
	got := cfg.Redacted()
	if got.OIDCProviders[0].ClientSecret != "REDACTED" || got.Contexts[0].OIDC.ClientSecret != "REDACTED" {
		t.Fatalf("secrets not redacted: %#v", got)
	}
	if cfg.OIDCProviders[0].ClientSecret != "secret" || cfg.Contexts[0].OIDC.ClientSecret != "inline" {
		t.Fatal("redaction mutated source config")
	}
}

func TestRedactionPreservesSecretReferencesAndEmptyValues(t *testing.T) {
	cfg := &Config{OIDCProviders: []OIDCProvider{{ClientSecretEnv: "SECRET"}, {ClientSecretFile: "secret-file"}, {}}, Contexts: []Context{{OIDC: &InlineOIDC{}}, {}}}
	got := cfg.Redacted()
	for _, p := range got.OIDCProviders {
		if p.ClientSecret != "" {
			t.Fatal("invented inline secret")
		}
	}
	if got.OIDCProviders[0].ClientSecretEnv != "SECRET" || got.OIDCProviders[1].ClientSecretFile != "secret-file" || got.Contexts[0].OIDC.ClientSecret != "" || got.Contexts[1].OIDC != nil {
		t.Fatal("references or absent config changed")
	}
}
