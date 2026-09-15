// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package cmd

import (
	"context"
	"crypto/sha256"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/telekom/k8s-breakglass/pkg/bgctl/auth"
	"github.com/telekom/k8s-breakglass/pkg/bgctl/config"
)

func TestTokenIdentityIsolationAndLegacyReauthentication(t *testing.T) {
	original := config.Context{Server: "https://api", OIDCProvider: "provider"}
	resolved := config.ResolvedOIDC{Authority: "https://issuer", ClientID: "client"}
	rt := runtimeState{}
	base := rt.resolveTokenKey(&original, &resolved)
	for _, mutate := range []func(*config.Context, *config.ResolvedOIDC, *runtimeState){
		func(c *config.Context, r *config.ResolvedOIDC, rt *runtimeState) { c.Server += "2" },
		func(c *config.Context, r *config.ResolvedOIDC, rt *runtimeState) { r.Authority += "2" },
		func(c *config.Context, r *config.ResolvedOIDC, rt *runtimeState) { r.ClientID += "2" },
		func(c *config.Context, r *config.ResolvedOIDC, rt *runtimeState) { r.CAFile = "ca" },
		func(c *config.Context, r *config.ResolvedOIDC, rt *runtimeState) { r.InsecureSkipTLS = true },
		func(c *config.Context, r *config.ResolvedOIDC, rt *runtimeState) { c.CAFile = "ca" },
		func(c *config.Context, r *config.ResolvedOIDC, rt *runtimeState) { c.InsecureSkipTLSVerify = true },
		func(c *config.Context, r *config.ResolvedOIDC, rt *runtimeState) {
			rt.serverOverride = "https://override"
		},
	} {
		c, r, state := original, resolved, rt
		mutate(&c, &r, &state)
		if got := state.resolveTokenKey(&c, &r); got == base {
			t.Fatal("different identity reused token key")
		}
	}
	manager := auth.TokenManager{CachePath: filepath.Join(t.TempDir(), "tokens"), StorageMode: "file"}
	if err := manager.SaveToken(resolveProviderKey(&original, &resolved), auth.StoredToken{AccessToken: "legacy"}); err != nil {
		t.Fatal(err)
	}
	if _, found, err := manager.GetToken(base); err != nil || found {
		t.Fatalf("legacy token reused: %v %v", found, err)
	}
	if err := manager.SaveToken(base, auth.StoredToken{AccessToken: "new"}); err != nil {
		t.Fatal(err)
	}
	if err := manager.DeleteToken(base); err != nil {
		t.Fatal(err)
	}
	if _, found, err := manager.GetToken(base); err != nil || found {
		t.Fatalf("logout retained scoped token: %v %v", found, err)
	}
}

func TestChecksumResponseBoundary(t *testing.T) {
	path := filepath.Join(t.TempDir(), "archive")
	if err := os.WriteFile(path, []byte("archive"), 0600); err != nil {
		t.Fatal(err)
	}
	sum := fmt.Sprintf("%x", sha256.Sum256([]byte("archive")))
	for _, size := range []int{maxChecksumBodyBytes, maxChecksumBodyBytes + 1} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, sum+strings.Repeat(" ", size-len(sum))) }))
			defer srv.Close()
			err := verifyChecksum(context.Background(), []githubAsset{{Name: "archive.sha256", URL: srv.URL}}, "archive", path)
			if (err == nil) != (size == maxChecksumBodyBytes) {
				t.Fatalf("size=%d err=%v", size, err)
			}
		})
	}
	if got := readUpdateErrorBody(strings.NewReader("bad\x1b\u009b\u009d")); strings.ContainsAny(got, "\x1b\u009b\u009d") {
		t.Fatalf("unsafe update error: %q", got)
	}
}
