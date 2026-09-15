// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

func TestCredentialURLPolicy(t *testing.T) {
	for _, raw := range []string{"https://issuer.example/token", "http://127.0.0.2/token", "http://[::1]/token", "http://issuer.example/token", "javascript:alert(1)"} {
		for _, allow := range []bool{false, true} {
			wantOK := strings.HasPrefix(raw, "https:") || (allow && strings.HasPrefix(raw, "http:"))
			for _, validate := range []func(string, bool) error{validateCredentialURLFor, validateBrowserURLFor} {
				if err := validate(raw, allow); (err == nil) != wantOK {
					t.Errorf("%s HTTP=%v: %v", raw, allow, err)
				}
			}
		}
	}
}

func TestHTTPSDiscoveryRejectsHTTPTokenAndDevice(t *testing.T) {
	for _, device := range []bool{false, true} {
		t.Run(fmt.Sprint(device), func(t *testing.T) {
			var issuer string
			srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]string{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": "http://127.0.0.1/token", "device_authorization_endpoint": "http://127.0.0.1/device", "jwks_uri": issuer + "/keys"})
			}))
			defer srv.Close()
			issuer = srv.URL
			cfg := OIDCConfig{Authority: issuer, ClientID: "client", InsecureSkipTLS: true}
			var err error
			if device {
				_, err = DeviceCodeLogin(context.Background(), cfg)
			} else {
				_, err = BuildOAuthConfig(context.Background(), cfg, "http://localhost/callback")
			}
			if err == nil || !strings.Contains(err.Error(), "endpoint") {
				t.Fatalf("downgrade accepted: %v", err)
			}
		})
	}
}

func TestOAuthGrantsDoNotReplayRedirects(t *testing.T) {
	for _, status := range []int{http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		for _, grant := range []string{"client-credentials", "code", "refresh", "device"} {
			t.Run(fmt.Sprintf("%d/%s", status, grant), func(t *testing.T) {
				leaks := 0
				sink := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { leaks++; w.WriteHeader(http.StatusBadRequest) }))
				defer sink.Close()
				var issuer string
				srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
					if strings.Contains(r.URL.Path, ".well-known") {
						_ = json.NewEncoder(w).Encode(map[string]string{"issuer": issuer, "authorization_endpoint": issuer + "/authorize", "token_endpoint": issuer + "/token", "jwks_uri": issuer + "/keys"})
						return
					}
					http.Redirect(w, r, sink.URL, status)
				}))
				defer srv.Close()
				issuer = srv.URL
				cfg := OIDCConfig{Authority: issuer, ClientID: "client", ClientSecret: "secret", InsecureSkipTLS: true}
				built, err := BuildOAuthConfig(context.Background(), cfg, "http://localhost/callback")
				if err != nil {
					t.Fatal(err)
				}
				ctx := oidc.ClientContext(context.Background(), built.Client)
				switch grant {
				case "client-credentials":
					_, err = ClientCredentialsLogin(ctx, cfg)
				case "code":
					_, err = built.OAuthConfig.Exchange(ctx, "secret-code")
				case "refresh":
					m := TokenManager{CachePath: filepath.Join(t.TempDir(), "tokens"), StorageMode: "file"}
					if err = m.SaveToken("test", StoredToken{AccessToken: "old", RefreshToken: "secret-refresh", Expiry: time.Now().Add(-time.Hour)}); err != nil {
						t.Fatal(err)
					}
					_, _, err = m.RefreshIfNeeded(ctx, "test", built.OAuthConfig)
				case "device":
					_, err = pollDeviceToken(ctx, built.Client, issuer+"/token", cfg, "secret-device")
				}
				if err == nil {
					t.Fatal("redirect unexpectedly succeeded")
				}
				if leaks != 0 {
					t.Fatalf("redirect destination received %d requests", leaks)
				}
			})
		}
	}
}

func TestRefreshUsesConfiguredTLSClient(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if err := r.ParseForm(); err != nil {
			t.Error(err)
		}
		if r.Form.Get("refresh_token") != "refresh" {
			t.Error("missing refresh token")
		}
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, `{"access_token":"fresh","token_type":"Bearer","expires_in":3600}`)
	}))
	defer srv.Close()
	m := TokenManager{CachePath: filepath.Join(t.TempDir(), "tokens"), StorageMode: "file"}
	if err := m.SaveToken("test", StoredToken{AccessToken: "old", RefreshToken: "refresh", Expiry: time.Now().Add(-time.Hour)}); err != nil {
		t.Fatal(err)
	}
	client := srv.Client()
	client.CheckRedirect = credentialRedirectPolicy
	got, changed, err := m.RefreshIfNeeded(oidc.ClientContext(context.Background(), client), "test", oauth2.Config{ClientID: "client", Endpoint: oauth2.Endpoint{TokenURL: srv.URL}})
	if err != nil || !changed || got.AccessToken != "fresh" {
		t.Fatalf("configured TLS refresh: %+v %v %v", got, changed, err)
	}
}

func TestDeviceTimingRejectsInvalidValuesBeforePolling(t *testing.T) {
	t.Setenv("BGCTL_NO_BROWSER", "true")
	for _, timing := range []struct{ interval, expires int }{{-1, 60}, {301, 60}, {math.MaxInt, 60}, {1, -1}, {1, 0}, {1, 86401}, {1, math.MaxInt}} {
		t.Run(fmt.Sprint(timing), func(t *testing.T) {
			var issuer string
			polls := 0
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/.well-known/openid-configuration":
					_ = json.NewEncoder(w).Encode(oidcDiscovery{TokenEndpoint: issuer + "/token", DeviceAuthorizationEndpoint: issuer + "/device"})
				case "/device":
					_ = json.NewEncoder(w).Encode(deviceCodeResponse{Interval: timing.interval, ExpiresIn: timing.expires})
				default:
					polls++
					fmt.Fprint(w, `{"access_token":"bad"}`)
				}
			}))
			defer srv.Close()
			issuer = srv.URL
			_, err := DeviceCodeLogin(context.Background(), OIDCConfig{Authority: issuer, ClientID: "client"})
			if err == nil || polls != 0 {
				t.Fatalf("invalid timing accepted: err=%v polls=%d", err, polls)
			}
		})
	}
}

func TestOAuthErrorControls(t *testing.T) {
	for _, got := range []string{sanitizeTerminalText("a\x1b\u009b\u009d\nb"), deviceTokenPayloadError(tokenResponse{Error: "bad\u009b", ErrorDesc: "bad\x1b"}).Error(), readOIDCErrorBody(strings.NewReader("bad\u009d"))} {
		if strings.ContainsAny(got, "\x1b\u009b\u009d") {
			t.Fatalf("unsafe error %q", got)
		}
	}
}
