// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/go-jose/go-jose/v4"
	"github.com/golang-jwt/jwt/v5"
	"k8s.io/apiserver/pkg/apis/apiserver"
)

func TestCacheKeyIncludesPolicyAndJWKS(t *testing.T) {
	policy := apiserver.JWTAuthenticator{Issuer: apiserver.Issuer{URL: "https://issuer.example"}}
	first, err := cacheKey(policy, Options{JWKSURL: "https://issuer.example/keys"})
	if err != nil {
		t.Fatal(err)
	}
	second, err := cacheKey(policy, Options{JWKSURL: "https://other.example/keys"})
	if err != nil {
		t.Fatal(err)
	}
	if first == second {
		t.Fatal("different JWKS endpoints must not share an authenticator")
	}
}

func TestNewDefaults(t *testing.T) {
	engine := New(context.Background(), Options{Client: http.DefaultClient})
	defer engine.Close()
	if engine.options.MaxAuthenticators != 32 {
		t.Fatalf("MaxAuthenticators = %d, want 32", engine.options.MaxAuthenticators)
	}
}

func TestAuthenticateUsesKubernetesMappingsAndValidatesToken(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keySet := &coreosoidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&privateKey.PublicKey}}
	engine := New(context.Background(), Options{KeySet: keySet})
	defer engine.Close()
	policy := apiserver.JWTAuthenticator{
		Issuer: apiserver.Issuer{URL: "https://issuer.example", Audiences: []string{"breakglass"}},
		ClaimMappings: apiserver.ClaimMappings{
			Username: apiserver.PrefixedClaimOrExpression{Claim: "preferred_username", Prefix: stringPtr("tdi_security_oidc:")},
			Groups:   apiserver.PrefixedClaimOrExpression{Claim: "groups", Prefix: stringPtr("oidc:")},
			UID:      apiserver.ClaimOrExpression{Expression: "claims.sub"},
			Extra:    []apiserver.ExtraMapping{{Key: "example.com/role", ValueExpression: "claims.role"}},
		},
	}
	token := signToken(t, privateKey, map[string]any{
		"iss": "https://issuer.example", "aud": "breakglass", "sub": "subject-1",
		"preferred_username": "k834798", "groups": []string{"admins", "sre"}, "role": "operator",
		"exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix(),
	})
	response, err := engine.Authenticate(t.Context(), token, policy)
	if err != nil {
		t.Fatal(err)
	}
	if response.User.GetName() != "tdi_security_oidc:k834798" || response.User.GetUID() != "subject-1" {
		t.Fatalf("unexpected mapped identity: %#v", response.User)
	}
	if got := response.User.GetGroups(); len(got) != 2 || got[0] != "oidc:admins" || got[1] != "oidc:sre" {
		t.Fatalf("unexpected groups: %#v", got)
	}
	if got := response.User.GetExtra()["example.com/role"]; len(got) != 1 || got[0] != "operator" {
		t.Fatalf("unexpected extra: %#v", response.User.GetExtra())
	}

	badAudience := signToken(t, privateKey, map[string]any{"iss": "https://issuer.example", "aud": "other", "sub": "x", "preferred_username": "x", "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix()})
	if _, err := engine.Authenticate(t.Context(), badAudience, policy); err == nil {
		t.Fatal("expected audience validation failure")
	}
}

func TestAuthenticateRemoteDiscoveryAndJWKS(t *testing.T) {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	keyDocument, err := json.Marshal(map[string]any{"keys": []jose.JSONWebKey{{Key: &privateKey.PublicKey, KeyID: "test", Use: "sig", Algorithm: "RS256"}}})
	if err != nil {
		t.Fatal(err)
	}
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body := `{"issuer":"https://issuer.example","jwks_uri":"https://keys.example/jwks"}`
		if req.URL.String() == "https://keys.example/jwks" {
			body = string(keyDocument)
		}
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	engine := New(context.Background(), Options{Client: client})
	defer engine.Close()
	policy := apiserver.JWTAuthenticator{Issuer: apiserver.Issuer{URL: "https://issuer.example", DiscoveryURL: "https://discovery.example/.well-known", Audiences: []string{"breakglass"}}, ClaimMappings: apiserver.ClaimMappings{Username: apiserver.PrefixedClaimOrExpression{Claim: "sub", Prefix: stringPtr("oidc:")}}}
	token := signToken(t, privateKey, map[string]any{"iss": "https://issuer.example", "aud": "breakglass", "sub": "remote-user", "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix()})
	response, err := engine.Authenticate(t.Context(), token, policy)
	if err != nil {
		t.Fatal(err)
	}
	if response.User.GetName() != "oidc:remote-user" {
		t.Fatalf("unexpected remote identity %q", response.User.GetName())
	}
}

func TestEngineBoundsCacheAndRejectsAfterClose(t *testing.T) {
	engine := New(context.Background(), Options{KeySet: &coreosoidc.StaticKeySet{}, MaxAuthenticators: 1})
	policy := func(issuer string) apiserver.JWTAuthenticator {
		return apiserver.JWTAuthenticator{Issuer: apiserver.Issuer{URL: issuer, Audiences: []string{"breakglass"}}, ClaimMappings: apiserver.ClaimMappings{Username: apiserver.PrefixedClaimOrExpression{Claim: "sub", Prefix: stringPtr("")}}}
	}
	if _, err := engine.get(t.Context(), policy("https://one.example")); err != nil {
		t.Fatal(err)
	}
	if _, err := engine.get(t.Context(), policy("https://two.example")); err != nil {
		t.Fatal(err)
	}
	if len(engine.items) != 1 {
		t.Fatalf("cache size = %d, want 1", len(engine.items))
	}
	engine.Close()
	if _, err := engine.get(t.Context(), policy("https://three.example")); err == nil {
		t.Fatal("expected closed engine rejection")
	}
}

func TestSharedJWKSRefreshSurvivesAuthenticatorEviction(t *testing.T) {
	firstKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	secondKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	transport := &rotatingJWKS{keys: []jose.JSONWebKey{{Key: &firstKey.PublicKey, KeyID: "first", Use: "sig", Algorithm: "RS256"}}}
	client := &http.Client{Transport: transport}
	engine := New(context.Background(), Options{Client: client, JWKSURL: "https://keys.example/jwks", MaxAuthenticators: 1})
	defer engine.Close()
	policy := func(issuer string) apiserver.JWTAuthenticator {
		return apiserver.JWTAuthenticator{Issuer: apiserver.Issuer{URL: issuer, Audiences: []string{"breakglass"}}, ClaimMappings: apiserver.ClaimMappings{Username: apiserver.PrefixedClaimOrExpression{Claim: "sub", Prefix: stringPtr("")}}}
	}
	token1 := signTokenWithKID(t, firstKey, "first", map[string]any{"iss": "https://one.example", "aud": "breakglass", "sub": "one", "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix()})
	if _, err := engine.Authenticate(t.Context(), token1, policy("https://one.example")); err != nil {
		t.Fatal(err)
	}
	transport.keys = []jose.JSONWebKey{{Key: &secondKey.PublicKey, KeyID: "second", Use: "sig", Algorithm: "RS256"}}
	token2 := signTokenWithKID(t, secondKey, "second", map[string]any{"iss": "https://two.example", "aud": "breakglass", "sub": "two", "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix()})
	if _, err := engine.Authenticate(t.Context(), token2, policy("https://two.example")); err != nil {
		t.Fatalf("rotated key after authenticator eviction was not refreshed: %v", err)
	}
	if atomic.LoadInt32(&transport.requests) < 2 {
		t.Fatalf("JWKS was fetched %d times, want initial and rotation refresh", transport.requests)
	}
}

func TestInvalidDiscoveryURLDoesNotMakeOutboundRequest(t *testing.T) {
	transport := &rotatingJWKS{}
	engine := New(context.Background(), Options{Client: &http.Client{Transport: transport}})
	defer engine.Close()
	policy := apiserver.JWTAuthenticator{Issuer: apiserver.Issuer{URL: "https://issuer.example", DiscoveryURL: "https://issuer.example?unexpected=true", Audiences: []string{"breakglass"}}, ClaimMappings: apiserver.ClaimMappings{Username: apiserver.PrefixedClaimOrExpression{Claim: "sub", Prefix: stringPtr("")}}}
	if _, err := engine.Authenticate(t.Context(), "invalid-token", policy); err == nil {
		t.Fatal("expected invalid discovery URL error")
	}
	if atomic.LoadInt32(&transport.requests) != 0 {
		t.Fatal("invalid discovery URL caused an outbound request")
	}
}

func TestAuthenticateRejectsInvalidEngineInputs(t *testing.T) {
	var nilEngine *Engine
	if _, err := nilEngine.Authenticate(t.Context(), "token", apiserver.JWTAuthenticator{}); err == nil {
		t.Fatal("expected nil engine error")
	}
	engine := New(context.Background(), Options{KeySet: &coreosoidc.StaticKeySet{}})
	defer engine.Close()
	if _, err := engine.Authenticate(t.Context(), "token", apiserver.JWTAuthenticator{}); err == nil {
		t.Fatal("expected missing issuer error")
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

type rotatingJWKS struct {
	keys     []jose.JSONWebKey
	requests int32
}

func (r *rotatingJWKS) RoundTrip(req *http.Request) (*http.Response, error) {
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
	atomic.AddInt32(&r.requests, 1)
	body, err := json.Marshal(map[string]any{"keys": r.keys})
	if err != nil {
		return nil, err
	}
	return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(string(body))), Header: make(http.Header)}, nil
}

func stringPtr(value string) *string { return &value }

func signToken(t *testing.T, key *rsa.PrivateKey, claims map[string]any) string {
	return signTokenWithKID(t, key, "test", claims)
}

func signTokenWithKID(t *testing.T, key *rsa.PrivateKey, kid string, claims map[string]any) string {
	t.Helper()
	token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims(claims))
	token.Header["kid"] = kid
	signed, err := token.SignedString(key)
	if err != nil {
		t.Fatal(err)
	}
	return signed
}
