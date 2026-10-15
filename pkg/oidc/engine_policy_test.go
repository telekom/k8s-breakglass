// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"io"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"k8s.io/apiserver/pkg/apis/apiserver"
)

func TestInvalidPoliciesAreRejectedBeforeOIDCNetworkAccess(t *testing.T) {
	var requests int32
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		atomic.AddInt32(&requests, 1)
		return nil, io.ErrUnexpectedEOF
	})}
	base := apiserver.JWTAuthenticator{
		Issuer:        apiserver.Issuer{URL: "https://issuer.example", DiscoveryURL: "https://discovery.example/config", Audiences: []string{"breakglass"}},
		ClaimMappings: apiserver.ClaimMappings{Username: apiserver.PrefixedClaimOrExpression{Claim: "sub", Prefix: stringPtr("")}},
	}
	for _, tc := range []struct {
		name   string
		mutate func(*apiserver.JWTAuthenticator)
	}{
		{name: "invalid claim expression", mutate: func(policy *apiserver.JWTAuthenticator) {
			policy.ClaimValidationRules = []apiserver.ClaimValidationRule{{Expression: "claims."}}
		}},
		{name: "invalid user expression", mutate: func(policy *apiserver.JWTAuthenticator) {
			policy.UserValidationRules = []apiserver.UserValidationRule{{Expression: "user."}}
		}},
		{name: "extra key without domain", mutate: func(policy *apiserver.JWTAuthenticator) {
			policy.ClaimMappings.Extra = []apiserver.ExtraMapping{{Key: "role", ValueExpression: "claims.role"}}
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			policy := base
			tc.mutate(&policy)
			engine := New(context.Background(), Options{Client: client})
			t.Cleanup(engine.Close)
			if _, err := engine.Authenticate(t.Context(), "unused", policy); err == nil || !strings.Contains(err.Error(), "validate OIDC authenticator policy") {
				t.Fatalf("expected policy validation failure, got %v", err)
			}
		})
	}
	if got := atomic.LoadInt32(&requests); got != 0 {
		t.Fatalf("invalid policies made %d network requests", got)
	}
}

func TestMalformedExplicitJWKSURLFailsAuthentication(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	engine := New(context.Background(), Options{JWKSURL: "://invalid"})
	t.Cleanup(engine.Close)
	policy := apiserver.JWTAuthenticator{
		Issuer:        apiserver.Issuer{URL: "https://issuer.example", Audiences: []string{"breakglass"}},
		ClaimMappings: apiserver.ClaimMappings{Username: apiserver.PrefixedClaimOrExpression{Claim: "sub", Prefix: stringPtr("")}},
	}
	claims := map[string]any{"iss": policy.Issuer.URL, "aud": "breakglass", "sub": "operator", "exp": time.Now().Add(time.Minute).Unix(), "iat": time.Now().Unix()}
	if _, err := engine.Authenticate(t.Context(), signToken(t, key, claims), policy); err == nil {
		t.Fatal("expected malformed JWKS URL failure")
	}
}

func TestNegativeMaxAuthenticatorsUsesBoundedDefault(t *testing.T) {
	engine := New(context.Background(), Options{KeySet: &coreosoidc.StaticKeySet{}, MaxAuthenticators: -1})
	t.Cleanup(engine.Close)
	if engine.options.MaxAuthenticators != 32 {
		t.Fatalf("MaxAuthenticators = %d, want 32", engine.options.MaxAuthenticators)
	}
}

func TestOversizedCustomDiscoveryDocumentIsRejected(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		body := `{"issuer":"https://issuer.example","jwks_uri":"https://keys.example/jwks","padding":"` + strings.Repeat("x", 1<<20) + `"}`
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(body)), Header: make(http.Header)}, nil
	})}
	engine := New(context.Background(), Options{Client: client})
	t.Cleanup(engine.Close)
	policy := apiserver.JWTAuthenticator{
		Issuer:        apiserver.Issuer{URL: "https://issuer.example", DiscoveryURL: "https://discovery.example/config", Audiences: []string{"breakglass"}},
		ClaimMappings: apiserver.ClaimMappings{Username: apiserver.PrefixedClaimOrExpression{Claim: "sub", Prefix: stringPtr("")}},
	}
	if _, err := engine.Authenticate(t.Context(), "unused", policy); err == nil || !strings.Contains(err.Error(), "decode discovery document") {
		t.Fatalf("expected oversized discovery document failure, got %v", err)
	}
}
