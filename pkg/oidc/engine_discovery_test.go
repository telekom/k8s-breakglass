// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"k8s.io/apiserver/pkg/apis/apiserver"
)

func TestAuthenticateEmailUsernameVerification(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	engine := New(t.Context(), Options{KeySet: &coreosoidc.StaticKeySet{PublicKeys: []crypto.PublicKey{&key.PublicKey}}})
	t.Cleanup(engine.Close)
	policy := apiserver.JWTAuthenticator{
		Issuer:        apiserver.Issuer{URL: "https://issuer.example", Audiences: []string{"breakglass"}},
		ClaimMappings: apiserver.ClaimMappings{Username: apiserver.PrefixedClaimOrExpression{Claim: "email", Prefix: stringPtr("")}},
	}
	for _, tc := range []struct {
		name                string
		verified            any
		accepted            bool
		requireVerification bool
	}{
		{name: "absent follows upstream compatibility", accepted: true},
		{name: "verified", verified: true, accepted: true},
		{name: "unverified", verified: false},
		{name: "wrong verification type", verified: "true"},
		{name: "explicit verification rule rejects absent claim", requireVerification: true},
		{name: "explicit verification rule accepts true", verified: true, accepted: true, requireVerification: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			claims := map[string]any{"iss": policy.Issuer.URL, "aud": "breakglass", "email": "operator@example.com", "exp": time.Now().Add(time.Minute).Unix()}
			if tc.verified != nil {
				claims["email_verified"] = tc.verified
			}
			effective := policy
			if tc.requireVerification {
				effective.ClaimValidationRules = []apiserver.ClaimValidationRule{{Expression: "claims.?email_verified.orValue(false) == true"}}
			}
			response, err := engine.Authenticate(t.Context(), signToken(t, key, claims), effective)
			if tc.accepted {
				require.NoError(t, err)
				require.Equal(t, "operator@example.com", response.User.GetName())
			} else {
				require.Error(t, err)
				require.Nil(t, response)
			}
		})
	}
}

func TestAuthenticateDiscoveryFailures(t *testing.T) {
	for _, custom := range []bool{false, true} {
		mode := "issuer discovery"
		if custom {
			mode = "custom discovery"
		}
		t.Run(mode, func(t *testing.T) {
			for _, tc := range []struct {
				name   string
				status int
				body   string
				err    error
			}{
				{name: "transport failure", err: errors.New("discovery connection failed")},
				{name: "HTTP failure", status: http.StatusServiceUnavailable, body: "unavailable"},
				{name: "malformed JSON", status: http.StatusOK, body: "{"},
				{name: "wrong issuer", status: http.StatusOK, body: `{"issuer":"https://other.example","jwks_uri":"https://keys.example/jwks"}`},
				{name: "missing issuer", status: http.StatusOK, body: `{"jwks_uri":"https://keys.example/jwks"}`},
				{name: "missing JWKS", status: http.StatusOK, body: `{"issuer":"https://issuer.example"}`},
				{name: "wrong JWKS type", status: http.StatusOK, body: `{"issuer":"https://issuer.example","jwks_uri":42}`},
			} {
				t.Run(tc.name, func(t *testing.T) {
					requests := 0
					client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
						requests++
						assert.NotEqual(t, "keys.example", req.URL.Host, "failed discovery must not proceed to JWKS")
						if tc.err != nil {
							return nil, tc.err
						}
						return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body)), Header: make(http.Header)}, nil
					})}
					engine := New(t.Context(), Options{Client: client})
					t.Cleanup(engine.Close)
					policy := apiserver.JWTAuthenticator{
						Issuer:        apiserver.Issuer{URL: "https://issuer.example", Audiences: []string{"breakglass"}},
						ClaimMappings: apiserver.ClaimMappings{Username: apiserver.PrefixedClaimOrExpression{Claim: "sub", Prefix: stringPtr("")}},
					}
					if custom {
						policy.Issuer.DiscoveryURL = "https://discovery.example/config"
					}
					response, err := engine.Authenticate(t.Context(), "unused-before-discovery", policy)
					require.Error(t, err)
					require.Nil(t, response)
					require.Equal(t, 1, requests, "failure must come from discovery, not policy or token validation")
				})
			}
		})
	}
}

func TestAuthenticateJWKSFailures(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	policy := apiserver.JWTAuthenticator{
		Issuer:        apiserver.Issuer{URL: "https://issuer.example", Audiences: []string{"breakglass"}},
		ClaimMappings: apiserver.ClaimMappings{Username: apiserver.PrefixedClaimOrExpression{Claim: "sub", Prefix: stringPtr("")}},
	}
	token := signToken(t, key, map[string]any{"iss": policy.Issuer.URL, "aud": "breakglass", "sub": "operator", "exp": time.Now().Add(time.Minute).Unix()})
	for _, tc := range []struct {
		name   string
		status int
		body   string
		err    error
	}{
		{name: "transport failure", err: errors.New("JWKS connection failed")},
		{name: "HTTP failure", status: http.StatusServiceUnavailable, body: "unavailable"},
		{name: "malformed JSON", status: http.StatusOK, body: "{"},
		{name: "empty key set", status: http.StatusOK, body: `{"keys":[]}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			requests := 0
			client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
				requests++
				assert.Equal(t, "https://keys.example/jwks", req.URL.String(), "explicit JWKS must bypass discovery")
				if tc.err != nil {
					return nil, tc.err
				}
				return &http.Response{StatusCode: tc.status, Body: io.NopCloser(strings.NewReader(tc.body)), Header: make(http.Header)}, nil
			})}
			engine := New(t.Context(), Options{Client: client, JWKSURL: "https://keys.example/jwks"})
			t.Cleanup(engine.Close)
			response, err := engine.Authenticate(t.Context(), token, policy)
			require.ErrorContains(t, err, "authenticate OIDC token")
			require.Nil(t, response)
			require.Positive(t, requests, "failure must exercise JWKS retrieval")
		})
	}
}
