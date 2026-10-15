// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package oidc

import (
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"k8s.io/apiserver/pkg/apis/apiserver"
)

func TestCloseRejectsAuthenticatorCreatedDuringShutdown(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	var startedOnce sync.Once
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		startedOnce.Do(func() { close(started) })
		<-release
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"issuer":"https://issuer.example","jwks_uri":"https://keys.example/jwks"}`)), Header: make(http.Header)}, nil
	})
	engine := New(context.Background(), Options{Client: &http.Client{Transport: transport}})
	t.Cleanup(func() { releaseAll(); engine.Close() })
	policy := apiserver.JWTAuthenticator{Issuer: apiserver.Issuer{URL: "https://issuer.example", DiscoveryURL: "https://discovery.example/config", Audiences: []string{"breakglass"}}, ClaimMappings: apiserver.ClaimMappings{Username: apiserver.PrefixedClaimOrExpression{Claim: "sub", Prefix: stringPtr("")}}}
	done := make(chan error, 1)
	go func() {
		_, err := engine.get(context.Background(), policy)
		done <- err
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("discovery request did not start")
	}
	engine.Close()
	releaseAll()
	select {
	case err := <-done:
		if err == nil || !strings.Contains(err.Error(), "engine is closed") {
			t.Fatalf("discovery creation returned %v, want closed-engine error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("blocked discovery did not finish after release")
	}
	if len(engine.items) != 0 {
		t.Fatalf("closed engine retained %d authenticators", len(engine.items))
	}
}

func TestConcurrentSamePolicyCreationIsBoundedAndConsistent(t *testing.T) {
	const callers = 16
	started := make(chan struct{}, callers)
	release := make(chan struct{})
	var releaseOnce sync.Once
	releaseAll := func() { releaseOnce.Do(func() { close(release) }) }
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		started <- struct{}{}
		<-release
		return &http.Response{StatusCode: http.StatusOK, Body: io.NopCloser(strings.NewReader(`{"issuer":"https://issuer.example","jwks_uri":"https://keys.example/jwks"}`)), Header: make(http.Header)}, nil
	})
	engine := New(context.Background(), Options{Client: &http.Client{Transport: transport}, MaxAuthenticators: 2})
	defer func() { releaseAll(); engine.Close() }()
	policy := apiserver.JWTAuthenticator{Issuer: apiserver.Issuer{URL: "https://issuer.example", DiscoveryURL: "https://discovery.example/config", Audiences: []string{"breakglass"}}, ClaimMappings: apiserver.ClaimMappings{Username: apiserver.PrefixedClaimOrExpression{Claim: "sub", Prefix: stringPtr("")}}}
	results := make(chan error, callers)
	var wg sync.WaitGroup
	wg.Add(callers)
	for range callers {
		go func() {
			defer wg.Done()
			_, err := engine.get(t.Context(), policy)
			results <- err
		}()
	}
	for range callers {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("concurrent discovery request did not start")
		}
	}
	releaseAll()
	wg.Wait()
	close(results)
	for err := range results {
		if err != nil {
			t.Fatal(err)
		}
	}
	if len(engine.items) != 1 {
		t.Fatalf("same policy created %d cached authenticators, want 1", len(engine.items))
	}
}

func TestJWKSCacheRemainsBoundedAcrossDistinctDiscoveryURLs(t *testing.T) {
	client := &http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		issuer := strings.TrimPrefix(req.URL.Path, "/")
		return &http.Response{
			StatusCode: http.StatusOK,
			Body:       io.NopCloser(strings.NewReader(`{"issuer":"https://` + issuer + `", "jwks_uri":"https://keys.example/` + issuer + `"}`)),
			Header:     make(http.Header),
		}, nil
	})}
	engine := New(context.Background(), Options{Client: client, MaxAuthenticators: 2})
	defer engine.Close()
	for _, issuer := range []string{"one.example", "two.example", "three.example"} {
		policy := apiserver.JWTAuthenticator{Issuer: apiserver.Issuer{URL: "https://" + issuer, DiscoveryURL: "https://discovery.example/" + issuer, Audiences: []string{"breakglass"}}, ClaimMappings: apiserver.ClaimMappings{Username: apiserver.PrefixedClaimOrExpression{Claim: "sub", Prefix: stringPtr("")}}}
		if _, err := engine.get(t.Context(), policy); err != nil {
			t.Fatal(err)
		}
	}
	if len(engine.keys) > 2 || len(engine.items) > 2 {
		t.Fatalf("cache bounds exceeded: authenticators=%d jwks=%d", len(engine.items), len(engine.keys))
	}
}

func TestCloseIsIdempotentIncludingNilEngine(t *testing.T) {
	var nilEngine *Engine
	nilEngine.Close()
	engine := New(nil, Options{KeySet: &coreosoidc.StaticKeySet{}})
	engine.Close()
	engine.Close()
}
