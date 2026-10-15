// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

// Package oidc provides the Kubernetes API server OIDC authenticator behind a
// small, bounded cache suitable for a dynamically configured service.
package oidc

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	coreosoidc "github.com/coreos/go-oidc/v3/oidc"
	"k8s.io/apiserver/pkg/apis/apiserver"
	apiservervalidation "k8s.io/apiserver/pkg/apis/apiserver/validation"
	"k8s.io/apiserver/pkg/authentication/authenticator"
	authenticationcel "k8s.io/apiserver/pkg/authentication/cel"
	"k8s.io/apiserver/plugin/pkg/authenticator/token/oidc"
)

// Options controls the remote OIDC connection and cache. Client must enforce
// the caller's TLS and network policy; it is used for discovery and JWKS.
type Options struct {
	Client  *http.Client
	JWKSURL string
	// KeySet is an optional injected verifier, primarily for tests and callers
	// that already maintain an immutable key set.
	KeySet               coreosoidc.KeySet
	MaxAuthenticators    int
	SupportedSigningAlgs []string
}

// Engine verifies and maps tokens using Kubernetes' upstream authenticator.
type Engine struct {
	ctx     context.Context
	cancel  context.CancelFunc
	client  *http.Client
	options Options

	mu     sync.Mutex
	items  map[string]*entry
	keys   map[string]coreosoidc.KeySet
	closed bool
}

type entry struct {
	auth   oidc.AuthenticatorTokenWithHealthCheck
	cancel context.CancelFunc
}

// New creates an engine. A nil client uses a bounded 30-second HTTP client.
func New(parent context.Context, options Options) *Engine {
	if parent == nil {
		parent = context.Background()
	}
	ctx, cancel := context.WithCancel(parent)
	if options.Client == nil {
		options.Client = &http.Client{Timeout: 30 * time.Second}
	}
	if options.MaxAuthenticators < 1 {
		options.MaxAuthenticators = 32
	}
	return &Engine{ctx: ctx, cancel: cancel, client: options.Client, options: options, items: make(map[string]*entry), keys: make(map[string]coreosoidc.KeySet)}
}

// Authenticate verifies rawToken and applies policy's claim mappings and
// validation rules. The returned response is the upstream user identity.
func (e *Engine) Authenticate(ctx context.Context, rawToken string, policy apiserver.JWTAuthenticator) (*authenticator.Response, error) {
	if e == nil {
		return nil, fmt.Errorf("oidc engine is nil")
	}
	if policy.Issuer.URL == "" {
		return nil, fmt.Errorf("oidc issuer URL is required")
	}
	auth, err := e.get(ctx, policy)
	if err != nil {
		return nil, err
	}
	response, ok, err := auth.AuthenticateToken(ctx, rawToken)
	if err != nil {
		return nil, fmt.Errorf("authenticate OIDC token: %w", err)
	}
	if !ok || response == nil || response.User == nil {
		return nil, fmt.Errorf("OIDC token was not accepted")
	}
	return response, nil
}

func (e *Engine) get(ctx context.Context, policy apiserver.JWTAuthenticator) (oidc.AuthenticatorTokenWithHealthCheck, error) {
	key, err := cacheKey(policy, e.options)
	if err != nil {
		return nil, err
	}
	e.mu.Lock()
	if e.closed {
		e.mu.Unlock()
		return nil, fmt.Errorf("oidc engine is closed")
	}
	if cached := e.items[key]; cached != nil {
		auth := cached.auth
		e.mu.Unlock()
		return auth, nil
	}
	if len(e.items) >= e.options.MaxAuthenticators {
		// The cache is intentionally bounded. Evicting an arbitrary entry keeps
		// this engine small; callers should use stable policies so re-creation is rare.
		for oldKey, old := range e.items {
			old.cancel()
			delete(e.items, oldKey)
			break
		}
	}
	child, cancel := context.WithCancel(e.ctx)
	e.mu.Unlock()

	auth, err := e.newAuthenticator(child, ctx, policy)
	if err != nil {
		cancel()
		return nil, fmt.Errorf("create OIDC authenticator: %w", err)
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closed {
		cancel()
		return nil, fmt.Errorf("oidc engine is closed")
	}
	if existing := e.items[key]; existing != nil {
		cancel()
		return existing.auth, nil
	}
	if len(e.items) >= e.options.MaxAuthenticators {
		for oldKey, old := range e.items {
			old.cancel()
			delete(e.items, oldKey)
			break
		}
	}
	e.items[key] = &entry{auth: auth, cancel: cancel}
	return auth, nil
}

func (e *Engine) newAuthenticator(lifecycle, requestCtx context.Context, policy apiserver.JWTAuthenticator) (oidc.AuthenticatorTokenWithHealthCheck, error) {
	_, validation := apiservervalidation.CompileAndValidateJWTAuthenticator(authenticationcel.NewDefaultCompiler(), policy, nil)
	if err := validation.ToAggregate(); err != nil {
		return nil, fmt.Errorf("validate OIDC authenticator policy: %w", err)
	}
	keySet, err := e.keySet(requestCtx, policy)
	if err != nil {
		return nil, err
	}
	// Discovery was resolved synchronously above. Kubernetes rejects a KeySet
	// together with DiscoveryURL, even though the resolved issuer is valid.
	policy.Issuer.DiscoveryURL = ""
	options := oidc.Options{
		JWTAuthenticator:     policy,
		KeySet:               keySet,
		Client:               e.client,
		SupportedSigningAlgs: e.options.SupportedSigningAlgs,
	}
	return oidc.New(lifecycle, options)
}

func (e *Engine) keySet(requestCtx context.Context, policy apiserver.JWTAuthenticator) (coreosoidc.KeySet, error) {
	if e.options.KeySet != nil {
		return e.options.KeySet, nil
	}
	jwksURL := e.options.JWKSURL
	if jwksURL == "" {
		var err error
		if policy.Issuer.DiscoveryURL == "" {
			provider, providerErr := coreosoidc.NewProvider(coreosoidc.ClientContext(requestCtx, e.client), policy.Issuer.URL)
			if providerErr != nil {
				return nil, fmt.Errorf("discover OIDC issuer: %w", providerErr)
			}
			var discovery struct {
				JWKSURL string `json:"jwks_uri"`
			}
			err = provider.Claims(&discovery)
			jwksURL = discovery.JWKSURL
		} else {
			jwksURL, err = e.discoveryJWKSURL(requestCtx, policy)
		}
		if err != nil {
			return nil, fmt.Errorf("resolve OIDC JWKS endpoint: %w", err)
		}
	}
	if jwksURL == "" {
		return nil, fmt.Errorf("OIDC discovery returned an empty jwks_uri")
	}
	e.mu.Lock()
	if keySet := e.keys[jwksURL]; keySet != nil {
		e.mu.Unlock()
		return keySet, nil
	}
	keySet := coreosoidc.NewRemoteKeySet(coreosoidc.ClientContext(e.ctx, e.client), jwksURL)
	if len(e.keys) >= e.options.MaxAuthenticators {
		for oldURL := range e.keys {
			delete(e.keys, oldURL)
			break
		}
	}
	e.keys[jwksURL] = keySet
	e.mu.Unlock()
	return keySet, nil
}

func (e *Engine) discoveryJWKSURL(ctx context.Context, policy apiserver.JWTAuthenticator) (string, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, policy.Issuer.DiscoveryURL, nil)
	if err != nil {
		return "", fmt.Errorf("create discovery request: %w", err)
	}
	resp, err := e.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("fetch discovery document: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("discovery returned HTTP %d", resp.StatusCode)
	}
	var discovery struct {
		Issuer  string `json:"issuer"`
		JWKSURL string `json:"jwks_uri"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&discovery); err != nil {
		return "", fmt.Errorf("decode discovery document: %w", err)
	}
	if discovery.Issuer != policy.Issuer.URL {
		return "", fmt.Errorf("discovery issuer %q does not match %q", discovery.Issuer, policy.Issuer.URL)
	}
	return discovery.JWKSURL, nil
}

func cacheKey(policy apiserver.JWTAuthenticator, options Options) (string, error) {
	// The policy is the complete authenticator contract. Hashing its JSON keeps
	// cache keys bounded even when CEL expressions are long.
	b, err := json.Marshal(struct {
		Policy apiserver.JWTAuthenticator
		JWKS   string
		Algs   []string
	}{policy, options.JWKSURL, options.SupportedSigningAlgs})
	if err != nil {
		return "", fmt.Errorf("marshal OIDC authenticator policy: %w", err)
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:]), nil
}

// Close stops all authenticator lifecycles. It is safe to call more than once.
func (e *Engine) Close() {
	if e == nil {
		return
	}
	e.cancel()
	e.mu.Lock()
	defer e.mu.Unlock()
	e.closed = true
	for key, item := range e.items {
		item.cancel()
		delete(e.items, key)
	}
	clear(e.keys)
}
