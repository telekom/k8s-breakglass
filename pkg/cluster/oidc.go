package cluster

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/utils"
)

// TokenRefreshBuffer is the duration before expiry when we proactively refresh tokens
const TokenRefreshBuffer = 30 * time.Second

// OIDCTokenProvider manages OIDC token acquisition for cluster authentication.
// It supports both client credentials flow and token exchange flow, with automatic
// token refresh and TOFU (Trust On First Use) for API server CA certificates.
type OIDCTokenProvider struct {
	k8s    client.Client
	log    *zap.SugaredLogger
	tokens map[string]*cachedToken
	mu     sync.RWMutex
	// httpClients caches OIDC HTTP clients by issuer/config key
	httpClients map[string]*http.Client
	httpMu      sync.RWMutex
	// tofuCAs stores discovered CA certificates for TOFU (cluster name -> CA PEM)
	tofuCAs map[string][]byte
	tofuMu  sync.RWMutex
	// issuerTOFUCAs stores discovered CA certificates for OIDC issuers (issuer URL -> CA PEM)
	issuerTOFUCAs map[string][]byte
	issuerTOFUMu  sync.RWMutex
}

// cachedToken stores a token with its expiry time and refresh token
type cachedToken struct {
	accessToken  string
	refreshToken string
	expiresAt    time.Time
}

// tokenResponse represents the OIDC token endpoint response
type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int    `json:"expires_in"`
	RefreshToken string `json:"refresh_token,omitempty"`
	Scope        string `json:"scope,omitempty"`
}

// oidcDiscovery represents the OIDC discovery document
type oidcDiscovery struct {
	Issuer                string `json:"issuer"`
	TokenEndpoint         string `json:"token_endpoint"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

// NewOIDCTokenProvider creates a new OIDC token provider
func NewOIDCTokenProvider(k8s client.Client, log *zap.SugaredLogger) *OIDCTokenProvider {
	return &OIDCTokenProvider{
		k8s:           k8s,
		log:           log.Named("oidc-token-provider"),
		tokens:        make(map[string]*cachedToken),
		httpClients:   make(map[string]*http.Client),
		tofuCAs:       make(map[string][]byte),
		issuerTOFUCAs: make(map[string][]byte),
	}
}

// tokenCacheKey generates a namespaced cache key for OIDC tokens.
// This ensures tokens from ClusterConfigs with the same name in different namespaces
// are cached separately and don't collide.
//
// When namespace is the empty string, the returned key will have a leading slash,
// e.g. "/cluster-name". This behavior is intentional and kept for backward
// compatibility with the deprecated cacheToken() method. Callers must not rely
// on the presence or absence of a leading slash to infer whether a namespace was
// set; they should treat the returned value as an opaque cache key.
func tokenCacheKey(namespace, name string) string {
	return fmt.Sprintf("%s/%s", namespace, name)
}

// GetRESTConfig builds a rest.Config using OIDC authentication for the given cluster config.
// It supports both direct oidcAuth configuration and oidcFromIdentityProvider references.
// The returned config uses WrapTransport to inject fresh tokens on each request,
// allowing the config to be cached while tokens are refreshed dynamically.
func (p *OIDCTokenProvider) GetRESTConfig(ctx context.Context, cc *v1alpha1.ClusterConfig) (*rest.Config, error) {
	var oidc *v1alpha1.OIDCAuthConfig

	// Resolve OIDC configuration from either direct config or IdentityProvider reference
	if cc.Spec.OIDCFromIdentityProvider != nil {
		var err error
		oidc, err = p.resolveOIDCFromIdentityProvider(ctx, cc)
		if err != nil {
			return nil, fmt.Errorf("failed to resolve OIDC from IdentityProvider: %w", err)
		}
	} else if cc.Spec.OIDCAuth != nil {
		oidc = cc.Spec.OIDCAuth
	} else {
		return nil, fmt.Errorf("either oidcAuth or oidcFromIdentityProvider configuration is required")
	}

	clusterName := cc.Name
	namespace := cc.Namespace

	// Build rest.Config without static bearer token - we'll use WrapTransport instead
	cfg := &rest.Config{
		Host: oidc.Server,
	}

	// Configure TLS for the cluster API server
	if err := p.configureTLS(ctx, cfg, oidc); err != nil {
		return nil, fmt.Errorf("failed to configure TLS for cluster %s: %w", clusterName, err)
	}

	// Use WrapTransport to inject fresh tokens on each request
	// This allows the rest.Config to be cached while tokens are refreshed dynamically
	cfg.WrapTransport = p.createTokenInjector(clusterName, oidc, namespace)

	// Apply QPS and burst settings
	if cc.Spec.QPS != nil {
		cfg.QPS = float32(*cc.Spec.QPS)
	}
	if cc.Spec.Burst != nil {
		cfg.Burst = int(*cc.Spec.Burst)
	}

	return cfg, nil
}

// tokenInjectorRoundTripper wraps an http.RoundTripper to inject OIDC bearer tokens.
type tokenInjectorRoundTripper struct {
	delegate    http.RoundTripper
	provider    *OIDCTokenProvider
	clusterName string
	oidc        *v1alpha1.OIDCAuthConfig
	namespace   string
}

// RoundTrip implements http.RoundTripper, injecting fresh bearer tokens on each request.
func (t *tokenInjectorRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// Get fresh token (uses cache with automatic refresh)
	token, err := t.provider.getToken(req.Context(), t.clusterName, t.oidc, t.namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to get OIDC token for cluster %s: %w", t.clusterName, err)
	}

	// Clone request to avoid modifying the original
	reqClone := req.Clone(req.Context())
	reqClone.Header.Set("Authorization", "Bearer "+token)

	return t.delegate.RoundTrip(reqClone)
}

// createTokenInjector returns a transport wrapper that injects fresh OIDC tokens.
func (p *OIDCTokenProvider) createTokenInjector(clusterName string, oidc *v1alpha1.OIDCAuthConfig, namespace string) func(rt http.RoundTripper) http.RoundTripper {
	return func(rt http.RoundTripper) http.RoundTripper {
		return &tokenInjectorRoundTripper{
			delegate:    rt,
			provider:    p,
			clusterName: clusterName,
			oidc:        oidc,
			namespace:   namespace,
		}
	}
}

// resolveOIDCFromIdentityProvider builds an OIDCAuthConfig by resolving the referenced IdentityProvider
// and merging it with the cluster-specific configuration from OIDCFromIdentityProviderConfig.
func (p *OIDCTokenProvider) resolveOIDCFromIdentityProvider(ctx context.Context, cc *v1alpha1.ClusterConfig) (*v1alpha1.OIDCAuthConfig, error) {
	ref := cc.Spec.OIDCFromIdentityProvider

	// Fetch the referenced IdentityProvider
	idp := &v1alpha1.IdentityProvider{}
	if err := p.k8s.Get(ctx, types.NamespacedName{Name: ref.Name}, idp); err != nil {
		if apierrors.IsNotFound(err) {
			return nil, fmt.Errorf("IdentityProvider %q not found", ref.Name)
		}
		return nil, fmt.Errorf("failed to get IdentityProvider %q: %w", ref.Name, err)
	}

	// Check if the IdentityProvider is disabled
	if idp.Spec.Disabled {
		return nil, fmt.Errorf("IdentityProvider %q is disabled", ref.Name)
	}

	// Determine clientID - use override from ref, or fall back to IdentityProvider
	clientID := ref.ClientID
	if clientID == "" {
		clientID = idp.Spec.OIDC.ClientID
	}

	// Build OIDCAuthConfig from IdentityProvider OIDC settings + cluster-specific settings
	oidc := &v1alpha1.OIDCAuthConfig{
		IssuerURL:             idp.Spec.OIDC.Authority,
		ClientID:              clientID,
		Server:                ref.Server,
		CASecretRef:           ref.CASecretRef,
		ClientSecretRef:       ref.ClientSecretRef,
		InsecureSkipTLSVerify: ref.InsecureSkipTLSVerify,
		AllowTOFU:             ref.AllowTOFU,
	}

	// If client secret is not specified in the reference, try to use Keycloak service account credentials
	if oidc.ClientSecretRef == nil && idp.Spec.Keycloak != nil {
		p.log.Debugw("Using Keycloak service account credentials for OIDC auth",
			"cluster", cc.Name, "identityProvider", ref.Name)
		oidc.ClientID = idp.Spec.Keycloak.ClientID
		oidc.ClientSecretRef = &idp.Spec.Keycloak.ClientSecretRef
	}

	// Validate required fields
	if oidc.ClientSecretRef == nil {
		return nil, fmt.Errorf("clientSecretRef is required: either specify it in oidcFromIdentityProvider or ensure the IdentityProvider has Keycloak service account configured")
	}

	p.log.Debugw("Resolved OIDC config from IdentityProvider",
		"cluster", cc.Name,
		"identityProvider", ref.Name,
		"issuerURL", oidc.IssuerURL,
		"clientID", oidc.ClientID,
		"server", oidc.Server)

	return oidc, nil
}

// getToken retrieves a valid token, refreshing if necessary using refresh tokens when available.
// This follows kubelogin's pattern: check cache -> try refresh token -> fall back to full auth
func (p *OIDCTokenProvider) getToken(ctx context.Context, clusterName string, oidc *v1alpha1.OIDCAuthConfig, namespace string) (string, error) {
	cacheKey := tokenCacheKey(namespace, clusterName)
	p.mu.RLock()
	cached, ok := p.tokens[cacheKey]
	p.mu.RUnlock()

	// Return cached token if still valid (with buffer for proactive refresh)
	if ok && time.Now().Add(TokenRefreshBuffer).Before(cached.expiresAt) {
		p.log.Debugw("Using cached token", "cluster", clusterName, "namespace", namespace, "expiresAt", cached.expiresAt)
		return cached.accessToken, nil
	}

	// Try to refresh using refresh token if available
	if ok && cached.refreshToken != "" {
		p.log.Debugw("Attempting token refresh", "cluster", clusterName, "namespace", namespace)
		token, err := p.refreshToken(ctx, oidc, cached.refreshToken)
		if err == nil {
			p.cacheTokenWithNamespace(namespace, clusterName, token)
			p.log.Debugw("Token refreshed successfully", "cluster", clusterName, "namespace", namespace, "expiresIn", token.ExpiresIn)
			return token.AccessToken, nil
		}
		// Refresh failed, fall through to full authentication
		p.log.Warnw("Token refresh failed, will re-authenticate", "cluster", clusterName, "namespace", namespace, "error", err)
	}

	// Acquire new token
	var token *tokenResponse
	var err error

	if oidc.TokenExchange != nil && oidc.TokenExchange.Enabled {
		// Token exchange flow - exchange a subject token for a cluster-scoped token
		token, err = p.tokenExchangeFromSecret(ctx, oidc, namespace)
		if err != nil {
			return "", fmt.Errorf("token exchange flow failed: %w", err)
		}
	} else {
		// Client credentials flow
		token, err = p.clientCredentialsFlow(ctx, oidc)
		if err != nil {
			return "", fmt.Errorf("client credentials flow failed: %w", err)
		}
	}

	// Cache the token (including refresh token if provided)
	p.cacheTokenWithNamespace(namespace, clusterName, token)

	p.log.Debugw("Acquired OIDC token", "cluster", clusterName, "namespace", namespace, "expiresIn", token.ExpiresIn, "hasRefreshToken", token.RefreshToken != "")
	return token.AccessToken, nil
}

// cacheTokenWithNamespace stores a token in the cache using a namespaced key.
// This ensures tokens from ClusterConfigs with the same name in different namespaces
// are cached separately.
func (p *OIDCTokenProvider) cacheTokenWithNamespace(namespace, clusterName string, token *tokenResponse) {
	cacheKey := tokenCacheKey(namespace, clusterName)
	expiresAt := time.Now().Add(time.Duration(token.ExpiresIn) * time.Second)
	p.mu.Lock()
	p.tokens[cacheKey] = &cachedToken{
		accessToken:  token.AccessToken,
		refreshToken: token.RefreshToken,
		expiresAt:    expiresAt,
	}
	p.mu.Unlock()
}

// Deprecated: cacheToken stores a token in the cache using an empty namespace.
// Use cacheTokenWithNamespace instead for proper namespace isolation.
// This method is kept for backward compatibility and will be removed in v2.0.
// Migration: Replace `p.cacheToken(name, token)` with `p.cacheTokenWithNamespace(namespace, name, token)`.
func (p *OIDCTokenProvider) cacheToken(clusterName string, token *tokenResponse) {
	p.cacheTokenWithNamespace("", clusterName, token)
}

// refreshToken attempts to refresh an access token using a refresh token
func (p *OIDCTokenProvider) refreshToken(ctx context.Context, oidc *v1alpha1.OIDCAuthConfig, refreshTok string) (*tokenResponse, error) {
	// Discover token endpoint
	tokenEndpoint, err := p.discoverTokenEndpoint(ctx, oidc)
	if err != nil {
		return nil, fmt.Errorf("failed to discover token endpoint: %w", err)
	}

	// Get client secret (may be needed for token refresh)
	clientSecret, err := p.getClientSecret(ctx, oidc)
	if err != nil {
		return nil, fmt.Errorf("failed to get client secret: %w", err)
	}

	// Build refresh token request
	data := url.Values{
		"grant_type":    {"refresh_token"},
		"client_id":     {oidc.ClientID},
		"client_secret": {clientSecret},
		"refresh_token": {refreshTok},
	}

	// Create HTTP client
	httpClient, err := p.createOIDCHTTPClient(oidc)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// Make request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create refresh token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("refresh token request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read refresh token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("refresh token request returned status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp tokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse refresh token response: %w", err)
	}

	// Some providers return the same refresh token, some return a new one
	// If no new refresh token, keep the old one
	if tokenResp.RefreshToken == "" {
		tokenResp.RefreshToken = refreshTok
	}

	return &tokenResp, nil
}

// clientCredentialsFlow performs the OAuth 2.0 client credentials flow
func (p *OIDCTokenProvider) clientCredentialsFlow(ctx context.Context, oidc *v1alpha1.OIDCAuthConfig) (*tokenResponse, error) {
	// Discover token endpoint
	tokenEndpoint, err := p.discoverTokenEndpoint(ctx, oidc)
	if err != nil {
		return nil, fmt.Errorf("failed to discover token endpoint: %w", err)
	}

	// Get client secret
	clientSecret, err := p.getClientSecret(ctx, oidc)
	if err != nil {
		return nil, fmt.Errorf("failed to get client secret: %w", err)
	}

	// Build request
	data := url.Values{
		"grant_type":    {"client_credentials"},
		"client_id":     {oidc.ClientID},
		"client_secret": {clientSecret},
	}

	// Add audience if specified
	if oidc.Audience != "" {
		data.Set("audience", oidc.Audience)
	}

	// Add scopes
	scopes := []string{"openid"}
	scopes = append(scopes, oidc.Scopes...)
	data.Set("scope", strings.Join(scopes, " "))

	// Create HTTP client with TLS config for OIDC issuer
	httpClient, err := p.createOIDCHTTPClient(oidc)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// Make request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token request returned status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp tokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token response: %w", err)
	}

	return &tokenResp, nil
}

// TokenExchangeFlow performs OAuth 2.0 token exchange (RFC 8693)
// This exchanges a subject token (e.g., user's token) for a new token scoped to the target cluster.
func (p *OIDCTokenProvider) TokenExchangeFlow(ctx context.Context, oidc *v1alpha1.OIDCAuthConfig, subjectToken string) (*tokenResponse, error) {
	if oidc.TokenExchange == nil || !oidc.TokenExchange.Enabled {
		return nil, fmt.Errorf("token exchange is not enabled")
	}

	// Discover token endpoint
	tokenEndpoint, err := p.discoverTokenEndpoint(ctx, oidc)
	if err != nil {
		return nil, fmt.Errorf("failed to discover token endpoint: %w", err)
	}

	// Get client secret
	clientSecret, err := p.getClientSecret(ctx, oidc)
	if err != nil {
		return nil, fmt.Errorf("failed to get client secret: %w", err)
	}

	// Build token exchange request
	subjectTokenType := oidc.TokenExchange.SubjectTokenType
	if subjectTokenType == "" {
		subjectTokenType = "urn:ietf:params:oauth:token-type:access_token"
	}

	requestedTokenType := oidc.TokenExchange.RequestedTokenType
	if requestedTokenType == "" {
		requestedTokenType = "urn:ietf:params:oauth:token-type:access_token"
	}

	data := url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":            {oidc.ClientID},
		"client_secret":        {clientSecret},
		"subject_token":        {subjectToken},
		"subject_token_type":   {subjectTokenType},
		"requested_token_type": {requestedTokenType},
	}

	// Add audience if specified
	if oidc.Audience != "" {
		data.Set("audience", oidc.Audience)
	}

	// Add resource if specified
	if oidc.TokenExchange.Resource != "" {
		data.Set("resource", oidc.TokenExchange.Resource)
	}

	// Add scopes
	if len(oidc.Scopes) > 0 {
		data.Set("scope", strings.Join(oidc.Scopes, " "))
	}

	// Create HTTP client
	httpClient, err := p.createOIDCHTTPClient(oidc)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// Make request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token exchange response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange returned status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp tokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token exchange response: %w", err)
	}

	p.log.Debugw("Token exchange successful", "expiresIn", tokenResp.ExpiresIn)
	return &tokenResp, nil
}

// tokenExchangeFromSecret performs token exchange using a subject token from a Kubernetes secret.
// This is used when the controller needs to exchange a stored service token for a cluster-scoped token.
func (p *OIDCTokenProvider) tokenExchangeFromSecret(ctx context.Context, oidc *v1alpha1.OIDCAuthConfig, namespace string) (*tokenResponse, error) {
	if oidc.TokenExchange == nil || !oidc.TokenExchange.Enabled {
		return nil, fmt.Errorf("token exchange is not enabled")
	}

	if oidc.TokenExchange.SubjectTokenSecretRef == nil {
		return nil, fmt.Errorf("token exchange requires subjectTokenSecretRef when used for service authentication")
	}

	// Get subject token from secret
	subjectToken, err := p.getTokenFromSecret(ctx, oidc.TokenExchange.SubjectTokenSecretRef, namespace)
	if err != nil {
		return nil, fmt.Errorf("failed to get subject token from secret: %w", err)
	}

	// Get actor token if specified (for delegation scenarios)
	var actorToken string
	if oidc.TokenExchange.ActorTokenSecretRef != nil {
		actorToken, err = p.getTokenFromSecret(ctx, oidc.TokenExchange.ActorTokenSecretRef, namespace)
		if err != nil {
			return nil, fmt.Errorf("failed to get actor token from secret: %w", err)
		}
	}

	// Perform the token exchange
	return p.tokenExchangeWithActorToken(ctx, oidc, subjectToken, actorToken)
}

// tokenExchangeWithActorToken performs token exchange with optional actor token (RFC 8693)
func (p *OIDCTokenProvider) tokenExchangeWithActorToken(ctx context.Context, oidc *v1alpha1.OIDCAuthConfig, subjectToken, actorToken string) (*tokenResponse, error) {
	// Discover token endpoint
	tokenEndpoint, err := p.discoverTokenEndpoint(ctx, oidc)
	if err != nil {
		return nil, fmt.Errorf("failed to discover token endpoint: %w", err)
	}

	// Get client secret
	clientSecret, err := p.getClientSecret(ctx, oidc)
	if err != nil {
		return nil, fmt.Errorf("failed to get client secret: %w", err)
	}

	// Build token exchange request
	subjectTokenType := oidc.TokenExchange.SubjectTokenType
	if subjectTokenType == "" {
		subjectTokenType = "urn:ietf:params:oauth:token-type:access_token"
	}

	requestedTokenType := oidc.TokenExchange.RequestedTokenType
	if requestedTokenType == "" {
		requestedTokenType = "urn:ietf:params:oauth:token-type:access_token"
	}

	data := url.Values{
		"grant_type":           {"urn:ietf:params:oauth:grant-type:token-exchange"},
		"client_id":            {oidc.ClientID},
		"client_secret":        {clientSecret},
		"subject_token":        {subjectToken},
		"subject_token_type":   {subjectTokenType},
		"requested_token_type": {requestedTokenType},
	}

	// Add actor token if present (for delegation)
	if actorToken != "" {
		actorTokenType := "urn:ietf:params:oauth:token-type:access_token"
		if oidc.TokenExchange.ActorTokenType != "" {
			actorTokenType = oidc.TokenExchange.ActorTokenType
		}
		data.Set("actor_token", actorToken)
		data.Set("actor_token_type", actorTokenType)
	}

	// Add audience if specified
	if oidc.Audience != "" {
		data.Set("audience", oidc.Audience)
	}

	// Add resource if specified
	if oidc.TokenExchange.Resource != "" {
		data.Set("resource", oidc.TokenExchange.Resource)
	}

	// Add scopes
	if len(oidc.Scopes) > 0 {
		data.Set("scope", strings.Join(oidc.Scopes, " "))
	}

	// Create HTTP client
	httpClient, err := p.createOIDCHTTPClient(oidc)
	if err != nil {
		return nil, fmt.Errorf("failed to create HTTP client: %w", err)
	}

	// Make request
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tokenEndpoint, strings.NewReader(data.Encode()))
	if err != nil {
		return nil, fmt.Errorf("failed to create token exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("token exchange request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read token exchange response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("token exchange returned status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp tokenResponse
	if err := json.Unmarshal(body, &tokenResp); err != nil {
		return nil, fmt.Errorf("failed to parse token exchange response: %w", err)
	}

	p.log.Debugw("Token exchange with actor successful", "expiresIn", tokenResp.ExpiresIn, "hasActorToken", actorToken != "")
	return &tokenResp, nil
}

// getTokenFromSecret retrieves a token from a Kubernetes secret
func (p *OIDCTokenProvider) getTokenFromSecret(ctx context.Context, secretRef *v1alpha1.SecretKeyReference, namespace string) (string, error) {
	if secretRef == nil {
		return "", fmt.Errorf("secret reference is nil")
	}

	ns := namespace
	if secretRef.Namespace != "" {
		ns = secretRef.Namespace
	}

	var secret corev1.Secret
	if err := p.k8s.Get(ctx, types.NamespacedName{
		Namespace: ns,
		Name:      secretRef.Name,
	}, &secret); err != nil {
		return "", fmt.Errorf("failed to get secret %s/%s: %w", ns, secretRef.Name, err)
	}

	key := secretRef.Key
	if key == "" {
		key = "token" // default key name
	}

	tokenBytes, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("secret %s/%s does not contain key %q", ns, secretRef.Name, key)
	}

	return strings.TrimSpace(string(tokenBytes)), nil
}

// discoverTokenEndpoint discovers the token endpoint from OIDC discovery
func (p *OIDCTokenProvider) discoverTokenEndpoint(ctx context.Context, oidc *v1alpha1.OIDCAuthConfig) (string, error) {
	discoveryURL := strings.TrimSuffix(oidc.IssuerURL, "/") + "/.well-known/openid-configuration"

	httpClient, err := p.createOIDCHTTPClient(oidc)
	if err != nil {
		return "", err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, discoveryURL, nil)
	if err != nil {
		return "", err
	}

	resp, err := httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("OIDC discovery request failed: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("OIDC discovery returned status %d", resp.StatusCode)
	}

	var discovery oidcDiscovery
	if err := json.NewDecoder(resp.Body).Decode(&discovery); err != nil {
		return "", fmt.Errorf("failed to parse OIDC discovery: %w", err)
	}

	if discovery.TokenEndpoint == "" {
		return "", fmt.Errorf("OIDC discovery missing token_endpoint")
	}

	return discovery.TokenEndpoint, nil
}

// getClientSecret retrieves the client secret from the referenced secret
func (p *OIDCTokenProvider) getClientSecret(ctx context.Context, oidc *v1alpha1.OIDCAuthConfig) (string, error) {
	if oidc.ClientSecretRef == nil {
		return "", fmt.Errorf("clientSecretRef is required for client credentials flow")
	}

	var secret corev1.Secret
	if err := p.k8s.Get(ctx, types.NamespacedName{
		Name:      oidc.ClientSecretRef.Name,
		Namespace: oidc.ClientSecretRef.Namespace,
	}, &secret); err != nil {
		return "", fmt.Errorf("failed to get client secret: %w", err)
	}

	key := oidc.ClientSecretRef.Key
	if key == "" {
		key = "value"
	}

	secretData, ok := secret.Data[key]
	if !ok {
		return "", fmt.Errorf("secret %s/%s missing key %s", oidc.ClientSecretRef.Namespace, oidc.ClientSecretRef.Name, key)
	}

	return string(secretData), nil
}

// createOIDCHTTPClient creates an HTTP client for OIDC requests with appropriate TLS config.
// It supports:
// 1. InsecureSkipTLSVerify - skip all TLS verification (not recommended)
// 2. Explicit CertificateAuthority - use provided CA
// 3. TOFU (Trust On First Use) - auto-discover and cache CA on first connection to the issuer
func (p *OIDCTokenProvider) createOIDCHTTPClient(oidc *v1alpha1.OIDCAuthConfig) (*http.Client, error) {
	cacheKey := p.oidcHTTPClientCacheKey(oidc)
	p.httpMu.RLock()
	if client := p.httpClients[cacheKey]; client != nil {
		p.httpMu.RUnlock()
		return client, nil
	}
	p.httpMu.RUnlock()

	transport := &http.Transport{}

	if oidc.InsecureSkipTLSVerify {
		transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true} //nolint:gosec // User explicitly requested insecure
	} else if oidc.CertificateAuthority != "" {
		roots := x509.NewCertPool()
		if ok := roots.AppendCertsFromPEM([]byte(oidc.CertificateAuthority)); !ok {
			return nil, fmt.Errorf("failed to parse certificateAuthority")
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: roots}
	} else if oidc.AllowTOFU {
		// Check if we have a cached TOFU CA for this issuer
		issuerKey := oidc.IssuerURL
		p.issuerTOFUMu.RLock()
		cachedCA, hasCachedCA := p.issuerTOFUCAs[issuerKey]
		p.issuerTOFUMu.RUnlock()

		if hasCachedCA {
			roots := x509.NewCertPool()
			if ok := roots.AppendCertsFromPEM(cachedCA); ok {
				transport.TLSClientConfig = &tls.Config{RootCAs: roots}
				p.log.Debugw("Using cached TOFU CA for OIDC issuer", "issuer", issuerKey)
			}
		} else {
			// Perform TOFU for the OIDC issuer with a short timeout to avoid blocking requests
			tofuCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			ca, err := p.performTOFU(tofuCtx, oidc.IssuerURL)
			cancel()
			if err != nil {
				return nil, fmt.Errorf("TOFU failed for OIDC issuer %s: %w", issuerKey, err)
			}
			// Cache the CA
			p.issuerTOFUMu.Lock()
			p.issuerTOFUCAs[issuerKey] = ca
			p.issuerTOFUMu.Unlock()

			roots := x509.NewCertPool()
			if ok := roots.AppendCertsFromPEM(ca); ok {
				transport.TLSClientConfig = &tls.Config{RootCAs: roots}
				p.log.Infow("TOFU: captured and cached OIDC issuer CA", "issuer", issuerKey)
			}
		}
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   30 * time.Second,
	}
	if cacheKey != "" {
		p.httpMu.Lock()
		p.httpClients[cacheKey] = client
		p.httpMu.Unlock()
	}
	return client, nil
}

// configureTLS configures TLS for the cluster API server connection.
// It supports:
// 1. Explicit CA from caSecretRef
// 2. TOFU (Trust On First Use) - auto-discover and cache CA on first connection
// 3. Insecure skip verify (not recommended)
func (p *OIDCTokenProvider) configureTLS(ctx context.Context, cfg *rest.Config, oidc *v1alpha1.OIDCAuthConfig) error {
	clusterName := oidc.Server // Use API server URL as key for TOFU cache

	// 0. Handle insecure skip verify first
	if oidc.InsecureSkipTLSVerify {
		cfg.TLSClientConfig.Insecure = true
		p.log.Warnw("InsecureSkipTLSVerify enabled for cluster connection - NOT recommended for production",
			"cluster", clusterName)
		return nil
	}

	// 1. Check for explicit CA in secret
	if oidc.CASecretRef != nil {
		var secret corev1.Secret
		if err := p.k8s.Get(ctx, types.NamespacedName{
			Name:      oidc.CASecretRef.Name,
			Namespace: oidc.CASecretRef.Namespace,
		}, &secret); err != nil {
			if !apierrors.IsNotFound(err) {
				return fmt.Errorf("failed to get cluster CA secret: %w", err)
			}
			// Secret doesn't exist yet, will try TOFU
			p.log.Debugw("CA secret not found, will attempt TOFU", "cluster", clusterName)
		} else {
			key := oidc.CASecretRef.Key
			if key == "" {
				key = "value"
			}
			if ca, ok := secret.Data[key]; ok && len(ca) > 0 {
				cfg.TLSClientConfig.CAData = ca
				p.log.Debugw("Loaded cluster CA from secret", "cluster", clusterName,
					"secret", fmt.Sprintf("%s/%s", oidc.CASecretRef.Namespace, oidc.CASecretRef.Name), "key", key)
				return nil
			}
			p.log.Warnw("Cluster CA secret key missing or empty; will attempt TOFU", "cluster", clusterName,
				"secret", fmt.Sprintf("%s/%s", oidc.CASecretRef.Namespace, oidc.CASecretRef.Name), "key", key)
		}
	}

	if !oidc.AllowTOFU {
		// No explicit CA and TOFU disabled: rely on system trust store
		p.log.Debugw("No CA configured and TOFU disabled; using system trust store", "cluster", clusterName)
		return nil
	}

	// 2. Check TOFU cache
	p.tofuMu.RLock()
	cachedCA, hasCachedCA := p.tofuCAs[clusterName]
	p.tofuMu.RUnlock()

	if hasCachedCA {
		cfg.TLSClientConfig.CAData = cachedCA
		p.log.Debugw("Using cached TOFU CA for cluster", "cluster", clusterName)
		return nil
	}

	// 3. Perform TOFU - connect to API server and capture the CA certificate
	ca, err := p.performTOFU(ctx, oidc.Server)
	if err != nil {
		return fmt.Errorf("TOFU failed for cluster %s: %w", clusterName, err)
	}

	// Cache the CA
	p.tofuMu.Lock()
	p.tofuCAs[clusterName] = ca
	p.tofuMu.Unlock()

	// Set the CA for this connection
	cfg.TLSClientConfig.CAData = ca
	p.log.Infow("TOFU: captured CA for cluster", "cluster", clusterName)

	// If CASecretRef is configured, persist the discovered CA
	if oidc.CASecretRef != nil {
		if err := p.persistTOFUCA(ctx, oidc.CASecretRef, ca); err != nil {
			p.log.Warnw("Failed to persist TOFU CA to secret", "cluster", clusterName, "error", err)
		} else {
			p.log.Infow("Persisted TOFU CA to secret", "cluster", clusterName,
				"secret", fmt.Sprintf("%s/%s", oidc.CASecretRef.Namespace, oidc.CASecretRef.Name))
		}
	}

	return nil
}

func (p *OIDCTokenProvider) oidcHTTPClientCacheKey(oidc *v1alpha1.OIDCAuthConfig) string {
	if oidc == nil {
		return ""
	}
	var caHash string
	if oidc.CertificateAuthority != "" {
		sum := sha256.Sum256([]byte(oidc.CertificateAuthority))
		caHash = hex.EncodeToString(sum[:])
	}
	return fmt.Sprintf("%s|ca=%s|insecure=%t|tofu=%t", oidc.IssuerURL, caHash, oidc.InsecureSkipTLSVerify, oidc.AllowTOFU)
}

// performTOFU performs Trust On First Use for the API server certificate.
// It connects to the server, captures the presented certificate chain, and returns the CA.
//
// Security Note - InsecureSkipVerify usage:
// This function intentionally uses InsecureSkipVerify=true for Trust On First Use (TOFU).
// This is REQUIRED because:
//  1. TOFU by definition connects to a server whose CA is not yet trusted
//  2. Go's standard TLS verification would reject the connection before we can capture the CA
//  3. We mitigate the risk by: (a) verifying hostname matches the certificate,
//     (b) logging the certificate fingerprint for audit, (c) persisting the CA for all future
//     connections which then use full TLS verification
//  4. This pattern is standard for TOFU implementations (similar to SSH's known_hosts)
//  5. After first use, the captured CA is stored and all subsequent connections are fully verified
//
// codeql[go/disabled-certificate-check]: Intentional for TOFU - see above security note
func (p *OIDCTokenProvider) performTOFU(ctx context.Context, apiServerURL string) ([]byte, error) {
	u, err := url.Parse(apiServerURL)
	if err != nil {
		return nil, fmt.Errorf("invalid API server URL: %w", err)
	}

	host := u.Host
	if u.Port() == "" {
		host = u.Host + ":443"
	}

	var caPEM []byte
	hostname := u.Hostname()
	tlsConfig := &tls.Config{
		ServerName:         hostname,
		InsecureSkipVerify: true, //nolint:gosec // TOFU requires accepting untrusted certs on first connection
		VerifyConnection: func(cs tls.ConnectionState) error {
			// Even though we skip chain verification (required for TOFU),
			// we still verify the hostname matches the certificate to prevent
			// connecting to the wrong server.
			if len(cs.PeerCertificates) == 0 {
				return fmt.Errorf("no certificates presented by API server")
			}

			leaf := cs.PeerCertificates[0]

			// Verify hostname matches the certificate's DNS names or IP addresses
			if err := leaf.VerifyHostname(hostname); err != nil {
				return fmt.Errorf("TOFU hostname verification failed: %w", err)
			}

			// Find the root CA (last cert in chain) or self-signed cert
			var caCert *x509.Certificate
			for i := len(cs.PeerCertificates) - 1; i >= 0; i-- {
				cert := cs.PeerCertificates[i]
				// Check if it's a CA or self-signed
				if cert.IsCA || cert.Subject.String() == cert.Issuer.String() {
					caCert = cert
					break
				}
			}

			// If no CA found in chain, use the leaf certificate (self-signed scenario)
			if caCert == nil {
				caCert = leaf
			}

			// Encode to PEM and store for return
			caPEM = pem.EncodeToMemory(&pem.Block{
				Type:  "CERTIFICATE",
				Bytes: caCert.Raw,
			})

			// Log fingerprint for security awareness
			fingerprint := sha256.Sum256(caCert.Raw)
			p.log.Infow("TOFU: Trusting API server certificate",
				"apiServer", apiServerURL,
				"subject", caCert.Subject.String(),
				"issuer", caCert.Issuer.String(),
				"fingerprint", hex.EncodeToString(fingerprint[:]),
				"notBefore", caCert.NotBefore,
				"notAfter", caCert.NotAfter,
			)

			return nil
		},
	}

	// Create a dialer that respects the context
	dialer := &net.Dialer{Timeout: 10 * time.Second}

	// Connect with custom verification callback, respecting the context
	netConn, err := dialer.DialContext(ctx, "tcp", host)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to API server for TOFU: %w", err)
	}

	// Upgrade to TLS
	conn := tls.Client(netConn, tlsConfig)
	defer func() { _ = conn.Close() }()

	// Perform the TLS handshake with context deadline
	if deadline, ok := ctx.Deadline(); ok {
		if err := conn.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("failed to set connection deadline: %w", err)
		}
	}
	if err := conn.Handshake(); err != nil {
		return nil, fmt.Errorf("TLS handshake failed for TOFU: %w", err)
	}

	if len(caPEM) == 0 {
		return nil, fmt.Errorf("failed to capture CA certificate during TOFU")
	}

	return caPEM, nil
}

// persistTOFUCA saves the discovered CA certificate to the referenced secret
func (p *OIDCTokenProvider) persistTOFUCA(ctx context.Context, secretRef *v1alpha1.SecretKeyReference, caPEM []byte) error {
	key := secretRef.Key
	if key == "" {
		key = "ca.crt"
	}

	// Try to get existing secret
	var secret corev1.Secret
	err := p.k8s.Get(ctx, types.NamespacedName{
		Name:      secretRef.Name,
		Namespace: secretRef.Namespace,
	}, &secret)

	if apierrors.IsNotFound(err) {
		// Create new secret
		secret = corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      secretRef.Name,
				Namespace: secretRef.Namespace,
				Labels: map[string]string{
					"app.kubernetes.io/managed-by":          "breakglass",
					"breakglass.t-caas.telekom.com/tofu-ca": "true",
				},
				Annotations: map[string]string{
					"breakglass.t-caas.telekom.com/tofu-timestamp": time.Now().UTC().Format(time.RFC3339),
				},
			},
			Type: corev1.SecretTypeOpaque,
			Data: map[string][]byte{
				key: caPEM,
			},
		}
		return p.k8s.Create(ctx, &secret)
	} else if err != nil {
		return fmt.Errorf("failed to get existing secret: %w", err)
	}

	// Update existing secret
	if secret.Data == nil {
		secret.Data = make(map[string][]byte)
	}
	secret.Data[key] = caPEM

	if secret.Annotations == nil {
		secret.Annotations = make(map[string]string)
	}
	secret.Annotations["breakglass.t-caas.telekom.com/tofu-timestamp"] = time.Now().UTC().Format(time.RFC3339)

	secret.TypeMeta = metav1.TypeMeta{
		APIVersion: corev1.SchemeGroupVersion.String(),
		Kind:       "Secret",
	}
	return utils.ApplyObject(ctx, p.k8s, &secret)
}

// InvalidateTOFU removes a cached TOFU CA for the specified cluster
func (p *OIDCTokenProvider) InvalidateTOFU(apiServerURL string) {
	p.tofuMu.Lock()
	delete(p.tofuCAs, apiServerURL)
	p.tofuMu.Unlock()
}

// Invalidate removes a cached token for the specified namespace/cluster combination.
// Callers must provide the namespace to avoid cross-namespace collisions.
func (p *OIDCTokenProvider) Invalidate(namespace, clusterName string) {
	cacheKey := tokenCacheKey(namespace, clusterName)
	p.mu.Lock()
	delete(p.tokens, cacheKey)
	p.mu.Unlock()
}

// InvalidateAll removes all cached tokens
func (p *OIDCTokenProvider) InvalidateAll() {
	p.mu.Lock()
	p.tokens = make(map[string]*cachedToken)
	p.mu.Unlock()
}
