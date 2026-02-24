package config

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"gopkg.in/yaml.v2"
)

// CachedLoader provides thread-safe cached access to config with automatic reload on file change.
// This avoids reading the config file from disk on every request.
type CachedLoader struct {
	path        string
	mu          sync.RWMutex
	config      Config
	lastModTime time.Time
	lastCheck   time.Time
	checkEvery  time.Duration // how often to stat the file (default: 5s)
}

// NewCachedLoader creates a new cached config loader for the given path.
// The loader will check for file modifications at most once per checkInterval.
func NewCachedLoader(path string, checkInterval time.Duration) *CachedLoader {
	if checkInterval <= 0 {
		checkInterval = 5 * time.Second
	}
	return &CachedLoader{
		path:       path,
		checkEvery: checkInterval,
	}
}

// Get returns the cached config, reloading from disk only if the file has been modified.
// This is safe for concurrent use.
func (cl *CachedLoader) Get() (Config, error) {
	cl.mu.RLock()
	// Fast path: if we checked recently, return cached config
	if time.Since(cl.lastCheck) < cl.checkEvery && !cl.lastModTime.IsZero() {
		cfg := cl.config
		cl.mu.RUnlock()
		return cfg, nil
	}
	cl.mu.RUnlock()

	// Slow path: check if file was modified
	cl.mu.Lock()
	defer cl.mu.Unlock()

	// Double-check after acquiring write lock
	if time.Since(cl.lastCheck) < cl.checkEvery && !cl.lastModTime.IsZero() {
		return cl.config, nil
	}

	// Stat the file to check modification time
	info, err := os.Stat(cl.path)
	if err != nil {
		// If file doesn't exist but we have a cached config, return it
		if !cl.lastModTime.IsZero() {
			cl.lastCheck = time.Now()
			return cl.config, nil
		}
		return Config{}, fmt.Errorf("config file stat error: %w", err)
	}

	cl.lastCheck = time.Now()

	// If file hasn't changed, return cached config
	if info.ModTime().Equal(cl.lastModTime) {
		return cl.config, nil
	}

	// File changed, reload
	cfg, err := Load(cl.path)
	if err != nil {
		// On error, keep returning old config if we have one
		if !cl.lastModTime.IsZero() {
			return cl.config, nil
		}
		return Config{}, err
	}

	cl.config = cfg
	cl.lastModTime = info.ModTime()
	return cl.config, nil
}

// IdentityProviderConfig represents the runtime identity provider configuration
// loaded from IdentityProvider CRD resources
type IdentityProviderConfig struct {
	// Name is the name of the IdentityProvider CRD resource (metadata.name)
	// Used to reference this IDP in ClusterConfig and BreakglassEscalation specs
	Name string

	// Issuer is the OIDC issuer URL (must match the 'iss' claim in JWT tokens)
	// Used to identify which IDP authenticated a user based on their JWT
	Issuer string

	// Type is the provider type (OIDC, Keycloak, LDAP, AzureAD)
	Type string

	// Authority/URL for OIDC and other endpoint-based providers
	Authority string

	// ClientID for OIDC and Keycloak
	ClientID string

	// ClientSecret for Keycloak (loaded from secret reference)
	ClientSecret string

	// CertificateAuthority contains a PEM encoded CA certificate for TLS validation
	// Loaded from spec.oidc.certificateAuthority
	CertificateAuthority string

	// InsecureSkipVerify allows skipping TLS verification for OIDC authority (testing only)
	InsecureSkipVerify bool

	// Other provider-specific fields (BaseURL for Keycloak, etc.)
	Keycloak *KeycloakRuntimeConfig

	// Raw provider config for extensibility
	RawConfig interface{}
}

// KeycloakRuntimeConfig is Keycloak-specific runtime configuration
type KeycloakRuntimeConfig struct {
	BaseURL              string
	Realm                string
	ClientID             string
	ClientSecret         string
	ServiceAccountToken  string
	CacheTTL             string
	RequestTimeout       string
	InsecureSkipVerify   bool
	CertificateAuthority string
}

type Frontend struct {
	BaseURL string `yaml:"baseURL"`
	// BrandingName optionally overrides the UI product name shown in the frontend
	// e.g. "Das SCHIFF Breakglass". If empty, the frontend may use a hardcoded
	// default or its own placeholder.
	BrandingName string `yaml:"brandingName"`
	// UIFlavour optionally specifies the UI theme/flavour at runtime (e.g. "telekom", "oss", "neutral").
	// If empty, defaults to "oss". This allows the UI appearance to be configured server-side
	// without requiring a rebuild.
	UIFlavour string `yaml:"uiFlavour"`
}

type Server struct {
	ListenAddress  string   `yaml:"listenAddress"`
	TLSCertFile    string   `yaml:"tlsCertFile"`
	TLSKeyFile     string   `yaml:"tlsKeyFile"`
	TrustedProxies []string `yaml:"trustedProxies"` // IPs/CIDRS to trust for X-Forwarded-For headers (e.g., ["10.0.0.0/8", "127.0.0.1"])
	AllowedOrigins []string `yaml:"allowedOrigins"` // Explicit list of origins permitted for credentialed browser calls
	// HardenedIDPHints when true, prevents disclosure of available identity providers in error messages.
	// Default: true (hardened) unless explicitly set to false in config.
	// +optional
	HardenedIDPHints *bool `yaml:"hardenedIDPHints"`

	// Timeouts configures HTTP server timeouts.
	// All values are Go duration strings (e.g. "30s", "2m", "1h").
	// When omitted, sensible production defaults are applied automatically.
	// +optional
	Timeouts *ServerTimeouts `yaml:"timeouts,omitempty"`

	// ShutdownTimeout controls how long the server waits for in-flight requests
	// to complete during graceful shutdown. Go duration string.
	// Default: "30s"
	// +optional
	ShutdownTimeout string `yaml:"shutdownTimeout,omitempty"`
}

// ServerTimeouts configures HTTP server timeouts.
// Zero or unset values are replaced with production defaults via the GetX() accessor methods.
type ServerTimeouts struct {
	// ReadTimeout is the maximum duration for reading the entire request, including the body.
	// Default: "30s"
	// +optional
	ReadTimeout string `yaml:"readTimeout,omitempty"`
	// ReadHeaderTimeout is the maximum duration for reading request headers.
	// Default: "10s"
	// +optional
	ReadHeaderTimeout string `yaml:"readHeaderTimeout,omitempty"`
	// WriteTimeout is the maximum duration before timing out writes of the response.
	// This covers the entire response lifetime for normal HTTP responses, including
	// streaming/SSE and long-running endpoints. Note: this does not apply after a
	// connection is hijacked (e.g. for WebSocket upgrades). For workloads that
	// require long-running responses, set this to a sufficiently large value (e.g. "24h").
	// Default: "60s"
	// +optional
	WriteTimeout string `yaml:"writeTimeout,omitempty"`
	// IdleTimeout is the maximum duration an idle (keep-alive) connection will remain open.
	// Default: "120s"
	// +optional
	IdleTimeout string `yaml:"idleTimeout,omitempty"`
	// MaxHeaderBytes controls the maximum number of bytes the server will read
	// parsing the request header's keys and values, including the request line.
	// Default: 1048576 (1 MB)
	// +optional
	MaxHeaderBytes int `yaml:"maxHeaderBytes,omitempty"`
}

const (
	// DefaultReadTimeout is the default maximum duration for reading the entire request.
	DefaultReadTimeout = 30 * time.Second
	// DefaultReadHeaderTimeout is the default maximum duration for reading request headers.
	DefaultReadHeaderTimeout = 10 * time.Second
	// DefaultWriteTimeout is the default maximum duration before timing out response writes.
	DefaultWriteTimeout = 60 * time.Second
	// DefaultIdleTimeout is the default maximum duration an idle connection remains open.
	DefaultIdleTimeout = 120 * time.Second
	// DefaultMaxHeaderBytes is the default maximum size of request headers (1 MB).
	DefaultMaxHeaderBytes = 1 << 20
	// DefaultShutdownTimeout is the default graceful shutdown timeout.
	DefaultShutdownTimeout = 30 * time.Second
)

// GetReadTimeout returns the configured read timeout or the default value.
func (t *ServerTimeouts) GetReadTimeout() time.Duration {
	if t == nil {
		return DefaultReadTimeout
	}
	return parseDurationOrDefault(t.ReadTimeout, DefaultReadTimeout)
}

// GetReadHeaderTimeout returns the configured read header timeout or the default value.
func (t *ServerTimeouts) GetReadHeaderTimeout() time.Duration {
	if t == nil {
		return DefaultReadHeaderTimeout
	}
	return parseDurationOrDefault(t.ReadHeaderTimeout, DefaultReadHeaderTimeout)
}

// GetWriteTimeout returns the configured write timeout or the default value.
func (t *ServerTimeouts) GetWriteTimeout() time.Duration {
	if t == nil {
		return DefaultWriteTimeout
	}
	return parseDurationOrDefault(t.WriteTimeout, DefaultWriteTimeout)
}

// GetIdleTimeout returns the configured idle timeout or the default value.
func (t *ServerTimeouts) GetIdleTimeout() time.Duration {
	if t == nil {
		return DefaultIdleTimeout
	}
	return parseDurationOrDefault(t.IdleTimeout, DefaultIdleTimeout)
}

// GetMaxHeaderBytes returns the configured max header bytes or the default value.
func (t *ServerTimeouts) GetMaxHeaderBytes() int {
	if t == nil {
		return DefaultMaxHeaderBytes
	}
	if t.MaxHeaderBytes > 0 {
		return t.MaxHeaderBytes
	}
	return DefaultMaxHeaderBytes
}

// GetServerTimeouts returns the server timeouts config.
// If nil, returns an empty ServerTimeouts whose getter methods apply defaults.
func (s Server) GetServerTimeouts() *ServerTimeouts {
	if s.Timeouts != nil {
		return s.Timeouts
	}
	return &ServerTimeouts{}
}

// GetShutdownTimeout returns the configured graceful shutdown timeout or the default value.
func (s Server) GetShutdownTimeout() time.Duration {
	return parseDurationOrDefault(s.ShutdownTimeout, DefaultShutdownTimeout)
}

// parseDurationOrDefault parses a Go duration string, returning the default on empty, invalid, or non-positive input.
func parseDurationOrDefault(value string, defaultVal time.Duration) time.Duration {
	value = strings.TrimSpace(value)
	if value == "" {
		return defaultVal
	}
	d, err := time.ParseDuration(value)
	if err != nil || d <= 0 {
		return defaultVal
	}
	return d
}

type Kubernetes struct {
	Context      string   `yaml:"context"`
	OIDCPrefixes []string `yaml:"oidcPrefixes"`
	// ClusterConfigCheckInterval controls how often ClusterConfig resources are validated (e.g. "10m").
	// +optional
	ClusterConfigCheckInterval string `yaml:"clusterConfigCheckInterval"`
	// UserIdentifierClaim specifies which OIDC claim to use as the user identifier for session matching.
	// This is a global default that can be overridden per-cluster in ClusterConfig.
	// Valid values: "email" (default), "preferred_username", "sub"
	// +optional
	UserIdentifierClaim string `yaml:"userIdentifierClaim"`
}

type Config struct {
	Server     Server
	Frontend   Frontend
	Kubernetes Kubernetes
}

// HardenedIDPHintsEnabled returns true when IDP hints should be hardened.
// If the setting is unset, it defaults to true to avoid IDP enumeration.
func (c Config) HardenedIDPHintsEnabled() bool {
	if c.Server.HardenedIDPHints == nil {
		return true
	}
	return *c.Server.HardenedIDPHints
}

// Load loads the breakglass configuration from a file path.
// If configPath is empty, defaults to "./config.yaml".
// The config file path can also be overridden via the BREAKGLASS_CONFIG_PATH environment variable.
func Load(configPath ...string) (Config, error) {
	var path string

	// Use provided path or fall back to default
	if len(configPath) > 0 && configPath[0] != "" {
		path = configPath[0]
	} else {
		path = "./config.yaml"
	}

	var config Config

	content, err := os.ReadFile(path)
	if err != nil {
		return config, fmt.Errorf("trying to open breakglass config file %s: %w", configPath, err)
	}

	err = yaml.Unmarshal(content, &config)
	if err != nil {
		return config, fmt.Errorf("error unmarshaling YAML %s: %w", configPath, err)
	}
	return config, nil
}

// GetUserIdentifierClaim returns the configured user identifier claim type.
// Returns UserIdentifierClaimEmail as default if not configured or if an invalid value is set.
func (c Config) GetUserIdentifierClaim() breakglassv1alpha1.UserIdentifierClaimType {
	switch c.Kubernetes.UserIdentifierClaim {
	case string(breakglassv1alpha1.UserIdentifierClaimEmail):
		return breakglassv1alpha1.UserIdentifierClaimEmail
	case string(breakglassv1alpha1.UserIdentifierClaimPreferredUsername):
		return breakglassv1alpha1.UserIdentifierClaimPreferredUsername
	case string(breakglassv1alpha1.UserIdentifierClaimSub):
		return breakglassv1alpha1.UserIdentifierClaimSub
	default:
		return breakglassv1alpha1.UserIdentifierClaimEmail
	}
}
