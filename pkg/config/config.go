package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

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
}

type Kubernetes struct {
	Context      string   `yaml:"context"`
	OIDCPrefixes []string `yaml:"oidcPrefixes"`
	// ClusterConfigCheckInterval controls how often ClusterConfig resources are validated (e.g. "10m").
	// +optional
	ClusterConfigCheckInterval string `yaml:"clusterConfigCheckInterval"`
}

type Config struct {
	Server     Server
	Frontend   Frontend
	Kubernetes Kubernetes
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
		return config, fmt.Errorf("trying to open breakglass config file %s: %v", configPath, err)
	}

	err = yaml.Unmarshal(content, &config)
	if err != nil {
		return config, fmt.Errorf("error unmarshaling YAML %s: %v", configPath, err)
	}
	return config, nil
}
