package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

// IdentityProviderConfig represents the runtime identity provider configuration
// loaded from IdentityProvider CRD resources
type IdentityProviderConfig struct {
	// Type is the provider type (OIDC, Keycloak, LDAP, AzureAD)
	Type string

	// Authority/URL for OIDC and other endpoint-based providers
	Authority string

	// ClientID for OIDC and Keycloak
	ClientID string

	// ClientSecret for Keycloak (loaded from secret reference)
	ClientSecret string

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

type AuthorizationServer struct {
	URL          string `yaml:"url"`
	JWKSEndpoint string `yaml:"jwksEndpoint"`
	// InsecureSkipVerify allows opting into skipping TLS verification for the
	// authorization server. This must be explicitly enabled in non-production
	// setups. Default is false.
	InsecureSkipVerify bool `yaml:"insecureSkipVerify"`
	// CertificateAuthority contains a PEM encoded CA certificate to validate the
	// TLS certificate presented by the authorization server (optional).
	CertificateAuthority string `yaml:"certificateAuthority"`
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

	// IdentityProviderName is the name of the IdentityProvider CR to use for frontend config
	// This is REQUIRED and must reference a valid IdentityProvider resource
	// Example: "production-idp"
	IdentityProviderName string `yaml:"identityProviderName"`
}

type Mail struct {
	Host               string
	Port               int
	User               string
	Password           string
	InsecureSkipVerify bool `yaml:"insecureSkipVerify"`
	// SenderAddress is the email address used in the From header for outgoing mails.
	// Example: noreply@example.com
	SenderAddress string `yaml:"senderAddress"`
	// SenderName is the display name used in the From header for outgoing mails.
	// If empty, the application will fall back to the frontend branding name or a generic placeholder.
	SenderName string `yaml:"senderName"`
	// RetryCount is the number of times to retry failed mail sends (default: 5 for conservative backoff)
	RetryCount int `yaml:"retryCount"`
	// RetryBackoffMs is the initial backoff duration in milliseconds for exponential backoff (default: 10000 = 10s)
	RetryBackoffMs int `yaml:"retryBackoffMs"`
	// QueueSize is the maximum number of pending emails in the queue (default: 1000)
	QueueSize int `yaml:"queueSize"`
}

type Server struct {
	ListenAddress string `yaml:"listenAddress"`
	TLSCertFile   string `yaml:"tlsCertFile"`
	TLSKeyFile    string `yaml:"tlsKeyFile"`
}

type Kubernetes struct {
	Context      string   `yaml:"context"`
	OIDCPrefixes []string `yaml:"oidcPrefixes"`
	// ClusterConfigCheckInterval controls how often ClusterConfig resources are validated (e.g. "10m").
	// +optional
	ClusterConfigCheckInterval string `yaml:"clusterConfigCheckInterval"`
}

type Config struct {
	Server              Server
	AuthorizationServer AuthorizationServer `yaml:"authorizationServer"`
	Mail                Mail
	Frontend            Frontend
	Kubernetes          Kubernetes
}

func Load() (Config, error) {
	return LoadWithPath("")
}

// LoadWithPath loads the config from the specified path (empty string defaults to ./config.yaml)
func LoadWithPath(configPath string) (Config, error) {
	var config Config

	if len(configPath) == 0 {
		configPath = "./config.yaml"
	}

	content, err := os.ReadFile(configPath)
	if err != nil {
		return config, fmt.Errorf("trying to open breakglass config file %s: %v", configPath, err)
	}

	err = yaml.Unmarshal(content, &config)
	if err != nil {
		return config, fmt.Errorf("error unmarshaling YAML %s: %v", configPath, err)
	}
	return config, nil
}
