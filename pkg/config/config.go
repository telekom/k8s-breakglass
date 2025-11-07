package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

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
	OIDCAuthority string `yaml:"oidcAuthority"`
	OIDCClientID  string `yaml:"oidcClientID"`
	BaseURL       string `yaml:"baseURL"`
	// BrandingName optionally overrides the UI product name shown in the frontend
	// e.g. "Das SCHIFF Breakglass". If empty, the frontend may use a hardcoded
	// default or its own placeholder.
	BrandingName string `yaml:"brandingName"`
	// UIFlavour optionally specifies the UI theme/flavour at runtime (e.g. "telekom", "oss", "neutral").
	// If empty, defaults to "oss". This allows the UI appearance to be configured server-side
	// without requiring a rebuild.
	UIFlavour string `yaml:"uiFlavour"`
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

// Keycloak holds optional configuration for read-only group membership sync.
// Only minimal (view) permissions should be granted to the configured client.
type Keycloak struct {
	// BaseURL of the Keycloak server, e.g. https://keycloak.example.com
	BaseURL string `yaml:"baseURL"`
	// Realm to query, e.g. master or custom realm name
	Realm string `yaml:"realm"`
	// ClientID used for client_credentials flow (should have view-users/view-groups only)
	ClientID string `yaml:"clientID"`
	// ClientSecret for the above client (omit if using public client w/ other flow)
	ClientSecret string `yaml:"clientSecret"`
	// CacheTTL duration string (e.g. 5m, 1h); default 10m if empty
	CacheTTL string `yaml:"cacheTTL"`
	// RequestTimeout duration string (default 10s)
	RequestTimeout string `yaml:"requestTimeout"`
	// Disable set to true to turn off sync even if values present
	Disable bool `yaml:"disable"`
}

type Config struct {
	Server              Server
	AuthorizationServer AuthorizationServer `yaml:"authorizationServer"`
	Mail                Mail
	Frontend            Frontend
	Kubernetes          Kubernetes
	Keycloak            Keycloak
}

func Load() (Config, error) {
	var config Config

	configPath := os.Getenv("BREAKGLASS_CONFIG_PATH")
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
