package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v2"
)

const (
	VersionV1 = "v1"
)

type Config struct {
	Version        string         `yaml:"version"`
	CurrentContext string         `yaml:"current-context,omitempty"`
	OIDCProviders  []OIDCProvider `yaml:"oidc-providers,omitempty"`
	Contexts       []Context      `yaml:"contexts,omitempty"`
	Settings       Settings       `yaml:"settings,omitempty"`
}

type Settings struct {
	OutputFormat string `yaml:"output-format,omitempty"`
	Color        string `yaml:"color,omitempty"`
	PageSize     int    `yaml:"page-size,omitempty"`
}

type OIDCProvider struct {
	Name             string            `yaml:"name"`
	Authority        string            `yaml:"authority"`
	ClientID         string            `yaml:"client-id"`
	ClientSecret     string            `yaml:"client-secret,omitempty"`
	ClientSecretEnv  string            `yaml:"client-secret-env,omitempty"`
	ClientSecretFile string            `yaml:"client-secret-file,omitempty"`
	GrantType        string            `yaml:"grant-type,omitempty"`
	CAFile           string            `yaml:"ca-file,omitempty"`
	Scopes           []string          `yaml:"scopes,omitempty"`
	DeviceCodeFlow   bool              `yaml:"device-code-flow,omitempty"`
	InsecureSkipTLS  bool              `yaml:"insecure-skip-tls-verify,omitempty"`
	ExtraAuthParams  map[string]string `yaml:"extra-auth-params,omitempty"`
}

type Context struct {
	Name                  string      `yaml:"name"`
	Server                string      `yaml:"server"`
	OIDCProvider          string      `yaml:"oidc-provider,omitempty"`
	CAFile                string      `yaml:"ca-file,omitempty"`
	InsecureSkipTLSVerify bool        `yaml:"insecure-skip-tls-verify,omitempty"`
	OIDC                  *InlineOIDC `yaml:"oidc,omitempty"`
}

type InlineOIDC struct {
	Authority       string   `yaml:"authority"`
	ClientID        string   `yaml:"client-id"`
	ClientSecret    string   `yaml:"client-secret,omitempty"`
	GrantType       string   `yaml:"grant-type,omitempty"`
	Scopes          []string `yaml:"scopes,omitempty"`
	DeviceCodeFlow  bool     `yaml:"device-code-flow,omitempty"`
	CAFile          string   `yaml:"ca-file,omitempty"`
	InsecureSkipTLS bool     `yaml:"insecure-skip-tls-verify,omitempty"`
}

func DefaultConfig() Config {
	return Config{
		Version: VersionV1,
		Settings: Settings{
			OutputFormat: "table",
			Color:        "auto",
			PageSize:     50,
		},
	}
}

func Load(path string) (*Config, error) {
	if path == "" {
		return nil, errors.New("config path is required")
	}
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var cfg Config
	if err := yaml.Unmarshal(content, &cfg); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}
	if cfg.Version == "" {
		cfg.Version = VersionV1
	}
	return &cfg, nil
}

func Save(path string, cfg *Config) error {
	if cfg == nil {
		return errors.New("config is nil")
	}
	if cfg.Version == "" {
		cfg.Version = VersionV1
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return fmt.Errorf("failed to create config dir: %w", err)
	}
	content, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("failed to marshal config: %w", err)
	}
	return os.WriteFile(path, content, 0o600)
}

func (c *Config) FindContext(name string) (*Context, error) {
	for i := range c.Contexts {
		if c.Contexts[i].Name == name {
			return &c.Contexts[i], nil
		}
	}
	return nil, fmt.Errorf("context not found: %s", name)
}

func (c *Config) FindOIDCProvider(name string) (*OIDCProvider, error) {
	for i := range c.OIDCProviders {
		if c.OIDCProviders[i].Name == name {
			return &c.OIDCProviders[i], nil
		}
	}
	return nil, fmt.Errorf("oidc provider not found: %s", name)
}

func (c *Config) CurrentContextOrDefault() string {
	if c.CurrentContext != "" {
		return c.CurrentContext
	}
	if len(c.Contexts) > 0 {
		return c.Contexts[0].Name
	}
	return ""
}

type ResolvedOIDC struct {
	ProviderName     string
	Authority        string
	ClientID         string
	ClientSecret     string
	ClientSecretEnv  string
	ClientSecretFile string
	GrantType        string
	Scopes           []string
	CAFile           string
	DeviceCodeFlow   bool
	InsecureSkipTLS  bool
	ExtraAuthParams  map[string]string
}

func (c *Config) ResolveOIDC(ctx *Context) (*ResolvedOIDC, error) {
	if ctx == nil {
		return nil, errors.New("context is nil")
	}
	if ctx.OIDC != nil {
		return &ResolvedOIDC{
			Authority:       ctx.OIDC.Authority,
			ClientID:        ctx.OIDC.ClientID,
			ClientSecret:    ctx.OIDC.ClientSecret,
			GrantType:       ctx.OIDC.GrantType,
			Scopes:          ctx.OIDC.Scopes,
			CAFile:          ctx.OIDC.CAFile,
			DeviceCodeFlow:  ctx.OIDC.DeviceCodeFlow,
			InsecureSkipTLS: ctx.OIDC.InsecureSkipTLS,
		}, nil
	}
	if ctx.OIDCProvider == "" {
		return nil, errors.New("no oidc provider configured")
	}
	provider, err := c.FindOIDCProvider(ctx.OIDCProvider)
	if err != nil {
		return nil, err
	}
	return &ResolvedOIDC{
		ProviderName:     provider.Name,
		Authority:        provider.Authority,
		ClientID:         provider.ClientID,
		ClientSecret:     provider.ClientSecret,
		ClientSecretEnv:  provider.ClientSecretEnv,
		ClientSecretFile: provider.ClientSecretFile,
		GrantType:        provider.GrantType,
		Scopes:           provider.Scopes,
		CAFile:           provider.CAFile,
		DeviceCodeFlow:   provider.DeviceCodeFlow,
		InsecureSkipTLS:  provider.InsecureSkipTLS,
		ExtraAuthParams:  provider.ExtraAuthParams,
	}, nil
}

func (c *Config) Validate() error {
	if c.Version == "" {
		return errors.New("config version missing")
	}
	for _, ctx := range c.Contexts {
		if strings.TrimSpace(ctx.Name) == "" {
			return errors.New("context name cannot be empty")
		}
		if strings.TrimSpace(ctx.Server) == "" {
			return fmt.Errorf("context %s server is required", ctx.Name)
		}
	}
	return nil
}
