package config

import (
	"fmt"
	"os"

	"gopkg.in/yaml.v2"
)

type AuthorizationServer struct {
	URL          string `yaml:"url"`
	JWKSEndpoint string `yaml:"jwksEndpoint"`
}

type Frontend struct {
	OIDCAuthority string `yaml:"oidcAuthority"`
	OIDCClientID  string `yaml:"oidcClientID"`
	BaseURL       string `yaml:"baseURL"`
}

type Mail struct {
	Host               string
	Port               int
	User               string
	Password           string
	InsecureSkipVerify bool `yaml:"insecureSkipVerify"`
}

type Server struct {
	ListenAddress string `yaml:"listenAddress"`
	TLSCertFile   string `yaml:"tlsCertFile"`
	TLSKeyFile    string `yaml:"tlsKeyFile"`
	BaseURL       string `yaml:"baseURL"`
}

type Kubernetes struct {
	Context string `yaml:"context"`
}

type Config struct {
	Server              Server
	AuthorizationServer AuthorizationServer `yaml:"authorizationServer"`
	Mail                Mail
	Frontend            Frontend
	Kubernetes          Kubernetes
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
