package config

import (
	"fmt"
	"os"

	"github.com/google/go-cmp/cmp"
	"gopkg.in/yaml.v2"
)

type Transition struct {
	From                     string   `yaml:"from" json:"from"`
	To                       string   `yaml:"to" json:"to"`
	Duration                 int64    `yaml:"duration" json:"duration"`
	SelfApproval             bool     `yaml:"selfApproval" json:"selfApproval"`
	ApprovalGroups           []string `yaml:"approvalGroups" json:"approvalGroups"`
	GlobalBreakglassExcluded bool     `yaml:"globalBreakglassExcluded" json:"-"`
}

type Keycloak struct {
	Url          string
	ClientID     string `yaml:"clientID"`
	ClientSecret string `yaml:"clientSecret"`
	LoginRealm   string
	ManagedRealm string
}

type Frontend struct {
	OIDCAuthority string `yaml:"oidcAuthority"`
	OIDCClientID  string `yaml:"oidcClientID"`
}

type JWT struct {
	JWTPrivateKey string
	JWTPublicKey  string
	Expiry        int64
	Issuer        string
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

type ClusterAccess struct {
	FrontendPage  string   `yaml:"frontentPage"`
	ClusterGroups []string `yaml:"clusterGroups"`
}

type Config struct {
	Server                 Server
	PossibleTransitions    []Transition
	GlobalBreakglassGroups []string `yaml:"globalBreakglassGroups"`
	Keycloak               Keycloak
	BreakglassJWT          JWT
	Mail                   Mail
	Frontend               Frontend
	ClusterAccess          ClusterAccess
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

func (c *Config) Defaults() {
	if c.ClusterAccess.FrontendPage == "" {
		c.ClusterAccess.FrontendPage = "http://localhost:5173/"
	}
}

func (a Transition) Equal(b Transition) bool {
	if a.From != b.From {
		return false
	}
	if a.To != b.To {
		return false
	}
	if a.Duration != b.Duration {
		return false
	}
	if a.SelfApproval != b.SelfApproval {
		return false
	}
	if !cmp.Equal(a.ApprovalGroups, b.ApprovalGroups) {
		return false
	}
	return true
}
