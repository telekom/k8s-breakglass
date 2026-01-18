package config

import (
	"os"
	"path/filepath"
)

const (
	defaultConfigDirName = "bgctl"
	defaultConfigFile    = "config.yaml"
	defaultTokenFile     = "tokens.json"
)

func DefaultConfigPath() string {
	if env := os.Getenv("BGCTL_CONFIG"); env != "" {
		return env
	}
	base, err := os.UserConfigDir()
	if err == nil {
		return filepath.Join(base, defaultConfigDirName, defaultConfigFile)
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".bgctl", defaultConfigFile)
}

func DefaultTokenPath() string {
	base, err := os.UserConfigDir()
	if err == nil {
		return filepath.Join(base, defaultConfigDirName, defaultTokenFile)
	}
	home, _ := os.UserHomeDir()
	return filepath.Join(home, ".bgctl", defaultTokenFile)
}
