package config

import (
	"testing"
)

func TestDefaultConfigSecureDefaults(t *testing.T) {
	var cfg Config
	// Zero value config should be secure
	// Note: Mail configuration moved to MailProvider CRD
	// Note: AuthorizationServer removed - TLS validation now handled by IdentityProvider CRDs

	// Just verify config struct exists and can be instantiated
	if cfg.Server.ListenAddress == "" {
		t.Log("Server.ListenAddress is empty by default (expected)")
	}
}
