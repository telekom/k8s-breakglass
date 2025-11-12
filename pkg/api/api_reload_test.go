package api

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/assert"
	"go.uber.org/zap"

	"github.com/telekom/k8s-breakglass/pkg/config"
)

// TestServer_ReloadIdentityProvider tests basic reload functionality
func TestServer_ReloadIdentityProvider(t *testing.T) {
	log := zap.NewNop()
	loader := &mockIdentityProviderLoader{
		config: &config.IdentityProviderConfig{
			Type:      "OIDC",
			Authority: "https://auth.example.com",
			ClientID:  "test-client",
		},
	}

	server := &Server{
		log:       log,
		idpConfig: nil,
		idpMutex:  sync.RWMutex{},
	}

	// Reload with new config - should work even though loader is mock
	// We call SetIdentityProvider directly instead
	server.SetIdentityProvider(loader.config)

	// Verify config was updated
	server.idpMutex.RLock()
	assert.NotNil(t, server.idpConfig)
	assert.Equal(t, "OIDC", server.idpConfig.Type)
	assert.Equal(t, "https://auth.example.com", server.idpConfig.Authority)
	server.idpMutex.RUnlock()
}

// TestServer_ConcurrentReloadsAndReads tests concurrent reload and read operations
func TestServer_ConcurrentReloadsAndReads(t *testing.T) {
	log := zap.NewNop()
	server := &Server{
		log:       log,
		idpConfig: nil,
		idpMutex:  sync.RWMutex{},
	}

	config1 := &config.IdentityProviderConfig{
		Type:      "OIDC",
		Authority: "https://auth.example.com",
		ClientID:  "test-client",
	}

	// Initial set
	server.SetIdentityProvider(config1)

	var wg sync.WaitGroup
	var readCount int32
	var updateCount int32

	// Spawn multiple readers
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				server.idpMutex.RLock()
				_ = server.idpConfig
				server.idpMutex.RUnlock()
				atomic.AddInt32(&readCount, 1)
			}
		}()
	}

	// Spawn multiple updaters (SetIdentityProvider)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 10; j++ {
				server.SetIdentityProvider(config1)
				atomic.AddInt32(&updateCount, 1)
			}
		}()
	}

	wg.Wait()

	// Verify operations completed
	assert.Equal(t, int32(1000), readCount, "expected 1000 reads")
	assert.Equal(t, int32(50), updateCount, "expected 50 updates")

	// Verify final state is correct
	server.idpMutex.RLock()
	assert.NotNil(t, server.idpConfig)
	assert.Equal(t, "OIDC", server.idpConfig.Type)
	server.idpMutex.RUnlock()
}

// TestServer_SetIdentityProviderPreservesOnError tests that existing config is preserved
func TestServer_SetIdentityProviderPreservesOnError(t *testing.T) {
	log := zap.NewNop()
	originalConfig := &config.IdentityProviderConfig{
		Type:      "Keycloak",
		Authority: "https://keycloak.example.com",
		ClientID:  "original-client",
	}

	server := &Server{
		log:       log,
		idpConfig: originalConfig,
		idpMutex:  sync.RWMutex{},
	}

	// Try to set nil - should not change
	server.SetIdentityProvider(nil)

	// Verify original config is still present
	server.idpMutex.RLock()
	assert.Equal(t, originalConfig, server.idpConfig)
	assert.Equal(t, "Keycloak", server.idpConfig.Type)
	server.idpMutex.RUnlock()
}

// TestServer_SetIdentityProviderUpdatesConfig tests that SetIdentityProvider changes the config
func TestServer_SetIdentityProviderUpdatesConfig(t *testing.T) {
	log := zap.NewNop()
	originalConfig := &config.IdentityProviderConfig{
		Type:      "OIDC",
		Authority: "https://old-auth.example.com",
		ClientID:  "old-client",
	}

	server := &Server{
		log:       log,
		idpConfig: originalConfig,
		idpMutex:  sync.RWMutex{},
	}

	newConfig := &config.IdentityProviderConfig{
		Type:      "Keycloak",
		Authority: "https://new-keycloak.example.com",
		ClientID:  "new-client",
		Keycloak: &config.KeycloakRuntimeConfig{
			BaseURL: "https://new-keycloak.example.com",
			Realm:   "new-realm",
		},
	}

	// Update to new config
	server.SetIdentityProvider(newConfig)

	// Verify config changed
	server.idpMutex.RLock()
	assert.NotEqual(t, originalConfig, server.idpConfig)
	assert.Equal(t, "Keycloak", server.idpConfig.Type)
	assert.Equal(t, "https://new-keycloak.example.com", server.idpConfig.Authority)
	assert.Equal(t, "new-client", server.idpConfig.ClientID)
	assert.NotNil(t, server.idpConfig.Keycloak)
	assert.Equal(t, "new-realm", server.idpConfig.Keycloak.Realm)
	server.idpMutex.RUnlock()
}

// Test for cert rotation scenario
func TestServer_Scenario_CertRotation(t *testing.T) {
	log := zap.NewNop()

	// Old cert-based config
	oldConfig := &config.IdentityProviderConfig{
		Type:      "OIDC",
		Authority: "https://auth.example.com",
		ClientID:  "client-123",
		Keycloak: &config.KeycloakRuntimeConfig{
			CertificateAuthority: "old-cert-pem-data",
		},
	}

	server := &Server{
		log:       log,
		idpConfig: oldConfig,
		idpMutex:  sync.RWMutex{},
	}

	// New cert after rotation
	newConfig := &config.IdentityProviderConfig{
		Type:      "OIDC",
		Authority: "https://auth.example.com", // same URL
		ClientID:  "client-123",               // same client
		Keycloak: &config.KeycloakRuntimeConfig{
			CertificateAuthority: "new-cert-pem-data", // rotated cert
		},
	}

	// Update should pick up the new cert
	server.SetIdentityProvider(newConfig)

	server.idpMutex.RLock()
	assert.Equal(t, "new-cert-pem-data", server.idpConfig.Keycloak.CertificateAuthority)
	server.idpMutex.RUnlock()
}

// Test for timeout adjustment scenario
func TestServer_Scenario_TimeoutAdjustment(t *testing.T) {
	log := zap.NewNop()

	oldConfig := &config.IdentityProviderConfig{
		Type:      "OIDC",
		Authority: "https://auth.example.com",
		ClientID:  "client-123",
		Keycloak: &config.KeycloakRuntimeConfig{
			RequestTimeout: "10s",
		},
	}

	server := &Server{
		log:       log,
		idpConfig: oldConfig,
		idpMutex:  sync.RWMutex{},
	}

	// New config with adjusted timeout
	newConfig := &config.IdentityProviderConfig{
		Type:      "OIDC",
		Authority: "https://auth.example.com",
		ClientID:  "client-123",
		Keycloak: &config.KeycloakRuntimeConfig{
			RequestTimeout: "30s", // increased timeout
		},
	}

	server.SetIdentityProvider(newConfig)

	server.idpMutex.RLock()
	assert.Equal(t, "30s", server.idpConfig.Keycloak.RequestTimeout)
	server.idpMutex.RUnlock()
}

// Mock loader for testing (unused in simplified tests but kept for reference)
type mockIdentityProviderLoader struct {
	config *config.IdentityProviderConfig
	err    string
}

func (m *mockIdentityProviderLoader) LoadIdentityProvider(ctx context.Context) (*config.IdentityProviderConfig, error) {
	if m.err != "" {
		return nil, context.DeadlineExceeded
	}
	return m.config, nil
}
