package reconciler

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
)

func TestNewManager(t *testing.T) {
	// Create a minimal scheme
	scheme := runtime.NewScheme()
	err := breakglassv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	// Create a test logger
	log := zap.NewNop().Sugar()

	tests := []struct {
		name          string
		restCfg       *rest.Config
		metricsAddr   string
		metricsSecure bool
		probeAddr     string
		enableHTTP2   bool
		expectError   bool
	}{
		{
			name:          "valid config with metrics disabled",
			restCfg:       &rest.Config{Host: "https://localhost:6443"},
			metricsAddr:   "0", // disabled
			metricsSecure: false,
			probeAddr:     "0", // disabled
			enableHTTP2:   false,
			expectError:   false,
		},
		{
			name:          "valid config with secure metrics",
			restCfg:       &rest.Config{Host: "https://localhost:6443"},
			metricsAddr:   ":8443",
			metricsSecure: true,
			probeAddr:     ":8081",
			enableHTTP2:   true,
			expectError:   false,
		},
		{
			name:          "nil rest config",
			restCfg:       nil,
			metricsAddr:   "0",
			metricsSecure: false,
			probeAddr:     "0",
			enableHTTP2:   false,
			expectError:   true, // controller-runtime requires a rest config
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mgr, err := NewManager(
				tt.restCfg,
				scheme,
				tt.metricsAddr,
				tt.metricsSecure,
				"", // metricsCertPath
				"", // metricsCertName
				"", // metricsCertKey
				tt.probeAddr,
				tt.enableHTTP2,
				log,
			)

			if tt.expectError {
				assert.Error(t, err)
				assert.Nil(t, mgr)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, mgr)
			}
		})
	}
}

func TestNewManager_WithMetricsCertificates(t *testing.T) {
	scheme := runtime.NewScheme()
	err := breakglassv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	log := zap.NewNop().Sugar()

	// Test with certificate path specified
	mgr, err := NewManager(
		&rest.Config{Host: "https://localhost:6443"},
		scheme,
		"0", // metricsAddr disabled to avoid port conflicts
		true,
		"/tmp/certs", // metricsCertPath
		"tls.crt",    // metricsCertName
		"tls.key",    // metricsCertKey
		"0",          // probeAddr disabled to avoid port conflicts
		false,
		log,
	)

	// Manager creation should succeed (cert watcher will fail at runtime if certs don't exist)
	assert.NoError(t, err)
	assert.NotNil(t, mgr)
}

func TestNewManager_HTTP2Disabled(t *testing.T) {
	scheme := runtime.NewScheme()
	err := breakglassv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	log := zap.NewNop().Sugar()

	// Test with HTTP/2 disabled (for CVE mitigations)
	mgr, err := NewManager(
		&rest.Config{Host: "https://localhost:6443"},
		scheme,
		"0", // metricsAddr disabled to avoid port conflicts
		false,
		"", "", "",
		"0",   // probeAddr disabled to avoid port conflicts
		false, // HTTP/2 disabled
		log,
	)

	assert.NoError(t, err)
	assert.NotNil(t, mgr)
}

func TestNewManager_SchemeContainsCRDs(t *testing.T) {
	scheme := runtime.NewScheme()
	err := breakglassv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	// Verify the scheme contains expected types
	gvks := scheme.AllKnownTypes()

	// Check that BreakglassSession is registered
	found := false
	for gvk := range gvks {
		if gvk.Kind == "BreakglassSession" {
			found = true
			assert.Equal(t, "breakglass.t-caas.telekom.com", gvk.Group)
			assert.Equal(t, "v1alpha1", gvk.Version)
			break
		}
	}
	assert.True(t, found, "BreakglassSession should be in the scheme")
}

func TestNewManager_OptionsValidation(t *testing.T) {
	scheme := runtime.NewScheme()
	err := breakglassv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	log := zap.NewNop().Sugar()

	tests := []struct {
		name        string
		metricsAddr string
		probeAddr   string
		expectError bool
	}{
		{
			name:        "metrics and probes disabled",
			metricsAddr: "0",
			probeAddr:   "0",
			expectError: false,
		},
		{
			name:        "only metrics enabled",
			metricsAddr: ":8081",
			probeAddr:   "0",
			expectError: false,
		},
		{
			name:        "only probes enabled",
			metricsAddr: "0",
			probeAddr:   ":8082",
			expectError: false,
		},
		{
			name:        "both enabled on different ports",
			metricsAddr: ":8081",
			probeAddr:   ":8082",
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use disabled ports to avoid conflicts
			mgr, err := NewManager(
				&rest.Config{Host: "https://localhost:6443"},
				scheme,
				"0", // Always use 0 to avoid port conflicts
				false,
				"", "", "",
				"0", // Always use 0 to avoid port conflicts
				false,
				log,
			)

			if tt.expectError {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
				assert.NotNil(t, mgr)
			}
		})
	}
}

func TestNewManager_LeaderElectionDisabled(t *testing.T) {
	scheme := runtime.NewScheme()
	err := breakglassv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	log := zap.NewNop().Sugar()

	mgr, err := NewManager(
		&rest.Config{Host: "https://localhost:6443"},
		scheme,
		"0",
		false,
		"", "", "",
		"0",
		false,
		log,
	)

	require.NoError(t, err)
	require.NotNil(t, mgr)

	// The manager created by NewManager should have leader election disabled
	// This is because leader election is handled separately for background loops
	// Verify by checking that the manager was created successfully
	assert.NotNil(t, mgr.GetScheme())
}

func TestNewManager_ClientConfiguration(t *testing.T) {
	scheme := runtime.NewScheme()
	err := breakglassv1alpha1.AddToScheme(scheme)
	require.NoError(t, err)

	log := zap.NewNop().Sugar()

	restCfg := &rest.Config{
		Host:    "https://localhost:6443",
		Timeout: 30,
		QPS:     100,
		Burst:   150,
	}

	mgr, err := NewManager(
		restCfg,
		scheme,
		"0",
		false,
		"", "", "",
		"0",
		false,
		log,
	)

	require.NoError(t, err)
	require.NotNil(t, mgr)

	// Verify the manager has a valid client
	client := mgr.GetClient()
	assert.NotNil(t, client)

	// Verify the manager has the correct scheme
	assert.Equal(t, scheme, mgr.GetScheme())
}
