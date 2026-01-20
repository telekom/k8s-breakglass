package webhook

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/telekom/k8s-breakglass/pkg/cert"
	"github.com/telekom/k8s-breakglass/pkg/cli"
	webhookserver "sigs.k8s.io/controller-runtime/pkg/webhook"
)

func TestParseWebhookBindAddress(t *testing.T) {
	log := zap.NewNop().Sugar()

	t.Run("standard address", func(t *testing.T) {
		host, port := parseWebhookBindAddress("0.0.0.0:9443", log)
		assert.Equal(t, "0.0.0.0", host)
		assert.Equal(t, 9443, port)
	})

	t.Run("localhost with custom port", func(t *testing.T) {
		host, port := parseWebhookBindAddress("127.0.0.1:8443", log)
		assert.Equal(t, "127.0.0.1", host)
		assert.Equal(t, 8443, port)
	})

	t.Run("empty host with port", func(t *testing.T) {
		host, port := parseWebhookBindAddress(":9443", log)
		assert.Equal(t, "", host)
		assert.Equal(t, 9443, port)
	})

	t.Run("invalid port falls back to default", func(t *testing.T) {
		host, port := parseWebhookBindAddress("0.0.0.0:invalid", log)
		assert.Equal(t, "0.0.0.0", host)
		assert.Equal(t, 9443, port)
	})

	t.Run("missing colon uses defaults", func(t *testing.T) {
		host, port := parseWebhookBindAddress("0.0.0.0", log)
		assert.Equal(t, "0.0.0.0", host)
		assert.Equal(t, 9443, port)
	})
}

func TestBuildWebhookServerOptions(t *testing.T) {
	log := zap.NewNop().Sugar()

	t.Run("cert generation disabled without cert path returns error", func(t *testing.T) {
		_, err := buildWebhookServerOptions(&cli.WebhookConfig{}, false, "0.0.0.0", 9443, log)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "cert generation is disabled")
	})

	t.Run("cert generation disabled with cert path uses provided certs", func(t *testing.T) {
		wc := &cli.WebhookConfig{
			CertPath: "/certs",
			CertName: "tls.crt",
			CertKey:  "tls.key",
		}
		opts, err := buildWebhookServerOptions(wc, false, "1.2.3.4", 9445, log)
		require.NoError(t, err)
		assert.Equal(t, "1.2.3.4", opts.Host)
		assert.Equal(t, 9445, opts.Port)
		assert.Equal(t, "/certs", opts.CertDir)
		assert.Equal(t, "tls.crt", opts.CertName)
		assert.Equal(t, "tls.key", opts.KeyName)
	})

	t.Run("cert generation enabled defaults to cert path", func(t *testing.T) {
		wc := &cli.WebhookConfig{}
		opts, err := buildWebhookServerOptions(wc, true, "0.0.0.0", 9443, log)
		require.NoError(t, err)
		assert.Equal(t, cert.DefaultWebhookPath, opts.CertDir)
	})
}

func TestBuildWebhookMetricsOptions(t *testing.T) {
	log := zap.NewNop().Sugar()
	webhookOpts := webhookserver.Options{
		Host:    "0.0.0.0",
		Port:    9443,
		CertDir: cert.DefaultWebhookPath,
	}

	t.Run("empty metrics addr uses default bind", func(t *testing.T) {
		wc := &cli.WebhookConfig{}
		opts, err := buildWebhookMetricsOptions(wc, true, true, webhookOpts, log)
		require.NoError(t, err)
		assert.Equal(t, "0", opts.BindAddress)
	})

	t.Run("metrics addr with insecure serving honors bind address", func(t *testing.T) {
		wc := &cli.WebhookConfig{
			MetricsAddr:   "0.0.0.0:8083",
			MetricsSecure: false,
		}
		opts, err := buildWebhookMetricsOptions(wc, true, true, webhookOpts, log)
		require.NoError(t, err)
		assert.Equal(t, "0.0.0.0:8083", opts.BindAddress)
		assert.False(t, opts.SecureServing)
		assert.Len(t, opts.TLSOpts, 0)
	})

	t.Run("metrics secure with provided certs", func(t *testing.T) {
		wc := &cli.WebhookConfig{
			MetricsAddr:     "0.0.0.0:8083",
			MetricsSecure:   true,
			MetricsCertPath: "/metrics-certs",
			MetricsCertName: "metrics.crt",
			MetricsCertKey:  "metrics.key",
		}
		opts, err := buildWebhookMetricsOptions(wc, false, true, webhookOpts, log)
		require.NoError(t, err)
		assert.Equal(t, "/metrics-certs", opts.CertDir)
		assert.Equal(t, "metrics.crt", opts.CertName)
		assert.Equal(t, "metrics.key", opts.KeyName)
		assert.True(t, opts.SecureServing)
		assert.Len(t, opts.TLSOpts, 1)
	})

	t.Run("metrics secure without certs uses generated certs", func(t *testing.T) {
		wc := &cli.WebhookConfig{
			MetricsAddr:   "0.0.0.0:8083",
			MetricsSecure: true,
		}
		opts, err := buildWebhookMetricsOptions(wc, true, true, webhookOpts, log)
		require.NoError(t, err)
		assert.Equal(t, webhookOpts.CertDir, opts.CertDir)
	})

	t.Run("metrics secure without certs and cert generation disabled errors", func(t *testing.T) {
		wc := &cli.WebhookConfig{
			MetricsAddr:   "0.0.0.0:8083",
			MetricsSecure: true,
		}
		_, err := buildWebhookMetricsOptions(wc, true, false, webhookOpts, log)
		require.Error(t, err)
		assert.Contains(t, err.Error(), "unable to configure webhook metrics server")
	})
}
