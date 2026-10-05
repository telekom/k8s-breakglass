// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestPlatformCertificateCLIPaths(t *testing.T) {
	for _, test := range []struct {
		name, path, cert, key string
		args                  []string
	}{
		{name: "defaults", path: "/tmp/k8s-webhook-server/serving-certs", cert: "tls.crt", key: "tls.key"},
		{name: "environment", path: "/environment", cert: "environment.crt", key: "environment.key"},
		{name: "flags override environment", path: "/flags", cert: "flags.crt", key: "flags.key",
			args: []string{"--webhook-cert-path=/flags", "--webhook-cert-name=flags.crt", "--webhook-cert-key=flags.key",
				"--webhooks-metrics-cert-name=flags.crt", "--webhooks-metrics-cert-key=flags.key", "--metrics-cert-key=flags.key"}},
	} {
		t.Run(test.name, func(t *testing.T) {
			for _, name := range []string{"WEBHOOK_CERT_PATH", "WEBHOOK_CERT_NAME", "WEBHOOK_CERT_KEY",
				"WEBHOOKS_METRICS_CERT_NAME", "WEBHOOKS_METRICS_CERT_KEY", "METRICS_CERT_KEY"} {
				t.Setenv(name, "")
				require.NoError(t, os.Unsetenv(name))
			}
			if test.name != "defaults" {
				t.Setenv("WEBHOOK_CERT_PATH", "/environment")
				t.Setenv("WEBHOOK_CERT_NAME", "environment.crt")
				t.Setenv("WEBHOOK_CERT_KEY", "environment.key")
				t.Setenv("WEBHOOKS_METRICS_CERT_NAME", "environment.crt")
				t.Setenv("WEBHOOKS_METRICS_CERT_KEY", "environment.key")
				t.Setenv("METRICS_CERT_KEY", "environment.key")
			}
			cfg := parseWithArgs(t, test.args)
			require.Equal(t, test.path, cfg.Webhook.CertPath)
			require.Equal(t, test.cert, cfg.Webhook.CertName)
			require.Equal(t, test.key, cfg.Webhook.CertKey)
			require.Equal(t, test.cert, cfg.Webhook.MetricsCertName)
			require.Equal(t, test.key, cfg.Webhook.MetricsCertKey)
			require.Equal(t, test.key, cfg.MetricsCertKey)
		})
	}
}
