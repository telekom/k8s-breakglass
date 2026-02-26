package cli

import (
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/telekom/k8s-breakglass/pkg/breakglass/escalation"
	"github.com/telekom/k8s-breakglass/pkg/cert"
	"go.uber.org/zap"
)

type Config struct {
	// Application flags
	Debug bool

	// Metrics server flags
	MetricsAddr     string
	MetricsSecure   bool
	MetricsCertPath string
	MetricsCertName string
	MetricsCertKey  string

	// Health probe flags
	ProbeAddr string

	// Leader election flags
	EnableLeaderElection bool
	LeaderElectNamespace string
	LeaderElectID        string
	EnableHTTP2          bool
	EnableWebhooks       bool
	PodNamespace         string

	// Component Enable flags (for splitting controller into multiple instances)
	EnableFrontend           bool
	EnableAPI                bool
	EnableCleanup            bool
	EnableValidatingWebhooks bool

	// Configuration flags
	ConfigPath          string
	BreakglassNamespace string
	DisableEmail        bool

	// Interval flags
	ClusterConfigCheckInterval string
	EscalationStatusUpdateInt  string

	// Webhook-related config
	Webhook WebhookConfig
}

type WebhookConfig struct {
	// Webhook server flags
	BindAddr             string
	CertPath             string
	CertName             string
	CertKey              string
	CertGeneration       bool
	SvcName              string
	ValidatingConfigName string

	// Webhook Metrics server flags
	MetricsAddr     string
	MetricsSecure   bool
	MetricsCertPath string
	MetricsCertName string
	MetricsCertKey  string
}

func Parse() *Config {
	config := &Config{}
	// Define command-line flags with environment variable fallbacks.
	// The pattern: flag.XxxVar(&variable, "flag-name", defaultValueOrEnvValue, "help text")
	flag.BoolVar(&config.Debug, "debug", false, "Enable debug level logging")

	// Webhook server configuration
	flag.StringVar(&config.Webhook.BindAddr, "webhook-bind-address", getEnvString("WEBHOOK_BIND_ADDRESS", "0.0.0.0:9443"),
		"The address the webhook server binds to (host:port)")
	flag.StringVar(&config.Webhook.CertPath, "webhook-cert-path", getEnvString("WEBHOOK_CERT_PATH", cert.DefaultWebhookPath),
		"The directory that contains the webhook certificate")
	flag.StringVar(&config.Webhook.CertName, "webhook-cert-name", getEnvString("WEBHOOK_CERT_NAME", cert.DefaultTLSCertFile),
		"The name of the webhook certificate file")
	flag.StringVar(&config.Webhook.CertKey, "webhook-cert-key", getEnvString("WEBHOOK_CERT_KEY", cert.DefaultTLSKeyFile),
		"The name of the webhook key file")

	// Metrics server configuration
	flag.StringVar(&config.MetricsAddr, "metrics-bind-address", getEnvString("METRICS_BIND_ADDRESS", "0.0.0.0:8081"),
		"The address the metrics endpoint binds to. "+
			"Use :8443 for HTTPS or :8081 for HTTP, or leave as 0 to disable the metrics service")
	flag.BoolVar(&config.MetricsSecure, "metrics-secure", getEnvBool("METRICS_SECURE", false),
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead")
	flag.StringVar(&config.MetricsCertPath, "metrics-cert-path", getEnvString("METRICS_CERT_PATH", ""),
		"The directory that contains the metrics server certificate")
	flag.StringVar(&config.MetricsCertName, "metrics-cert-name", getEnvString("METRICS_CERT_NAME", "tls.crt"),
		"The name of the metrics server certificate file")
	flag.StringVar(&config.MetricsCertKey, "metrics-cert-key", getEnvString("METRICS_CERT_KEY", cert.DefaultTLSKeyFile),
		"The name of the metrics server key file")

	// Webhook metrics server configuration (separate from reconciler metrics)
	flag.StringVar(&config.Webhook.MetricsAddr, "webhooks-metrics-bind-address", getEnvString("WEBHOOKS_METRICS_BIND_ADDRESS", ""),
		"The address the webhook metrics endpoint binds to (separate from reconciler metrics). "+
			"If empty, webhook metrics will use the reconciler metrics address. "+
			"Use :8443 for HTTPS or :8083 for HTTP")
	flag.BoolVar(&config.Webhook.MetricsSecure, "webhooks-metrics-secure", getEnvBool("WEBHOOKS_METRICS_SECURE", false),
		"If set, the webhook metrics endpoint is served securely via HTTPS")
	flag.StringVar(&config.Webhook.MetricsCertPath, "webhooks-metrics-cert-path", getEnvString("WEBHOOKS_METRICS_CERT_PATH", ""),
		"The directory that contains the webhook metrics server certificate")
	flag.StringVar(&config.Webhook.MetricsCertName, "webhooks-metrics-cert-name", getEnvString("WEBHOOKS_METRICS_CERT_NAME", cert.DefaultTLSCertFile),
		"The name of the webhook metrics server certificate file")
	flag.StringVar(&config.Webhook.MetricsCertKey, "webhooks-metrics-cert-key", getEnvString("WEBHOOKS_METRICS_CERT_KEY", cert.DefaultTLSKeyFile),
		"The name of the webhook metrics server key file")
	flag.StringVar(&config.Webhook.SvcName, "webhook-service-name", getEnvString("WEBHOOK_SERVICE_NAME", "breakglass-webhook-service"), "Name of the deployed breakglass service")
	flag.StringVar(&config.Webhook.ValidatingConfigName, "webhook-validating-config-name", getEnvString("WEBHOOK_VALIDATING_CONFIG_NAME", ""),
		"Name of the ValidatingWebhookConfiguration object for the webhook")
	flag.BoolVar(&config.Webhook.CertGeneration, "webhook-cert-generation", getEnvBool("WEBHOOK_CERT_GENERATION", false), "Enable certificate generation for the webhook")

	// Health probe configuration
	flag.StringVar(&config.ProbeAddr, "health-probe-bind-address", getEnvString("PROBE_BIND_ADDRESS", ":8082"),
		"The address the probe endpoint binds to")

	// Leader election configuration
	flag.BoolVar(&config.EnableLeaderElection, "enable-leader-election", getEnvBool("ENABLE_LEADER_ELECTION", true),
		"Enable leader election for running multiple instances. Set to false when running a single instance")
	flag.StringVar(&config.LeaderElectNamespace, "leader-elect-namespace", getEnvString("LEADER_ELECT_NAMESPACE", ""),
		"The namespace where the leader election lease will be created. If empty, will default to the pod's namespace")
	flag.StringVar(&config.LeaderElectID, "leader-elect-id", getEnvString("LEADER_ELECT_ID", "breakglass.telekom.io"),
		"The ID used for leader election; ensures multiple instances coordinate properly")
	flag.BoolVar(&config.EnableHTTP2, "enable-http2", getEnvBool("ENABLE_HTTP2", false),
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")
	flag.BoolVar(&config.EnableWebhooks, "enable-webhooks", getEnvBool("ENABLE_WEBHOOKS", true),
		"Enable webhook manager for BreakglassSession, BreakglassEscalation, ClusterConfig, IdentityProvider and MailProvider")
	flag.StringVar(&config.PodNamespace, "pod-namespace", getEnvString("POD_NAMESPACE", "default"),
		"The namespace where the pod is running (used for event recording)")

	// Component enable flags for multi-instance deployments
	// By default, all components are enabled for backwards compatibility
	flag.BoolVar(&config.EnableFrontend, "enable-frontend", getEnvBool("ENABLE_FRONTEND", true),
		"Enable the frontend API endpoints. Use false when deploying a webhook-only instance")
	flag.BoolVar(&config.EnableAPI, "enable-api", getEnvBool("ENABLE_API", true),
		"Enable the API controller for BreakglassSession and BreakglassEscalation endpoints. Use false when deploying a webhook-only instance")
	flag.BoolVar(&config.EnableCleanup, "enable-cleanup", getEnvBool("ENABLE_CLEANUP", true),
		"Enable the background cleanup routine for expired sessions. Use false when deploying a webhook-only instance")
	flag.BoolVar(&config.EnableValidatingWebhooks, "enable-validating-webhooks", getEnvBool("ENABLE_VALIDATING_WEBHOOKS", true),
		"Enable validating webhooks for breakglass CRDs. Disable when running a frontend/API-only instance")

	// Interval configuration flags
	flag.StringVar(&config.ClusterConfigCheckInterval, "cluster-config-check-interval", getEnvString("CLUSTER_CONFIG_CHECK_INTERVAL", "10m"),
		"Interval for checking cluster configuration validity (e.g., '10m', '5m')")
	flag.StringVar(&config.EscalationStatusUpdateInt, "escalation-status-update-interval", getEnvString("ESCALATION_STATUS_UPDATE_INTERVAL", "10m"),
		"Interval for updating escalation status from identity provider (e.g., '10m', '5m')")

	// Configuration flags
	flag.StringVar(&config.ConfigPath, "config-path", getEnvString("BREAKGLASS_CONFIG_PATH", "./config.yaml"),
		"Path to the breakglass configuration file")
	flag.StringVar(&config.BreakglassNamespace, "breakglass-namespace", getEnvString("BREAKGLASS_NAMESPACE", ""),
		"The Kubernetes namespace containing breakglass resources (e.g., IdentityProvider secrets)")
	flag.BoolVar(&config.DisableEmail, "disable-email", getEnvBool("BREAKGLASS_DISABLE_EMAIL", false),
		"Disable email notifications for breakglass session requests")

	// Parse command-line flags and enable logging flag options
	flag.Parse()

	return config
}

func (c *Config) Print(log *zap.SugaredLogger) {
	log.Infow("CLI Configuration",
		// Debug and logging
		"debug", c.Debug,
		// Webhook server configuration
		"webhook_bind_address", c.Webhook.BindAddr,
		"webhook_cert_path", c.Webhook.CertPath,
		"webhook_cert_name", c.Webhook.CertName,
		"webhook_cert_key", c.Webhook.CertKey,
		"webhook-service-name", c.Webhook.SvcName,
		"webhook-validating-config-name", c.Webhook.ValidatingConfigName,
		"webhook-cert-generation", c.Webhook.CertGeneration,
		// Metrics server configuration
		"metrics_bind_address", c.MetricsAddr,
		"metrics_secure", c.MetricsSecure,
		"metrics_cert_path", c.MetricsCertPath,
		// Webhook metrics server configuration
		"webhooks_metrics_bind_address", c.Webhook.MetricsAddr,
		"webhooks_metrics_secure", c.Webhook.MetricsSecure,
		// Health probe
		"health_probe_bind_address", c.ProbeAddr,
		// Leader election configuration
		"enable_leader_election", c.EnableLeaderElection,
		"leader_elect_namespace", c.LeaderElectNamespace,
		"leader_elect_id", c.LeaderElectID,
		"enable_http2", c.EnableHTTP2,
		"pod_namespace", c.PodNamespace,
		// Component enable flags
		"enable_frontend", c.EnableFrontend,
		"enable_api", c.EnableAPI,
		"enable_cleanup", c.EnableCleanup,
		"enable_webhooks", c.EnableWebhooks,
		"enable_validating_webhooks", c.EnableValidatingWebhooks,
		// Intervals
		"cluster_config_check_interval", c.ClusterConfigCheckInterval,
		"escalation_status_update_interval", c.EscalationStatusUpdateInt,
		// Configuration paths
		"config_path", c.ConfigPath,
		"breakglass_namespace", c.BreakglassNamespace,
		"disable_email", c.DisableEmail,
	)
}

// DisableHTTP2 is used to configure TLS options to disable HTTP/2.
// This is important because HTTP/2 has known vulnerabilities (CVE-2023-44487, CVE-2024-3156).
func DisableHTTP2(c *tls.Config) {
	c.NextProtos = []string{"http/1.1"}
}

func ParseEscalationStatusUpdateInterval(interval string, log *zap.SugaredLogger) time.Duration {
	// Determine escalation status update interval from CLI flag (fallback to 10m)
	escalationInterval, err := parseDuration("escalation-status-update-interval", interval, escalation.DefaultEscalationStatusUpdateInterval)
	if err != nil {
		log.Warn(err)
	}
	return escalationInterval
}

func ParseClusterConfigCheckInterval(interval string, log *zap.SugaredLogger) time.Duration {
	// Determine cluster config check interval from CLI flag (fallback to 10m)
	checkInterval, err := parseDuration("cluster-config-check-interval", interval, escalation.DefaultClusterConfigCheckInterval)
	if err != nil {
		log.Warn(err)
	}
	return checkInterval
}

func parseDuration(name, value string, def time.Duration) (time.Duration, error) {
	duration := def
	if value != "" {
		if d, err := time.ParseDuration(value); err == nil {
			duration = d
		} else {
			return duration, fmt.Errorf("invalid %s %q; using default %s: %w", name, value, def.String(), err)
		}
	}

	return duration, nil
}

// getEnvString returns the value of an environment variable, or the provided default if not set.
func getEnvString(key, defaultVal string) string {
	if val, ok := os.LookupEnv(key); ok {
		return val
	}
	return defaultVal
}

// getEnvBool returns the value of an environment variable as a bool, or the provided default if not set.
// Valid true values are "true", "1", "yes" (case-insensitive).
func getEnvBool(key string, defaultVal bool) bool {
	if val, ok := os.LookupEnv(key); ok {
		switch strings.ToLower(val) {
		case "true", "1", "yes":
			return true
		case "false", "0", "no":
			return false
		}
	}
	return defaultVal
}
