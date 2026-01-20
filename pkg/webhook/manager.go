package webhook

import (
	"context"
	"crypto/tls"
	"fmt"
	"strconv"
	"strings"

	"github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/cert"
	"github.com/telekom/k8s-breakglass/pkg/cli"
	"github.com/telekom/k8s-breakglass/pkg/indexer"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/runtime"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	webhookserver "sigs.k8s.io/controller-runtime/pkg/webhook"
	"sigs.k8s.io/controller-runtime/pkg/webhook/admission"
)

// Setup starts the webhook server with TLS configuration and optional separate metrics server.
// This function is only called if webhooks are enabled via --enable-webhooks flag.
// Webhooks are optional; they can be disabled for deployments that don't use CRD validation.
//
// Component flags allow splitting the controller into multiple instances:
//   - enableValidatingWebhooks: enables validating webhooks for breakglass CRDs (BreakglassSession,
//     BreakglassEscalation, ClusterConfig, IdentityProvider, MailProvider)
//
// NOTE: Subject Access Review (SAR) webhooks run on the API server (Gin), not here, and cannot
// be independently disabled. They run whenever enable-api is true.
func Setup(
	ctx context.Context,
	log *zap.SugaredLogger,
	scheme *runtime.Scheme,
	wc *cli.WebhookConfig,
	enableValidatingWebhooks bool,
	enableHTTP2 bool,
	enableCertGeneration bool,
) error {
	log.Debugw("Starting webhook server setup")

	webhookHost, webhookPort := parseWebhookBindAddress(wc.BindAddr, log)

	webhookServerOptions, err := buildWebhookServerOptions(wc, enableCertGeneration, webhookHost, webhookPort, log)
	if err != nil {
		return err
	}
	webhookServer := webhookserver.NewServer(webhookServerOptions)

	metricsServerOptions, err := buildWebhookMetricsOptions(wc, enableHTTP2, enableCertGeneration, webhookServerOptions, log)
	if err != nil {
		return err
	}

	// Create a manager for webhooks (separate from reconciler manager)
	mgr, err := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
		Scheme:           scheme,
		WebhookServer:    webhookServer,
		Metrics:          metricsServerOptions,
		LeaderElection:   false,
		LeaderElectionID: "",
	})
	if err != nil {
		return fmt.Errorf("failed to start webhook server; webhooks will not be registered: %w", err)
	}
	log.Infow("Webhook server created successfully")

	if err := indexer.RegisterCommonFieldIndexes(ctx, mgr.GetFieldIndexer(), log); err != nil {
		return fmt.Errorf("failed to register common field indexes: %w", err)
	}

	// Assert that all expected indexes are registered
	if err := indexer.AssertIndexesRegistered(log); err != nil {
		return fmt.Errorf("index registration assertion failed: %w", err)
	}

	// Register health check handlers for the webhook manager
	if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
		return fmt.Errorf("failed to add webhook healthz check: %w", err)
	}
	if err := mgr.AddReadyzCheck("ping", healthz.Ping); err != nil {
		return fmt.Errorf("failed to add webhook readyz check: %w", err)
	}
	log.Infow("Webhook health check handlers registered")

	type webhookRegistrar interface {
		SetupWebhookWithManager(ctrl.Manager) error
	}

	registerWebhook := func(r webhookRegistrar, name string, mgr ctrl.Manager, log *zap.SugaredLogger) error {
		log.Debugf("Starting webhook registration for %s", name)
		if err := r.SetupWebhookWithManager(mgr); err != nil {
			return fmt.Errorf("failed to setup %s webhook with manager: %w", name, err)
		}
		log.Infof("Successfully registered %s webhook", name)
		return nil
	}

	// Register validating webhooks (conditionally based on enableValidatingWebhooks)
	if enableValidatingWebhooks {
		if err := registerWebhook(&v1alpha1.BreakglassSession{}, "BreakglassSession", mgr, log); err != nil {
			return err
		}
		if err := registerWebhook(&v1alpha1.BreakglassEscalation{}, "BreakglassEscalation", mgr, log); err != nil {
			return err
		}
		if err := registerWebhook(&v1alpha1.ClusterConfig{}, "ClusterConfig", mgr, log); err != nil {
			return err
		}
		if err := registerWebhook(&v1alpha1.IdentityProvider{}, "IdentityProvider", mgr, log); err != nil {
			return err
		}
		if err := registerWebhook(&v1alpha1.MailProvider{}, "MailProvider", mgr, log); err != nil {
			return err
		}
		if err := registerWebhook(&v1alpha1.DenyPolicy{}, "DenyPolicy", mgr, log); err != nil {
			return err
		}
		if err := registerWebhook(&v1alpha1.DebugSession{}, "DebugSession", mgr, log); err != nil {
			return err
		}
		if err := registerWebhook(&v1alpha1.DebugSessionTemplate{}, "DebugSessionTemplate", mgr, log); err != nil {
			return err
		}
		if err := registerWebhook(&v1alpha1.DebugPodTemplate{}, "DebugPodTemplate", mgr, log); err != nil {
			return err
		}
		if err := registerWebhook(&v1alpha1.AuditConfig{}, "AuditConfig", mgr, log); err != nil {
			return err
		}

		// Register ephemeral container webhook
		log.Infof("Registering ephemeral container webhook at /validate-ephemeral-containers")
		mgr.GetWebhookServer().Register("/validate-ephemeral-containers", &webhookserver.Admission{
			Handler: &EphemeralContainerWebhook{
				Client:       mgr.GetClient(),
				Log:          log,
				Decoder:      admission.NewDecoder(mgr.GetScheme()),
				DebugHandler: breakglass.NewKubectlDebugHandler(mgr.GetClient(), nil),
			},
		})
	} else {
		log.Infow("Validating webhooks disabled via --enable-validating-webhooks=false")
	}

	// Start webhook server (blocks) but we run it in a goroutine so it doesn't prevent the API server
	log.Infow("Starting webhook manager", "bindAddress", wc.BindAddr)

	// Start the manager in a blocking call that will also handle cache synchronization
	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("webhook server failed to start or exited with error (type: %s): %w", fmt.Sprintf("%T", err), err)
	}

	log.Infow("webhook server exited normally (this should not happen during normal operation)")
	return nil
}

func parseWebhookBindAddress(bindAddr string, log *zap.SugaredLogger) (string, int) {
	// webhookBindAddr should be in format "host:port" (e.g., "0.0.0.0:9443")
	webhookHost := "0.0.0.0"
	webhookPort := 9443
	if parts := strings.Split(bindAddr, ":"); len(parts) == 2 {
		webhookHost = parts[0]
		if port, err := strconv.Atoi(parts[1]); err == nil {
			webhookPort = port
			if log != nil {
				log.Debugw("Parsed webhook bind address", "bindAddress", bindAddr, "host", webhookHost, "port", webhookPort)
			}
		} else if log != nil {
			log.Warnw("Failed to parse webhook port from bind address; using default", "bindAddress", bindAddr, "defaultPort", 9443, "error", err)
		}
	}

	return webhookHost, webhookPort
}

func buildWebhookServerOptions(wc *cli.WebhookConfig, enableCertGeneration bool, webhookHost string, webhookPort int, log *zap.SugaredLogger) (webhookserver.Options, error) {
	webhookServerOptions := webhookserver.Options{
		Host: webhookHost,
		Port: webhookPort,
	}
	if !enableCertGeneration && wc.CertPath != "" {
		webhookServerOptions.CertDir = wc.CertPath
		webhookServerOptions.CertName = wc.CertName
		webhookServerOptions.KeyName = wc.CertKey
		if log != nil {
			log.Infow("Initializing webhook certificate watcher using provided certificates",
				"webhook-cert-path", wc.CertPath, "webhook-cert-name", wc.CertName,
				"webhook-cert-key", wc.CertKey)
		}
	} else if !enableCertGeneration {
		return webhookserver.Options{}, fmt.Errorf("no webhook certificate path provided and cert generation is disabled; no webhooks will be configured")
	} else if wc.CertPath != "" {
		webhookServerOptions.CertDir = wc.CertPath
		if log != nil {
			log.Infof("Cert-controller will generate certs in %q", webhookServerOptions.CertDir)
		}
	} else {
		webhookServerOptions.CertDir = cert.DefaultWebhookPath
		if log != nil {
			log.Infof("No webhook certificate path provided - cert-controller will generate certs in default directory %q", webhookServerOptions.CertDir)
		}
	}

	return webhookServerOptions, nil
}

func buildWebhookMetricsOptions(wc *cli.WebhookConfig, enableHTTP2 bool, enableCertGeneration bool, webhookServerOptions webhookserver.Options, log *zap.SugaredLogger) (metricsserver.Options, error) {
	// Configure separate metrics server for webhooks (if specified)
	// This allows running webhook-only instances with their own metrics endpoint
	var metricsServerOptions metricsserver.Options
	if wc.MetricsAddr != "" {
		if log != nil {
			log.Infow("Configuring separate metrics server for webhooks",
				"address", wc.MetricsAddr, "secure", wc.MetricsSecure)
		}

		tlsOpts := []func(*tls.Config){}
		if !enableHTTP2 {
			tlsOpts = append(tlsOpts, cli.DisableHTTP2)
		}

		metricsServerOptions = metricsserver.Options{
			BindAddress:   wc.MetricsAddr,
			SecureServing: wc.MetricsSecure,
			TLSOpts:       tlsOpts,
		}

		if wc.MetricsSecure {
			if wc.MetricsCertPath != "" {
				if log != nil {
					log.Infow("Initializing webhook metrics certificate watcher using provided certificates",
						"webhooks-metrics-cert-path", wc.MetricsCertPath, "webhooks-metrics-cert-name", wc.MetricsCertName,
						"webhooks-metrics-cert-key", wc.MetricsCertKey)
				}
				metricsServerOptions.CertDir = wc.MetricsCertPath
				metricsServerOptions.CertName = wc.MetricsCertName
				metricsServerOptions.KeyName = wc.MetricsCertKey
			} else {
				if enableCertGeneration {
					if log != nil {
						log.Infow("Initializing webhook metrics certificate watcher using generated certificates",
							"path", webhookServerOptions.CertDir, "webhooks-metrics-cert-name", wc.MetricsCertName,
							"webhooks-metrics-cert-key", wc.MetricsCertKey)
					}
					metricsServerOptions.CertDir = webhookServerOptions.CertDir
					metricsServerOptions.CertName = wc.MetricsCertName
					metricsServerOptions.KeyName = wc.MetricsCertKey
				} else if wc.MetricsSecure {
					return metricsserver.Options{}, fmt.Errorf("unable to configure webhook metrics server - webhooks-metrics-cert-path: %s, secure: %t, cert-generation: %t",
						wc.MetricsCertPath, wc.MetricsSecure, enableCertGeneration)
				}
			}
		}
	} else {
		if log != nil {
			log.Infow("Webhook metrics will use default metrics endpoint; to use separate metrics, set --webhooks-metrics-bind-address")
		}
		metricsServerOptions = metricsserver.Options{
			BindAddress: "0",
		}
	}

	return metricsServerOptions, nil
}
