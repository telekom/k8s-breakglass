package main

import (
	"context"
	"flag"
	"fmt"
	stdlog "log"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/go-logr/zapr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"

	v1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	ctrlwebhook "sigs.k8s.io/controller-runtime/pkg/webhook"

	"github.com/telekom/k8s-breakglass/pkg/api"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/cert"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/mail"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"github.com/telekom/k8s-breakglass/pkg/policy"
	"github.com/telekom/k8s-breakglass/pkg/system"
	"github.com/telekom/k8s-breakglass/pkg/webhook"
)

// createScheme creates and returns a runtime scheme with all necessary types registered.
// This includes standard Kubernetes types and all custom breakglass CRDs.
// The same scheme instance should be reused for all Kubernetes clients to ensure consistency.
func createScheme(log *zap.SugaredLogger) *runtime.Scheme {
	scheme := runtime.NewScheme()

	// Add standard Kubernetes types (core API)
	if err := corev1.AddToScheme(scheme); err != nil {
		log.Fatalf("Failed to add corev1 to scheme: %v", err)
	}

	// Add custom breakglass CRD types (v1alpha1)
	if err := v1alpha1.AddToScheme(scheme); err != nil {
		log.Fatalf("Failed to add v1alpha1 CRDs to scheme: %v", err)
	}

	log.Debugw("Scheme initialized with CRDs", "types", "corev1, BreakglassSession, BreakglassEscalation, ClusterConfig, IdentityProvider, DenyPolicy")
	return scheme
}

// getConfigValueString returns the value from environment variable if set, otherwise returns the default value
func getConfigValueString(envVar string, defaultVal string) string {
	if val := os.Getenv(envVar); val != "" {
		return val
	}
	return defaultVal
}

// getConfigValueBool returns the value from environment variable if set as "true" or "false", otherwise returns the default value
func getConfigValueBool(envVar string, defaultVal bool) bool {
	if val := os.Getenv(envVar); val != "" {
		return val == "true"
	}
	return defaultVal
}

// getConfigValueInt returns the value from environment variable if set as a valid integer, otherwise returns the default value
func getConfigValueInt(envVar string, defaultVal int) int {
	if val := os.Getenv(envVar); val != "" {
		if i, err := strconv.Atoi(val); err == nil {
			return i
		}
	}
	return defaultVal
}

func main() {
	// Define flags for all configuration (webhook, email, config path, namespace, etc.)
	// These can be overridden by environment variables
	var (
		debug                bool
		webhookPort          int
		enableWebhookManager bool
		webhookCertDir       string
		webhookCertName      string
		webhookSecretName    string
		enableCertRotation   bool
		podNamespace         string
		disableEmail         bool
		configPath           string
	)

	flag.BoolVar(&debug, "debug", false, "enable debug level logging")
	flag.IntVar(&webhookPort, "webhook-port", 9443, "port for webhook server (can be overridden by WEBHOOK_PORT env var)")
	flag.BoolVar(&enableWebhookManager, "enable-webhook-manager", true, "enable webhook manager (can be overridden by ENABLE_WEBHOOK_MANAGER env var)")
	flag.StringVar(&webhookCertDir, "webhook-cert-dir", "/tmp/k8s-webhook-server/serving-certs", "directory for webhook certificates (can be overridden by WEBHOOK_CERT_DIR env var)")
	flag.StringVar(&webhookCertName, "webhook-cert-name", "tls.crt", "webhook certificate file name (can be overridden by WEBHOOK_CERT_NAME env var)")
	flag.StringVar(&webhookSecretName, "webhook-secret-name", "breakglass-webhook-certs", "kubernetes secret name for webhook certificates (can be overridden by WEBHOOK_SECRET_NAME env var)")
	flag.BoolVar(&enableCertRotation, "enable-cert-rotation", true, "enable certificate rotation (can be overridden by ENABLE_CERT_ROTATION env var)")
	flag.StringVar(&podNamespace, "pod-namespace", "default", "kubernetes namespace for breakglass pod and secret resources (can be overridden by POD_NAMESPACE or BREAKGLASS_NAMESPACE env var)")
	flag.BoolVar(&disableEmail, "disable-email", false, "disable email sending (can be overridden by BREAKGLASS_DISABLE_EMAIL env var, set to '1' or 'true')")
	flag.StringVar(&configPath, "config-path", "", "path to breakglass config file (can be overridden by BREAKGLASS_CONFIG_PATH env var)")
	flag.Parse()

	// Override flag values with environment variables if set
	webhookPort = getConfigValueInt("WEBHOOK_PORT", webhookPort)
	enableWebhookManager = getConfigValueBool("ENABLE_WEBHOOK_MANAGER", enableWebhookManager)
	webhookCertDir = getConfigValueString("WEBHOOK_CERT_DIR", webhookCertDir)
	webhookCertName = getConfigValueString("WEBHOOK_CERT_NAME", webhookCertName)
	webhookSecretName = getConfigValueString("WEBHOOK_SECRET_NAME", webhookSecretName)
	enableCertRotation = getConfigValueBool("ENABLE_CERT_ROTATION", enableCertRotation)
	podNamespace = getConfigValueString("POD_NAMESPACE", podNamespace)
	disableEmail = getConfigValueBool("BREAKGLASS_DISABLE_EMAIL", disableEmail)
	configPath = getConfigValueString("BREAKGLASS_CONFIG_PATH", configPath)

	zl := setupLogger(debug)
	// Ensure controller-runtime uses our zap logger to avoid its default stacktrace output
	zaprLogger := zapr.NewLogger(zl)
	ctrl.SetLogger(zaprLogger)

	log := zl.Sugar()
	log.With("version", system.Version).Info("Starting breakglass api")

	cfg, err := config.LoadWithPath(configPath)
	if err != nil {
		log.Fatalf("Error loading config for breakglass controller: %v", err)
	}

	if debug {
		log.Infof("%#v", cfg)
	}

	auth := api.NewAuth(log, cfg)
	server := api.NewServer(log.Desugar(), cfg, debug, auth)

	kubeContext := cfg.Kubernetes.Context
	sessionManager, err := breakglass.NewSessionManager(kubeContext)
	if err != nil {
		log.Fatalf("Error creating breakglass session manager: %v", err)
		return
	}

	// Create a unified scheme with all CRDs registered
	// This scheme is reused throughout the application for all Kubernetes clients
	scheme := createScheme(log)

	// Create a Kubernetes client for loading IdentityProvider (with custom scheme)
	restConfig, err := ctrl.GetConfig()
	if err != nil {
		log.Fatalf("Error getting Kubernetes config: %v", err)
		return
	}
	kubeClient, err := client.New(restConfig, client.Options{Scheme: scheme})
	if err != nil {
		log.Fatalf("Error creating Kubernetes client: %v", err)
		return
	}

	// Load IdentityProvider configuration for group sync
	idpLoader := config.NewIdentityProviderLoader(kubeClient)
	idpLoader.WithLogger(log)

	// Validate IdentityProvider exists (mandatory)
	ctx := context.Background()
	if err := idpLoader.ValidateIdentityProviderExists(ctx); err != nil {
		metrics.IdentityProviderValidationFailed.WithLabelValues("not_found").Inc()
		log.Fatalf("IdentityProvider validation failed: %v", err)
	}

	// Load primary IdentityProvider to check for Keycloak group sync
	idpConfig, err := idpLoader.LoadIdentityProvider(ctx)
	if err != nil {
		log.Warnf("Failed to load IdentityProvider: %v; group sync disabled", err)
		metrics.IdentityProviderLoadFailed.WithLabelValues("load_error").Inc()
		idpConfig = nil
	}

	// Make IdentityProvider available to API server for frontend configuration
	if idpConfig != nil {
		server.SetIdentityProvider(idpConfig)
		log.Infow("identity_provider_set_on_api_server", "type", idpConfig.Type)
	}

	var resolver breakglass.GroupMemberResolver
	if idpConfig != nil && idpConfig.Keycloak != nil && idpConfig.Keycloak.BaseURL != "" && idpConfig.Keycloak.Realm != "" {
		resolver = breakglass.NewKeycloakGroupMemberResolver(log, *idpConfig.Keycloak)
		log.Infow("Keycloak group sync enabled", "baseURL", idpConfig.Keycloak.BaseURL, "realm", idpConfig.Keycloak.Realm)
	} else {
		resolver = &breakglass.KeycloakGroupMemberResolver{} // no-op
		log.Infow("Keycloak group sync disabled or not fully configured; using no-op resolver")
	}
	escalationManager, err := breakglass.NewEscalationManager(kubeContext, resolver)
	if err != nil {
		log.Fatalf("Error creating breakglass escalation manager: %v", err)
		return
	}

	// Build shared cluster config provider & deny policy evaluator reusing escalation manager client.
	ccProvider := cluster.NewClientProvider(escalationManager.Client, log)
	denyEval := policy.NewEvaluator(escalationManager.Client, log)

	// Initialize mail queue for non-blocking async email sending
	mailSender := mail.NewSender(cfg)
	mailQueue := mail.NewQueue(mailSender, log, cfg.Mail.RetryCount, cfg.Mail.RetryBackoffMs, cfg.Mail.QueueSize)
	mailQueue.Start()
	log.Infow("Mail queue initialized and started", "retryCount", cfg.Mail.RetryCount, "retryBackoffMs", cfg.Mail.RetryBackoffMs, "queueSize", cfg.Mail.QueueSize)

	sessionController := breakglass.NewBreakglassSessionController(log, cfg, &sessionManager, &escalationManager, auth.Middleware(), ccProvider, escalationManager.Client, disableEmail).WithQueue(mailQueue)

	err = server.RegisterAll([]api.APIController{
		sessionController,
		breakglass.NewBreakglassEscalationController(log, &escalationManager, auth.Middleware()),
		webhook.NewWebhookController(log, cfg, &sessionManager, &escalationManager, ccProvider, denyEval),
	})
	if err != nil {
		log.Fatalf("Error registering breakglass controllers: %v", err)
	}

	// Background routines
	go breakglass.CleanupRoutine{Log: log, Manager: &sessionManager}.CleanupRoutine()
	// Escalation approver group expansion updater (Keycloak read-only sync)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go breakglass.EscalationStatusUpdater{Log: log, K8sClient: escalationManager.Client, Resolver: escalationManager.Resolver, Interval: 10 * time.Minute}.Start(ctx)

	// Event recorder for emitting Kubernetes events (persisted to API server)
	restCfg := ctrl.GetConfigOrDie()
	kubeClientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		log.Fatalf("failed to create kubernetes clientset for event recorder: %v", err)
	}
	// Use namespace flag for event recorder (namespace for pod and secrets)
	recorder := &breakglass.K8sEventRecorder{Clientset: kubeClientset, Source: corev1.EventSource{Component: "breakglass-controller"}, Namespace: podNamespace, Logger: log}

	// Determine interval from config (fallback to 10m)
	interval := 10 * time.Minute
	if cfg.Kubernetes.ClusterConfigCheckInterval != "" {
		if d, err := time.ParseDuration(cfg.Kubernetes.ClusterConfigCheckInterval); err == nil {
			interval = d
		} else {
			log.Warnw("Invalid clusterConfigCheckInterval in config; using default 10m", "value", cfg.Kubernetes.ClusterConfigCheckInterval, "error", err)
		}
	}

	// ClusterConfig checker: validates that referenced kubeconfig secrets contain the expected key
	go breakglass.ClusterConfigChecker{Log: log, Client: escalationManager.Client, Recorder: recorder, Interval: interval}.Start(ctx)

	// Start a controller-runtime manager to register webhooks and run reconcilers (non-blocking).
	// Webhook registration can be optionally disabled via ENABLE_WEBHOOK_MANAGER env var (default: true).
	// The manager is always needed for IdentityProvider reconciliation and field indexing.
	// Health probe channels - webhooksReady signals that webhooks are initialized and ready to handle traffic
	webhooksReady := make(chan struct{})

	// Register health check endpoints on the API server
	if enableWebhookManager {
		// Readiness probe will wait for webhooksReady channel to close
		server.RegisterHealthChecks(webhooksReady)
	} else {
		// Readiness probe will always return ready (webhooks disabled)
		server.RegisterHealthChecks(nil)
	}

	go func() {
		// Reuse the unified scheme for consistency across all Kubernetes clients
		log.Debugw("Starting manager with unified scheme")

		log.Debugw("Configuring webhook server options", "port", webhookPort, "webhooksEnabled", enableWebhookManager, "certDir", webhookCertDir)

		mgrOpts := ctrl.Options{
			Scheme: scheme,
		}

		// Set webhook port if webhooks are enabled
		if enableWebhookManager {
			log.Debugw("Creating webhook server", "port", webhookPort, "certDir", webhookCertDir)

			webhookServerOpts := ctrlwebhook.Options{
				Port: webhookPort,
			}

			mgrOpts.WebhookServer = ctrlwebhook.NewServer(webhookServerOpts)
			log.Debugw("Webhook server instance created", "port", webhookPort)
		} else {
			log.Infow("Webhook server creation skipped", "reason", "ENABLE_WEBHOOK_MANAGER=false")
		}

		log.Debugw("Creating controller-runtime manager")
		mgr, merr := ctrl.NewManager(ctrl.GetConfigOrDie(), mgrOpts)
		if merr != nil {
			log.Warnw("Failed to start controller-runtime manager; reconcilers and webhooks will not be available", "error", merr)
			return
		}
		log.Infow("Controller-runtime manager created successfully", "webhookEnabled", enableWebhookManager)

		// Setup health checks for liveness and readiness probes
		if err := mgr.AddHealthzCheck("healthz", healthz.Ping); err != nil {
			log.Errorw("Failed to add healthz check to manager", "error", err)
			return
		}
		if err := mgr.AddReadyzCheck("readyz", healthz.Ping); err != nil {
			log.Errorw("Failed to add readyz check to manager", "error", err)
			return
		}
		log.Infow("Health checks registered with manager")

		// Setup certificate rotation for webhook TLS certificates using cert-controller
		setupFinished := make(chan struct{})

		log.Debugw("Certificate rotation configuration", "enabled", enableCertRotation, "namespace", podNamespace, "secretName", webhookSecretName, "certDir", webhookCertDir)

		if enableCertRotation {
			log.Infow("Setting up certificate rotation for webhooks", "namespace", podNamespace, "secretName", webhookSecretName, "certDir", webhookCertDir, "webhookName", "breakglass-webhook")
			if _, err := cert.SetupRotator(mgr, "breakglass-webhook", false, setupFinished, podNamespace, webhookSecretName); err != nil {
				log.Fatalf("Failed to setup certificate rotation - controller cannot proceed without webhook certificates: %v", err)
			}
			log.Infow("Certificate rotator registered with manager; manager will handle cert generation")

			// Webhook registration happens BEFORE manager starts (in the manager setup code below)
			// This allows controller-runtime to properly register webhook paths when the HTTP server starts
		} else {
			log.Infow("Certificate rotation disabled via ENABLE_CERT_ROTATION env var - webhooks will not be available")
			close(setupFinished)
			// Signal webhooks ready even though certs are disabled (they won't be used)
			close(webhooksReady)
		} // Register field indices to support efficient cache-based lookups by controller-runtime clients.
		// Index fields: spec.cluster, spec.user, spec.grantedGroup
		// These are registered unconditionally as they are needed for reconciliation.

		// First, check if the types are registered in the manager's scheme
		log.Debugw("Checking CRD type registration in scheme")
		if mgr.GetScheme() == nil {
			log.Errorw("Manager scheme is nil; cannot register indices or reconcilers")
			return
		}

		idx := mgr.GetFieldIndexer()
		if idx != nil {
			log.Debugw("Starting field index registration for BreakglassSession", "cluster", "spec.cluster", "user", "spec.user", "group", "spec.grantedGroup")
			if err := idx.IndexField(ctx, &v1alpha1.BreakglassSession{}, "spec.cluster", func(rawObj client.Object) []string {
				bs := rawObj.(*v1alpha1.BreakglassSession)
				log.Debugw("Indexing BreakglassSession cluster field", "name", bs.Name, "cluster", bs.Spec.Cluster)
				return []string{bs.Spec.Cluster}
			}); err != nil {
				log.Errorw("Failed to index BreakglassSession.spec.cluster", "error", err, "errorType", fmt.Sprintf("%T", err))
			} else {
				log.Infow("Successfully indexed BreakglassSession.spec.cluster")
			}
			if err := idx.IndexField(ctx, &v1alpha1.BreakglassSession{}, "spec.user", func(rawObj client.Object) []string {
				bs := rawObj.(*v1alpha1.BreakglassSession)
				return []string{bs.Spec.User}
			}); err != nil {
				log.Errorw("Failed to index BreakglassSession.spec.user", "error", err, "errorType", fmt.Sprintf("%T", err))
			} else {
				log.Infow("Successfully indexed BreakglassSession.spec.user")
			}
			if err := idx.IndexField(ctx, &v1alpha1.BreakglassSession{}, "spec.grantedGroup", func(rawObj client.Object) []string {
				bs := rawObj.(*v1alpha1.BreakglassSession)
				return []string{bs.Spec.GrantedGroup}
			}); err != nil {
				log.Errorw("Failed to index BreakglassSession.spec.grantedGroup", "error", err, "errorType", fmt.Sprintf("%T", err))
			} else {
				log.Infow("Successfully indexed BreakglassSession.spec.grantedGroup")
			}

			// Index BreakglassEscalation helpful fields for quick lookups
			log.Debugw("Starting field index registration for BreakglassEscalation", "clusterConfigRefs", "spec.allowed.cluster+clusterConfigRefs")
			if err := idx.IndexField(ctx, &v1alpha1.BreakglassEscalation{}, "spec.allowed.cluster", func(rawObj client.Object) []string {
				be := rawObj.(*v1alpha1.BreakglassEscalation)
				if be == nil {
					return nil
				}
				out := make([]string, 0, len(be.Spec.Allowed.Clusters))
				out = append(out, be.Spec.Allowed.Clusters...)
				// also index clusterConfigRefs to support exact lookups
				out = append(out, be.Spec.ClusterConfigRefs...)
				return out
			}); err != nil {
				log.Errorw("Failed to index BreakglassEscalation.spec.allowed.cluster/clusterConfigRefs", "error", err, "errorType", fmt.Sprintf("%T", err))
			} else {
				log.Infow("Successfully indexed BreakglassEscalation.spec.allowed.cluster/clusterConfigRefs")
			}

			if err := idx.IndexField(ctx, &v1alpha1.BreakglassEscalation{}, "spec.allowed.group", func(rawObj client.Object) []string {
				be := rawObj.(*v1alpha1.BreakglassEscalation)
				if be == nil {
					return nil
				}
				return be.Spec.Allowed.Groups
			}); err != nil {
				log.Errorw("Failed to index BreakglassEscalation.spec.allowed.group", "error", err, "errorType", fmt.Sprintf("%T", err))
			} else {
				log.Infow("Successfully indexed BreakglassEscalation.spec.allowed.group")
			}

			if err := idx.IndexField(ctx, &v1alpha1.BreakglassEscalation{}, "spec.escalatedGroup", func(rawObj client.Object) []string {
				be := rawObj.(*v1alpha1.BreakglassEscalation)
				if be == nil || be.Spec.EscalatedGroup == "" {
					return nil
				}
				return []string{be.Spec.EscalatedGroup}
			}); err != nil {
				log.Errorw("Failed to index BreakglassEscalation.spec.escalatedGroup", "error", err, "errorType", fmt.Sprintf("%T", err))
			} else {
				log.Infow("Successfully indexed BreakglassEscalation.spec.escalatedGroup")
			}

			// Index ClusterConfig by metadata.name and spec.clusterID for fast lookup by name
			log.Debugw("Starting field index registration for ClusterConfig", "fields", "metadata.name, spec.clusterID")
			if err := idx.IndexField(ctx, &v1alpha1.ClusterConfig{}, "metadata.name", func(rawObj client.Object) []string {
				cc := rawObj.(*v1alpha1.ClusterConfig)
				if cc == nil {
					return nil
				}
				return []string{cc.Name}
			}); err != nil {
				log.Errorw("Failed to index ClusterConfig.metadata.name", "error", err, "errorType", fmt.Sprintf("%T", err))
			} else {
				log.Infow("Successfully indexed ClusterConfig.metadata.name")
			}

			if err := idx.IndexField(ctx, &v1alpha1.ClusterConfig{}, "spec.clusterID", func(rawObj client.Object) []string {
				cc := rawObj.(*v1alpha1.ClusterConfig)
				if cc == nil || cc.Spec.ClusterID == "" {
					return nil
				}
				return []string{cc.Spec.ClusterID}
			}); err != nil {
				log.Errorw("Failed to index ClusterConfig.spec.clusterID", "error", err, "errorType", fmt.Sprintf("%T", err))
			} else {
				log.Infow("Successfully indexed ClusterConfig.spec.clusterID")
			}
		} else {
			log.Warnw("Field indexer not available from manager")
		}

		// Register IdentityProvider Reconciler with controller-runtime manager (unconditional)
		log.Debugw("Setting up IdentityProvider reconciler")
		idpReconciler := config.NewIdentityProviderReconciler(
			mgr.GetClient(),
			log,
			func(reloadCtx context.Context) error {
				return server.ReloadIdentityProvider(idpLoader)
			},
		)
		idpReconciler.WithErrorHandler(func(ctx context.Context, err error) {
			log.Errorw("IdentityProvider reconciliation error", "error", err)
			metrics.IdentityProviderLoadFailed.WithLabelValues("reconciler_error").Inc()
		})
		idpReconciler.WithEventRecorder(mgr.GetEventRecorderFor("breakglass-controller"))
		idpReconciler.WithResyncPeriod(10 * time.Minute)

		if err := idpReconciler.SetupWithManager(mgr); err != nil {
			log.Warnw("Failed to setup IdentityProvider reconciler with manager", "error", err)
			return
		}
		log.Infow("Successfully registered IdentityProvider reconciler", "resyncPeriod", "10m")

		// Register webhooks BEFORE starting the manager - this is required for the webhook HTTP server
		// to properly register the paths when it starts listening
		if enableWebhookManager {
			log.Infow("Registering webhooks before starting manager", "webhooksToRegister", []string{"BreakglassSession", "BreakglassEscalation", "ClusterConfig", "IdentityProvider"})

			if err := (&v1alpha1.BreakglassSession{}).SetupWebhookWithManager(mgr); err != nil {
				log.Errorw("Failed to setup BreakglassSession webhook with manager", "error", err)
				return
			}
			log.Infow("Successfully registered BreakglassSession webhook")

			if err := (&v1alpha1.BreakglassEscalation{}).SetupWebhookWithManager(mgr); err != nil {
				log.Errorw("Failed to setup BreakglassEscalation webhook with manager", "error", err)
				return
			}
			log.Infow("Successfully registered BreakglassEscalation webhook")

			if err := (&v1alpha1.ClusterConfig{}).SetupWebhookWithManager(mgr); err != nil {
				log.Errorw("Failed to setup ClusterConfig webhook with manager", "error", err)
				return
			}
			log.Infow("Successfully registered ClusterConfig webhook")

			if err := (&v1alpha1.IdentityProvider{}).SetupWebhookWithManager(mgr); err != nil {
				log.Errorw("Failed to setup IdentityProvider webhook with manager", "error", err)
				return
			}
			log.Infow("Successfully registered IdentityProvider webhook")
			log.Infow("All webhooks registered successfully", "count", 4)
			// Signal that webhooks are ready to handle traffic
			close(webhooksReady)
		} else {
			log.Infow("Webhook registration disabled via ENABLE_WEBHOOK_MANAGER", "value", enableWebhookManager)
			// Still signal ready since webhooks are disabled
			close(webhooksReady)
		}

		// Start manager (blocks) but we run it in a goroutine so it doesn't prevent the API server
		log.Infow("Starting controller-runtime manager", "port", webhookPort, "certRotationEnabled", enableCertRotation)
		if err := mgr.Start(ctx); err != nil {
			log.Warnw("controller-runtime manager exited", "error", err)
		}
	}()

	// If webhooks are disabled, log it
	if !enableWebhookManager {
		log.Infow("Webhook manager disabled", "enableWebhookManager", enableWebhookManager)
	}

	// Add signal handlers for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start server in a goroutine so we can listen for signals
	go func() {
		server.Listen()
	}()

	// Wait for signal and perform graceful shutdown
	<-sigChan
	log.Info("Received shutdown signal, initiating graceful shutdown")

	// Shutdown mail queue with timeout
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := mailQueue.Stop(shutdownCtx); err != nil {
		log.Warnw("Mail queue shutdown error", "error", err)
	} else {
		log.Info("Mail queue shut down successfully")
	}
}

func setupLogger(debug bool) *zap.Logger {
	cfg := zap.NewProductionConfig()
	if debug {
		cfg = zap.NewDevelopmentConfig()
	}
	// Disable automatic stacktraces for non-fatal levels to avoid noisy traces in WARN/INFO logs
	cfg.DisableStacktrace = true
	cfg.EncoderConfig.EncodeTime = func(t time.Time, enc zapcore.PrimitiveArrayEncoder) {
		enc.AppendString(t.UTC().Format(time.RFC3339))
	}
	cfg.EncoderConfig.TimeKey = "ts"
	logger, err := cfg.Build()
	if err != nil {
		stdlog.Fatalf("failed to set up logger: %v", err)
	}
	return logger
}
