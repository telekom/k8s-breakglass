package main

import (
	"context"
	"crypto/tls"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/go-logr/zapr"
	"go.uber.org/zap"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/leaderelection"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/tools/record"

	v1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	webhookserver "sigs.k8s.io/controller-runtime/pkg/webhook"

	"github.com/telekom/k8s-breakglass/pkg/api"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
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

	log.Debugw("Scheme initialized with CRDs", "types", "corev1, BreakglassSession, BreakglassEscalation, ClusterConfig, IdentityProvider, MailProvider, DenyPolicy")
	return scheme
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
		switch val {
		case "true", "1", "yes":
			return true
		case "false", "0", "no":
			return false
		}
	}
	return defaultVal
}

// disableHTTP2 is used to configure TLS options to disable HTTP/2.
// This is important because HTTP/2 has known vulnerabilities (CVE-2023-44487, CVE-2024-3156).
func disableHTTP2(c *tls.Config) {
	c.NextProtos = []string{"http/1.1"}
}

// setupLogger creates and configures a zap logger for the application.
// If debug is true, it uses development mode; otherwise production mode.
func setupLogger(debug bool) *zap.Logger {
	if debug {
		logger, err := zap.NewDevelopment()
		if err != nil {
			panic(err)
		}
		return logger
	}

	logger, err := zap.NewProduction()
	if err != nil {
		panic(err)
	}
	return logger
}

func main() {
	// DEPLOYMENT PATTERNS
	// ===================
	// The breakglass controller supports multiple deployment patterns via component enable flags:
	//
	// 1. MONOLITHIC (default):
	//    All components run in a single instance. Use defaults or:
	//    breakglass-controller
	//
	// 2. WEBHOOK-ONLY INSTANCE (validating webhooks only):
	//    Runs only Kubernetes validating webhooks (CRD validation) with separate metrics.
	//    breakglass-controller \
	//      --enable-frontend=false \
	//      --enable-api=false \
	//      --enable-cleanup=false \
	//      --webhooks-metrics-bind-address=0.0.0.0:8083
	//
	// 3. API-ONLY INSTANCE (frontend, REST API, SAR webhook):
	//    Runs API endpoints (Session/Escalation), web UI, and SAR authorization webhook.
	//    breakglass-controller \
	//      --enable-webhooks=false \
	//      --enable-cleanup=false
	//
	// 4. FRONTEND-ONLY INSTANCE:
	//    Runs only the frontend web UI without webhooks, API, or SAR.
	//    breakglass-controller \
	//      --enable-api=false \
	//      --enable-webhooks=false \
	//      --enable-cleanup=false
	//
	// 5. CLEANUP-ONLY INSTANCE:
	//    Runs only the background cleanup routine for expired sessions.
	//    breakglass-controller \
	//      --enable-frontend=false \
	//      --enable-api=false \
	//      --enable-webhooks=false
	//
	// COMPONENT ARCHITECTURE
	// ======================
	// Frontend/API/SAR:      Gin HTTP server (port 8080) - runs if enable-frontend or enable-api
	// Validating Webhooks:   controller-runtime webhook server (port 9443) - runs if enable-webhooks
	// Cleanup Routine:       background goroutine - runs if enable-cleanup
	//
	// METRICS SEPARATION
	// ==================
	// The --webhooks-metrics-bind-address flag allows running a separate metrics server for webhooks.
	// This is useful for multi-instance deployments where you want to scrape metrics separately:
	//
	//   API/Reconciler metrics:  0.0.0.0:8080  (main controller metrics)
	//   Webhook metrics:         0.0.0.0:8081  (webhook-specific metrics)
	//   Health probe:            0.0.0.0:8082  (health checks)
	//
	// ENVIRONMENT VARIABLES
	// =====================
	// All flags can be set via environment variables with UPPERCASE_SNAKE_CASE names:
	//   ENABLE_FRONTEND=true          # Web UI
	//   ENABLE_API=true               # REST API and SAR webhook
	//   ENABLE_CLEANUP=true           # Background cleanup
	//   ENABLE_WEBHOOKS=true          # Validating webhooks (CRD validation)
	//   ENABLE_VALIDATING_WEBHOOKS=true  # Which validating webhooks to register
	//   WEBHOOKS_METRICS_BIND_ADDRESS=0.0.0.0:8083  # Separate metrics for webhooks
	//
	var (
		// Application flags
		debug bool

		// Webhook server flags
		webhookBindAddr string
		webhookCertPath string
		webhookCertName string
		webhookCertKey  string

		// Metrics server flags
		metricsAddr     string
		metricsSecure   bool
		metricsCertPath string
		metricsCertName string
		metricsCertKey  string

		// Webhook metrics server flags
		webhooksMetricsAddr     string
		webhooksMetricsSecure   bool
		webhooksMetricsCertPath string
		webhooksMetricsCertName string
		webhooksMetricsCertKey  string

		// Health probe flags
		probeAddr string

		// Leader election flags
		enableLeaderElection bool
		leaderElectNamespace string
		leaderElectID        string
		enableHTTP2          bool
		enableWebhooks       bool
		podNamespace         string

		// Component enable flags (for splitting controller into multiple instances)
		enableFrontend           bool
		enableAPI                bool
		enableCleanup            bool
		enableValidatingWebhooks bool

		// Configuration flags
		configPath          string
		breakglassNamespace string
		disableEmail        bool

		// Interval flags
		clusterConfigCheckInterval string
		escalationStatusUpdateInt  string
	)

	// Define command-line flags with environment variable fallbacks.
	// The pattern: flag.XxxVar(&variable, "flag-name", defaultValueOrEnvValue, "help text")
	flag.BoolVar(&debug, "debug", false, "Enable debug level logging")

	// Webhook server configuration
	flag.StringVar(&webhookBindAddr, "webhook-bind-address", getEnvString("WEBHOOK_BIND_ADDRESS", "0.0.0.0:9443"),
		"The address the webhook server binds to (host:port)")
	flag.StringVar(&webhookCertPath, "webhook-cert-path", getEnvString("WEBHOOK_CERT_PATH", "/tmp/k8s-webhook-server/serving-certs"),
		"The directory that contains the webhook certificate")
	flag.StringVar(&webhookCertName, "webhook-cert-name", getEnvString("WEBHOOK_CERT_NAME", "tls.crt"),
		"The name of the webhook certificate file")
	flag.StringVar(&webhookCertKey, "webhook-cert-key", getEnvString("WEBHOOK_CERT_KEY", "tls.key"),
		"The name of the webhook key file")

	// Metrics server configuration
	flag.StringVar(&metricsAddr, "metrics-bind-address", getEnvString("METRICS_BIND_ADDRESS", "0.0.0.0:8081"),
		"The address the metrics endpoint binds to. "+
			"Use :8443 for HTTPS or :8081 for HTTP, or leave as 0 to disable the metrics service")
	flag.BoolVar(&metricsSecure, "metrics-secure", getEnvBool("METRICS_SECURE", false),
		"If set, the metrics endpoint is served securely via HTTPS. Use --metrics-secure=false to use HTTP instead")
	flag.StringVar(&metricsCertPath, "metrics-cert-path", getEnvString("METRICS_CERT_PATH", ""),
		"The directory that contains the metrics server certificate")
	flag.StringVar(&metricsCertName, "metrics-cert-name", getEnvString("METRICS_CERT_NAME", "tls.crt"),
		"The name of the metrics server certificate file")
	flag.StringVar(&metricsCertKey, "metrics-cert-key", getEnvString("METRICS_CERT_KEY", "tls.key"),
		"The name of the metrics server key file")

	// Webhook metrics server configuration (separate from reconciler metrics)
	flag.StringVar(&webhooksMetricsAddr, "webhooks-metrics-bind-address", getEnvString("WEBHOOKS_METRICS_BIND_ADDRESS", ""),
		"The address the webhook metrics endpoint binds to (separate from reconciler metrics). "+
			"If empty, webhook metrics will use the reconciler metrics address. "+
			"Use :8443 for HTTPS or :8083 for HTTP")
	flag.BoolVar(&webhooksMetricsSecure, "webhooks-metrics-secure", getEnvBool("WEBHOOKS_METRICS_SECURE", false),
		"If set, the webhook metrics endpoint is served securely via HTTPS")
	flag.StringVar(&webhooksMetricsCertPath, "webhooks-metrics-cert-path", getEnvString("WEBHOOKS_METRICS_CERT_PATH", ""),
		"The directory that contains the webhook metrics server certificate")
	flag.StringVar(&webhooksMetricsCertName, "webhooks-metrics-cert-name", getEnvString("WEBHOOKS_METRICS_CERT_NAME", "tls.crt"),
		"The name of the webhook metrics server certificate file")
	flag.StringVar(&webhooksMetricsCertKey, "webhooks-metrics-cert-key", getEnvString("WEBHOOKS_METRICS_CERT_KEY", "tls.key"),
		"The name of the webhook metrics server key file")

	// Health probe configuration
	flag.StringVar(&probeAddr, "health-probe-bind-address", getEnvString("PROBE_BIND_ADDRESS", ":8082"),
		"The address the probe endpoint binds to")

	// Leader election configuration
	flag.BoolVar(&enableLeaderElection, "enable-leader-election", getEnvBool("ENABLE_LEADER_ELECTION", true),
		"Enable leader election for running multiple instances. Set to false when running a single instance")
	flag.StringVar(&leaderElectNamespace, "leader-elect-namespace", getEnvString("LEADER_ELECT_NAMESPACE", ""),
		"The namespace where the leader election lease will be created. If empty, will default to the pod's namespace")
	flag.StringVar(&leaderElectID, "leader-elect-id", getEnvString("LEADER_ELECT_ID", "breakglass.telekom.io"),
		"The ID used for leader election; ensures multiple instances coordinate properly")
	flag.BoolVar(&enableHTTP2, "enable-http2", getEnvBool("ENABLE_HTTP2", false),
		"If set, HTTP/2 will be enabled for the metrics and webhook servers")
	flag.BoolVar(&enableWebhooks, "enable-webhooks", getEnvBool("ENABLE_WEBHOOKS", true),
		"Enable webhook manager for BreakglassSession, BreakglassEscalation, ClusterConfig, IdentityProvider and MailProvider")
	flag.StringVar(&podNamespace, "pod-namespace", getEnvString("POD_NAMESPACE", "default"),
		"The namespace where the pod is running (used for event recording)")

	// Component enable flags for multi-instance deployments
	// By default, all components are enabled for backwards compatibility
	flag.BoolVar(&enableFrontend, "enable-frontend", getEnvBool("ENABLE_FRONTEND", true),
		"Enable the frontend API endpoints. Use false when deploying a webhook-only instance")
	flag.BoolVar(&enableAPI, "enable-api", getEnvBool("ENABLE_API", true),
		"Enable the API controller for BreakglassSession and BreakglassEscalation endpoints. Use false when deploying a webhook-only instance")
	flag.BoolVar(&enableCleanup, "enable-cleanup", getEnvBool("ENABLE_CLEANUP", true),
		"Enable the background cleanup routine for expired sessions. Use false when deploying a webhook-only instance")
	flag.BoolVar(&enableValidatingWebhooks, "enable-validating-webhooks", getEnvBool("ENABLE_VALIDATING_WEBHOOKS", true),
		"Enable validating webhooks for breakglass CRDs. Disable when running a frontend/API-only instance")

	// Interval configuration flags
	flag.StringVar(&clusterConfigCheckInterval, "cluster-config-check-interval", getEnvString("CLUSTER_CONFIG_CHECK_INTERVAL", "10m"),
		"Interval for checking cluster configuration validity (e.g., '10m', '5m')")
	flag.StringVar(&escalationStatusUpdateInt, "escalation-status-update-interval", getEnvString("ESCALATION_STATUS_UPDATE_INTERVAL", "10m"),
		"Interval for updating escalation status from identity provider (e.g., '10m', '5m')")

	// Configuration flags
	flag.StringVar(&configPath, "config-path", getEnvString("BREAKGLASS_CONFIG_PATH", "./config.yaml"),
		"Path to the breakglass configuration file")
	flag.StringVar(&breakglassNamespace, "breakglass-namespace", getEnvString("BREAKGLASS_NAMESPACE", ""),
		"The Kubernetes namespace containing breakglass resources (e.g., IdentityProvider secrets)")
	flag.BoolVar(&disableEmail, "disable-email", getEnvBool("BREAKGLASS_DISABLE_EMAIL", false),
		"Disable email notifications for breakglass session requests")

	// Parse command-line flags and enable logging flag options
	flag.Parse()

	// Setup logging with zap
	var zapLogger *zap.Logger
	var err error

	if debug {
		zapLogger, err = zap.NewDevelopment()
	} else {
		zapLogger, err = zap.NewProduction()
	}
	if err != nil {
		panic(err)
	}
	defer func() {
		_ = zapLogger.Sync()
	}()

	ctrl.SetLogger(zapr.NewLogger(zapLogger))

	log := zapLogger.Sugar()
	log.Infof("Starting breakglass controller (version: %s)", system.Version)

	if debug {
		log.Debug("Debug logging enabled")
	}

	// Log all startup configuration flags for debuggability
	log.Infow("Startup Configuration",
		// Debug and logging
		"debug", debug,
		// Webhook server configuration
		"webhook_bind_address", webhookBindAddr,
		"webhook_cert_path", webhookCertPath,
		"webhook_cert_name", webhookCertName,
		"webhook_cert_key", webhookCertKey,
		// Metrics server configuration
		"metrics_bind_address", metricsAddr,
		"metrics_secure", metricsSecure,
		"metrics_cert_path", metricsCertPath,
		// Webhook metrics server configuration
		"webhooks_metrics_bind_address", webhooksMetricsAddr,
		"webhooks_metrics_secure", webhooksMetricsSecure,
		// Health probe
		"health_probe_bind_address", probeAddr,
		// Leader election configuration
		"enable_leader_election", enableLeaderElection,
		"leader_elect_namespace", leaderElectNamespace,
		"leader_elect_id", leaderElectID,
		"enable_http2", enableHTTP2,
		"pod_namespace", podNamespace,
		// Component enable flags
		"enable_frontend", enableFrontend,
		"enable_api", enableAPI,
		"enable_cleanup", enableCleanup,
		"enable_webhooks", enableWebhooks,
		"enable_validating_webhooks", enableValidatingWebhooks,
		// Intervals
		"cluster_config_check_interval", clusterConfigCheckInterval,
		"escalation_status_update_interval", escalationStatusUpdateInt,
		// Configuration paths
		"config_path", configPath,
		"breakglass_namespace", breakglassNamespace,
		"disable_email", disableEmail,
	)

	// Load configuration from config.yaml
	cfg, err := config.Load(configPath)
	if err != nil {
		log.Fatalf("Error loading config for breakglass controller: %v", err)
	}

	if debug {
		log.Infof("Configuration: %#v", cfg)
	}

	// Setup authentication
	auth := api.NewAuth(log, cfg)
	server := api.NewServer(zapLogger, cfg, debug, auth)

	kubeContext := cfg.Kubernetes.Context
	sessionManager, err := breakglass.NewSessionManager(kubeContext)
	if err != nil {
		log.Fatalf("Error creating breakglass session manager: %v", err)
	}

	// Create a unified scheme with all CRDs registered
	scheme := createScheme(log)

	// Create a Kubernetes client for loading IdentityProvider (with custom scheme)
	restConfig, err := ctrl.GetConfig()
	if err != nil {
		log.Fatalf("Error getting Kubernetes config: %v", err)
	}

	kubeClient, err := client.New(restConfig, client.Options{Scheme: scheme})
	if err != nil {
		log.Fatalf("Error creating Kubernetes client: %v", err)
	}

	// Load IdentityProvider configuration for group sync
	idpLoader := config.NewIdentityProviderLoader(kubeClient)
	idpLoader.WithLogger(log)

	// Set up metrics recorder for conversion failures
	idpLoader.WithMetricsRecorder(func(idpName, failureReason string) {
		metrics.IdentityProviderConversionErrors.WithLabelValues(idpName, failureReason).Inc()
	})

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

	// Enable multi-IDP support in auth handler for token verification
	// This allows the backend to verify tokens from any configured IDP, not just the default one
	auth.WithIdentityProviderLoader(idpLoader)

	// Setup GroupMemberResolver for escalation approver expansion
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
	}

	// Build shared cluster config provider & deny policy evaluator reusing escalation manager client
	ccProvider := cluster.NewClientProvider(escalationManager.Client, log)
	denyEval := policy.NewEvaluator(escalationManager.Client, log)

	// Initialize MailProviderLoader and load default provider from cluster
	mailProviderLoader := config.NewMailProviderLoader(escalationManager.Client).WithLogger(log)
	var mailQueue *mail.Queue

	defaultProvider, err := mailProviderLoader.GetDefaultMailProvider(ctx)
	if err != nil {
		log.Warnw("No default mail provider found in cluster - mail notifications will be disabled", "error", err)
		mailQueue = nil
		disableEmail = true
	} else {
		log.Infow("Using default mail provider from cluster",
			"provider", defaultProvider.Name,
			"host", defaultProvider.Host,
			"port", defaultProvider.Port)
		mailSender := mail.NewSenderFromMailProvider(defaultProvider, cfg.Frontend.BrandingName)
		mailQueue = mail.NewQueue(mailSender, log, defaultProvider.RetryCount, defaultProvider.RetryBackoffMs, defaultProvider.QueueSize)
		mailQueue.Start()
		log.Infow("Mail queue initialized and started",
			"provider", defaultProvider.Name,
			"retryCount", defaultProvider.RetryCount,
			"retryBackoffMs", defaultProvider.RetryBackoffMs,
			"queueSize", defaultProvider.QueueSize)
	}

	// Setup session controller with all dependencies
	sessionController := breakglass.NewBreakglassSessionController(log, cfg, &sessionManager, &escalationManager, auth.Middleware(), configPath, ccProvider, escalationManager.Client, disableEmail).WithQueue(mailQueue)

	// Register API controllers based on component flags
	// Both frontend and API share the same HTTP server, so we check both flags
	shouldEnableHTTPServer := enableFrontend || enableAPI
	apiControllers := []api.APIController{}

	if enableFrontend {
		log.Infow("Frontend UI enabled via --enable-frontend=true")
	}

	if enableAPI {
		apiControllers = append(apiControllers, sessionController)
		apiControllers = append(apiControllers, breakglass.NewBreakglassEscalationController(log, &escalationManager, auth.Middleware(), configPath))
		log.Infow("API controllers enabled", "components", "BreakglassSession, BreakglassEscalation")
	}

	// Webhook controller is always registered but may not be exposed via webhooks
	webhookCtrl := webhook.NewWebhookController(log, cfg, &sessionManager, &escalationManager, ccProvider, denyEval)
	apiControllers = append(apiControllers, webhookCtrl)

	if shouldEnableHTTPServer {
		err = server.RegisterAll(apiControllers)
		if err != nil {
			log.Fatalf("Error registering breakglass controllers: %v", err)
		}
	} else {
		log.Infow("HTTP server disabled: both --enable-frontend and --enable-api are false")
	}

	// Create a channel to broadcast leadership signal to background loops
	// This enables safe horizontal scaling: only the leader runs cleanup loops
	leaderElectedCh := make(chan struct{})

	// Placeholder for resourcelock - will be created after kubeClientset is initialized
	var resourceLock resourcelock.Interface

	// Background routines (cleanup routine is optional)
	if enableCleanup {
		go breakglass.CleanupRoutine{Log: log, Manager: &sessionManager, LeaderElected: leaderElectedCh}.CleanupRoutine()
		log.Infow("Cleanup routine enabled")
	} else {
		log.Infow("Cleanup routine disabled via --enable-cleanup=false")
	}

	// Escalation approver group expansion updater (Keycloak read-only sync)
	managerCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Event recorder for emitting Kubernetes events (persisted to API server)
	restCfg := ctrl.GetConfigOrDie()
	kubeClientset, err := kubernetes.NewForConfig(restCfg)
	if err != nil {
		log.Fatalf("failed to create kubernetes clientset for event recorder: %v", err)
	}

	// Now create the leader election resourcelock using the kubeClientset
	eventBroadcaster := record.NewBroadcaster()
	eventRecorder := eventBroadcaster.NewRecorder(scheme, corev1.EventSource{Component: "breakglass-controller"})

	// Determine escalation status update interval from CLI flag (fallback to 10m)
	escalationInterval := 10 * time.Minute
	if escalationStatusUpdateInt != "" {
		if d, err := time.ParseDuration(escalationStatusUpdateInt); err == nil {
			escalationInterval = d
		} else {
			log.Warnw("Invalid escalation-status-update-interval; using default 10m", "value", escalationStatusUpdateInt, "error", err)
		}
	}

	// Start the escalation status updater with EventRecorder and IDPLoader so it can:
	// - Emit events when IDP group sync fails (surfaced via kubectl describe identityprovider)
	// - Fetch group members from multiple IDPs for status.groupSyncErrors and status.IDPGroupMemberships
	go breakglass.EscalationStatusUpdater{
		Log:           log,
		K8sClient:     escalationManager.Client,
		Resolver:      escalationManager.Resolver,
		EventRecorder: eventRecorder,
		IDPLoader:     idpLoader,
		Interval:      escalationInterval,
		LeaderElected: leaderElectedCh,
	}.Start(managerCtx)

	// Determine the namespace for the lease
	// If not specified via flag, use the pod's namespace from the environment
	leaseName := leaderElectID
	leaseNamespace := leaderElectNamespace
	if leaseNamespace == "" {
		leaseNamespace = podNamespace
	}
	if leaseNamespace == "" {
		leaseNamespace = "default"
	}

	log.Infow("Creating leader election lease", "id", leaseName, "namespace", leaseNamespace)

	// Get hostname for the resourcelock identity
	hostname, err := os.Hostname()
	if err != nil {
		log.Fatalf("Failed to get hostname for leader election: %v", err)
	}

	// Create the resourcelock directly using resourcelock.New
	// This will automatically create the lease if it doesn't exist
	resourceLock, err = resourcelock.New(
		"leases",
		leaseNamespace,
		leaseName,
		kubeClientset.CoreV1(),
		kubeClientset.CoordinationV1(),
		resourcelock.ResourceLockConfig{
			Identity:      hostname,
			EventRecorder: eventRecorder,
		},
	)
	if err != nil {
		log.Fatalf("Failed to create leader election resource lock: %v", err)
	}
	log.Infow("Leader election resource lock created", "id", leaseName, "namespace", leaseNamespace, "identity", hostname)

	recorder := &breakglass.K8sEventRecorder{Clientset: kubeClientset, Source: corev1.EventSource{Component: "breakglass-controller"}, Namespace: podNamespace, Logger: log}

	// Determine interval from CLI flag first, then config (fallback to 10m)
	interval := 10 * time.Minute
	intervalStr := clusterConfigCheckInterval
	if intervalStr == "" && cfg.Kubernetes.ClusterConfigCheckInterval != "" {
		intervalStr = cfg.Kubernetes.ClusterConfigCheckInterval
	}
	if intervalStr != "" {
		if d, err := time.ParseDuration(intervalStr); err == nil {
			interval = d
		} else {
			log.Warnw("Invalid cluster-config-check-interval; using default 10m", "value", intervalStr, "error", err)
		}
	}

	// ClusterConfig checker: validates that referenced kubeconfig secrets contain the expected key
	go breakglass.ClusterConfigChecker{Log: log, Client: escalationManager.Client, Recorder: recorder, Interval: interval, LeaderElected: leaderElectedCh}.Start(managerCtx)

	// Start leader election if enabled
	// This coordinates background loops (cleanup, escalation updater, cluster config checker)
	// to run only on the leader replica using the resourcelock
	if enableLeaderElection {
		go func() {
			// Create callbacks for leader election
			leaderCallbacks := leaderelection.LeaderCallbacks{
				OnStartedLeading: func(ctx context.Context) {
					log.Infow("This replica acquired leadership, signaling background loops")
					// Signal background loops that we're the leader
					select {
					case <-leaderElectedCh:
						// Already closed, we've signaled leadership
					default:
						close(leaderElectedCh)
					}
				},
				OnStoppedLeading: func() {
					log.Infow("Lost leadership")
					// Recreate the channel for the next leader to use
					leaderElectedCh = make(chan struct{})
				},
				OnNewLeader: func(identity string) {
					if identity == hostname {
						log.Infow("I became the leader", "identity", identity)
					} else {
						log.Infow("New leader elected", "identity", identity)
					}
				},
			}

			// Create the LeaderElector which handles the full lifecycle of leader election:
			// - Acquires the lock when becoming leader (creates/updates the lease)
			// - Renews the lock at the specified interval to maintain leadership
			// - Releases the lock when context is cancelled
			// - Detects when leadership is lost and calls OnStoppedLeading
			elector, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
				Lock:          resourceLock,
				LeaseDuration: 15 * time.Second, // Time the lease is held by leader
				RenewDeadline: 10 * time.Second, // Deadline for renewing the lease before losing it
				RetryPeriod:   2 * time.Second,  // Duration to wait between leader election tries
				Callbacks:     leaderCallbacks,
				WatchDog:      nil,
				Name:          "breakglass-controller",
			})
			if err != nil {
				log.Fatalf("Failed to create LeaderElector: %v", err)
			}

			log.Infow("Starting leader election", "id", leaseName, "namespace", leaseNamespace, "identity", hostname)

			// Run the leader election - this will block until context is cancelled
			// It continuously tries to acquire the lease and renews it if successful
			elector.Run(managerCtx)
		}()
	} else {
		// If leader election is disabled, immediately signal that we're the leader
		// This allows background loops to run on all replicas
		log.Infow("Leader election disabled via --enable-leader-election=false, background loops will run on all replicas")
		close(leaderElectedCh)
	}

	// Always start the reconciler manager (field indices and reconcilers always run)
	// The manager does NOT do leader election; background loops handle that
	setupReconcilerManager(managerCtx, log, scheme, kubeClient, idpLoader, server,
		metricsAddr, metricsSecure, metricsCertPath, metricsCertName, metricsCertKey,
		probeAddr, resourceLock, enableHTTP2, clusterConfigCheckInterval, escalationStatusUpdateInt, leaderElectedCh)

	// Optionally setup webhooks if enabled (webhooks are optional, reconcilers are not)
	if enableWebhooks {
		setupWebhooks(managerCtx, log, scheme,
			webhookBindAddr, webhookCertPath, webhookCertName, webhookCertKey,
			webhooksMetricsAddr, webhooksMetricsSecure, webhooksMetricsCertPath, webhooksMetricsCertName, webhooksMetricsCertKey,
			enableValidatingWebhooks, enableHTTP2)
		log.Infow("Webhooks enabled via --enable-webhooks flag")
	} else {
		log.Infow("Webhooks disabled via --enable-webhooks flag")
	}

	// Add signal handlers for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Start HTTP server (API/Frontend/SAR) if either frontend or API is enabled
	if shouldEnableHTTPServer {
		go func() {
			server.Listen()
		}()
	}

	// Wait for signal and perform graceful shutdown
	<-sigChan
	log.Info("Received shutdown signal, initiating graceful shutdown")

	// Shutdown mail queue with timeout
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()
	if err := mailQueue.Stop(shutdownCtx); err != nil {
		log.Warnw("Mail queue shutdown error", "error", err)
	} else {
		log.Info("Mail queue shut down successfully")
	}

	cancel()
	log.Info("Breakglass controller shutdown complete")
}

// setupReconcilerManager starts the controller-runtime manager with field indices and IdentityProvider reconciler.
// This function handles:
// - Metrics server configuration with secure serving
// - Field index setup for efficient queries
// - IdentityProvider reconciler setup
// - Manager startup and leader election
// - Broadcasting leadership signal to background loops when acquired
func setupReconcilerManager(
	ctx context.Context,
	log *zap.SugaredLogger,
	scheme *runtime.Scheme,
	kubeClient client.Client,
	idpLoader *config.IdentityProviderLoader,
	server *api.Server,
	metricsAddr string,
	metricsSecure bool,
	metricsCertPath string,
	metricsCertName string,
	metricsCertKey string,
	probeAddr string,
	resourceLock resourcelock.Interface,
	enableHTTP2 bool,
	clusterConfigCheckInterval string,
	escalationStatusUpdateInterval string,
	leaderElectedCh chan<- struct{}, // Channel to broadcast leadership signal to background loops
) {
	go func() {
		log.Debugw("Starting reconciler manager with unified scheme")

		// Configure TLS for metrics server
		// Disable HTTP/2 by default due to security vulnerabilities
		tlsOpts := []func(*tls.Config){}
		if !enableHTTP2 {
			tlsOpts = append(tlsOpts, disableHTTP2)
		}

		// Metrics server configuration
		metricsServerOptions := metricsserver.Options{
			BindAddress:   metricsAddr,
			SecureServing: metricsSecure,
			TLSOpts:       tlsOpts,
		}

		// If explicit certificate paths are provided, use them; otherwise controller-runtime
		// will auto-generate self-signed certificates (suitable for development/testing).
		if len(metricsCertPath) > 0 {
			log.Infow("Initializing metrics certificate watcher using provided certificates",
				"metrics-cert-path", metricsCertPath, "metrics-cert-name", metricsCertName,
				"metrics-cert-key", metricsCertKey)
			metricsServerOptions.CertDir = metricsCertPath
			metricsServerOptions.CertName = metricsCertName
			metricsServerOptions.KeyName = metricsCertKey
		}

		// Create manager without webhook server (webhooks are optional)
		// NOTE: Manager does NOT use leader election; that's handled separately by background loops
		// The resourcelock is passed to background loops for their own coordination
		mgr, merr := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
			Scheme:                 scheme,
			Metrics:                metricsServerOptions,
			HealthProbeBindAddress: probeAddr,
			WebhookServer:          nil,   // Webhooks are handled separately if enabled
			LeaderElection:         false, // Reconcilers run on all replicas
		})
		if merr != nil {
			log.Errorw("Failed to start controller-runtime manager; reconcilers will not run", "error", merr)
			return
		}
		log.Infow("Controller-runtime manager created successfully (no leader election at manager level)")

		// Register health check handlers for liveness and readiness probes
		// These endpoints are exposed at the health probe bind address (default :8082)
		if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
			log.Warnw("Failed to add healthz check", "error", err)
		}
		if err := mgr.AddReadyzCheck("ping", healthz.Ping); err != nil {
			log.Warnw("Failed to add readyz check", "error", err)
		}
		log.Infow("Health check handlers registered", "endpoint", probeAddr)

		registerCommonFieldIndexes(ctx, mgr.GetFieldIndexer(), log)

		// Register IdentityProvider Reconciler with controller-runtime manager
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

		// Set reconciler in API server so it can use the cached IDPs
		// This prevents the API from querying the Kubernetes APIServer on every /api/config/idps request
		server.SetIdentityProviderReconciler(idpReconciler)

		if err := idpReconciler.SetupWithManager(mgr); err != nil {
			log.Errorw("Failed to setup IdentityProvider reconciler with manager", "error", err)
			return
		}
		log.Infow("Successfully registered IdentityProvider reconciler", "resyncPeriod", "10m")

		// Register BreakglassEscalation Reconciler with controller-runtime manager
		log.Debugw("Setting up BreakglassEscalation reconciler")
		escalationReconciler := config.NewEscalationReconciler(
			mgr.GetClient(),
			log,
			mgr.GetEventRecorderFor("breakglass-escalation-controller"),
			nil, // no onReload callback needed for escalations
			func(ctx context.Context, err error) {
				log.Errorw("BreakglassEscalation reconciliation error", "error", err)
				metrics.IdentityProviderLoadFailed.WithLabelValues("escalation_reconciler_error").Inc()
			},
			10*time.Minute,
		)

		// Set reconciler in API server so it can use the cached escalation→IDP mapping
		// This prevents the API from querying the Kubernetes APIServer on every /api/config/idps request
		server.SetEscalationReconciler(escalationReconciler)

		if err := escalationReconciler.SetupWithManager(mgr); err != nil {
			log.Errorw("Failed to setup BreakglassEscalation reconciler with manager", "error", err)
			return
		}
		log.Infow("Successfully registered BreakglassEscalation reconciler", "resyncPeriod", "10m")

		// Note: Leadership election is NOT handled by the manager at this level.
		// Background loops (cleanup, escalation updater, cluster config checker) use the resourcelock
		// to coordinate and run only on the leader. The signal propagation to those loops happens
		// outside this manager in the main() function after the manager and loops are set up.

		// Start manager (blocks) but we run it in a goroutine so it doesn't prevent the API server
		// The manager runs reconcilers on all replicas (no leader election)
		log.Infow("Starting controller-runtime reconciler manager (no leader election at manager level)")
		if err := mgr.Start(ctx); err != nil {
			log.Warnw("controller-runtime reconciler manager exited", "error", err)
		}
	}()
}

// setupWebhooks starts the webhook server with TLS configuration and optional separate metrics server.
// This function is only called if webhooks are enabled via --enable-webhooks flag.
// Webhooks are optional; they can be disabled for deployments that don't use CRD validation.
//
// Component flags allow splitting the controller into multiple instances:
//   - enableValidatingWebhooks: enables validating webhooks for breakglass CRDs (BreakglassSession,
//     BreakglassEscalation, ClusterConfig, IdentityProvider, MailProvider)
//
// NOTE: Subject Access Review (SAR) webhooks run on the API server (Gin), not here, and cannot
// be independently disabled. They run whenever enable-api is true.
func setupWebhooks(
	ctx context.Context,
	log *zap.SugaredLogger,
	scheme *runtime.Scheme,
	webhookBindAddr string,
	webhookCertPath string,
	webhookCertName string,
	webhookCertKey string,
	webhooksMetricsAddr string,
	webhooksMetricsSecure bool,
	webhooksMetricsCertPath string,
	webhooksMetricsCertName string,
	webhooksMetricsCertKey string,
	enableValidatingWebhooks bool,
	enableHTTP2 bool,
) {
	go func() {
		log.Debugw("Starting webhook server setup")

		// Parse webhook bind address to extract host and port
		// webhookBindAddr should be in format "host:port" (e.g., "0.0.0.0:9443")
		webhookHost := "0.0.0.0"
		webhookPort := 9443
		if parts := strings.Split(webhookBindAddr, ":"); len(parts) == 2 {
			webhookHost = parts[0]
			if port, err := strconv.Atoi(parts[1]); err == nil {
				webhookPort = port
				log.Debugw("Parsed webhook bind address", "bindAddress", webhookBindAddr, "host", webhookHost, "port", webhookPort)
			} else {
				log.Warnw("Failed to parse webhook port from bind address; using default", "bindAddress", webhookBindAddr, "defaultPort", 9443, "error", err)
			}
		}

		// Webhook server configuration
		webhookServerOptions := webhookserver.Options{
			Host: webhookHost,
			Port: webhookPort,
		}
		if len(webhookCertPath) > 0 {
			log.Infow("Initializing webhook certificate watcher using provided certificates",
				"webhook-cert-path", webhookCertPath, "webhook-cert-name", webhookCertName,
				"webhook-cert-key", webhookCertKey)
			webhookServerOptions.CertDir = webhookCertPath
			webhookServerOptions.CertName = webhookCertName
			webhookServerOptions.KeyName = webhookCertKey
		} else {
			log.Infow("No webhook certificate path provided; controller-runtime will auto-generate self-signed certificates")
		}
		webhookServer := webhookserver.NewServer(webhookServerOptions)

		// Configure separate metrics server for webhooks (if specified)
		// This allows running webhook-only instances with their own metrics endpoint
		var metricsServerOptions metricsserver.Options
		if webhooksMetricsAddr != "" {
			log.Infow("Configuring separate metrics server for webhooks",
				"address", webhooksMetricsAddr, "secure", webhooksMetricsSecure)

			tlsOpts := []func(*tls.Config){}
			if !enableHTTP2 {
				tlsOpts = append(tlsOpts, disableHTTP2)
			}

			metricsServerOptions = metricsserver.Options{
				BindAddress:   webhooksMetricsAddr,
				SecureServing: webhooksMetricsSecure,
				TLSOpts:       tlsOpts,
			}

			if len(webhooksMetricsCertPath) > 0 {
				log.Infow("Initializing webhook metrics certificate watcher using provided certificates",
					"webhooks-metrics-cert-path", webhooksMetricsCertPath, "webhooks-metrics-cert-name", webhooksMetricsCertName,
					"webhooks-metrics-cert-key", webhooksMetricsCertKey)
				metricsServerOptions.CertDir = webhooksMetricsCertPath
				metricsServerOptions.CertName = webhooksMetricsCertName
				metricsServerOptions.KeyName = webhooksMetricsCertKey
			}
		} else {
			log.Infow("Webhook metrics will use default metrics endpoint; to use separate metrics, set --webhooks-metrics-bind-address")
			metricsServerOptions = metricsserver.Options{
				BindAddress: "0",
			}
		}

		// Create a manager for webhooks (separate from reconciler manager)
		mgr, merr := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{
			Scheme:           scheme,
			WebhookServer:    webhookServer,
			Metrics:          metricsServerOptions,
			LeaderElection:   false,
			LeaderElectionID: "",
		})
		if merr != nil {
			log.Warnw("Failed to start webhook server; webhooks will not be registered", "error", merr)
			return
		}
		log.Infow("Webhook server created successfully")

		registerCommonFieldIndexes(ctx, mgr.GetFieldIndexer(), log)

		// Register health check handlers for the webhook manager
		if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
			log.Warnw("Failed to add webhook healthz check", "error", err)
		}
		if err := mgr.AddReadyzCheck("ping", healthz.Ping); err != nil {
			log.Warnw("Failed to add webhook readyz check", "error", err)
		}
		log.Infow("Webhook health check handlers registered")

		// Register validating webhooks (conditionally based on enableValidatingWebhooks)
		if enableValidatingWebhooks {
			log.Debugw("Starting webhook registration for BreakglassSession")
			if err := (&v1alpha1.BreakglassSession{}).SetupWebhookWithManager(mgr); err != nil {
				log.Warnw("Failed to setup BreakglassSession webhook with manager", "error", err)
				return
			}
			log.Infow("Successfully registered BreakglassSession webhook")

			log.Debugw("Starting webhook registration for BreakglassEscalation")
			if err := (&v1alpha1.BreakglassEscalation{}).SetupWebhookWithManager(mgr); err != nil {
				log.Warnw("Failed to setup BreakglassEscalation webhook with manager", "error", err)
				return
			}
			log.Infow("Successfully registered BreakglassEscalation webhook")

			log.Debugw("Starting webhook registration for ClusterConfig")
			if err := (&v1alpha1.ClusterConfig{}).SetupWebhookWithManager(mgr); err != nil {
				log.Warnw("Failed to setup ClusterConfig webhook with manager", "error", err)
				return
			}
			log.Infow("Successfully registered ClusterConfig webhook")

			log.Debugw("Starting webhook registration for IdentityProvider")
			if err := (&v1alpha1.IdentityProvider{}).SetupWebhookWithManager(mgr); err != nil {
				log.Warnw("Failed to setup IdentityProvider webhook with manager", "error", err)
				return
			}
			log.Infow("Successfully registered IdentityProvider webhook")

			log.Debugw("Starting webhook registration for MailProvider")
			if err := (&v1alpha1.MailProvider{}).SetupWebhookWithManager(mgr); err != nil {
				log.Warnw("Failed to setup MailProvider webhook with manager", "error", err)
				return
			}
			log.Infow("Successfully registered MailProvider webhook")
		} else {
			log.Infow("Validating webhooks disabled via --enable-validating-webhooks=false")
		}

		// Start webhook server (blocks) but we run it in a goroutine so it doesn't prevent the API server
		log.Infow("Starting webhook manager", "bindAddress", webhookBindAddr)

		// Start the manager in a blocking call that will also handle cache synchronization
		if err := mgr.Start(ctx); err != nil {
			log.Errorw("webhook server failed to start or exited with error", "error", err, "errorType", fmt.Sprintf("%T", err))
		} else {
			log.Infow("webhook server exited normally (this should not happen during normal operation)")
		}
	}()
}

// registerCommonFieldIndexes configures the field indices required by both the
// reconcilers and validating webhooks. These indices allow cache-backed
// lookups for frequently queried fields (e.g., spec.cluster) and enable
// metadata.name selectors for cluster-wide uniqueness checks.
func registerCommonFieldIndexes(ctx context.Context, idx client.FieldIndexer, log *zap.SugaredLogger) {
	if idx == nil {
		log.Warnw("Field indexer not available from manager")
		return
	}
	if ctx == nil {
		ctx = context.Background()
	}

	register := func(field string, fn func() error) {
		if err := fn(); err != nil {
			log.Errorw("Failed to register field index", "field", field, "error", err, "errorType", fmt.Sprintf("%T", err))
		} else {
			log.Debugw("Registered field index", "field", field)
		}
	}

	register("BreakglassSession.spec.cluster", func() error {
		return idx.IndexField(ctx, &v1alpha1.BreakglassSession{}, "spec.cluster", func(rawObj client.Object) []string {
			if bs, ok := rawObj.(*v1alpha1.BreakglassSession); ok && bs.Spec.Cluster != "" {
				return []string{bs.Spec.Cluster}
			}
			return nil
		})
	})

	register("BreakglassSession.spec.user", func() error {
		return idx.IndexField(ctx, &v1alpha1.BreakglassSession{}, "spec.user", func(rawObj client.Object) []string {
			if bs, ok := rawObj.(*v1alpha1.BreakglassSession); ok && bs.Spec.User != "" {
				return []string{bs.Spec.User}
			}
			return nil
		})
	})

	register("BreakglassSession.spec.grantedGroup", func() error {
		return idx.IndexField(ctx, &v1alpha1.BreakglassSession{}, "spec.grantedGroup", func(rawObj client.Object) []string {
			if bs, ok := rawObj.(*v1alpha1.BreakglassSession); ok && bs.Spec.GrantedGroup != "" {
				return []string{bs.Spec.GrantedGroup}
			}
			return nil
		})
	})

	register("BreakglassSession.metadata.name", func() error {
		return idx.IndexField(ctx, &v1alpha1.BreakglassSession{}, "metadata.name", func(rawObj client.Object) []string {
			if bs, ok := rawObj.(*v1alpha1.BreakglassSession); ok && bs.Name != "" {
				return []string{bs.Name}
			}
			return nil
		})
	})

	register("BreakglassEscalation.spec.allowed.cluster", func() error {
		return idx.IndexField(ctx, &v1alpha1.BreakglassEscalation{}, "spec.allowed.cluster", func(rawObj client.Object) []string {
			be, ok := rawObj.(*v1alpha1.BreakglassEscalation)
			if !ok || be == nil {
				return nil
			}
			out := make([]string, 0, len(be.Spec.Allowed.Clusters)+len(be.Spec.ClusterConfigRefs))
			out = append(out, be.Spec.Allowed.Clusters...)
			out = append(out, be.Spec.ClusterConfigRefs...)
			return out
		})
	})

	register("BreakglassEscalation.spec.allowed.group", func() error {
		return idx.IndexField(ctx, &v1alpha1.BreakglassEscalation{}, "spec.allowed.group", func(rawObj client.Object) []string {
			if be, ok := rawObj.(*v1alpha1.BreakglassEscalation); ok && be != nil {
				return be.Spec.Allowed.Groups
			}
			return nil
		})
	})

	register("BreakglassEscalation.spec.escalatedGroup", func() error {
		return idx.IndexField(ctx, &v1alpha1.BreakglassEscalation{}, "spec.escalatedGroup", func(rawObj client.Object) []string {
			if be, ok := rawObj.(*v1alpha1.BreakglassEscalation); ok && be != nil && be.Spec.EscalatedGroup != "" {
				return []string{be.Spec.EscalatedGroup}
			}
			return nil
		})
	})

	register("BreakglassEscalation.metadata.name", func() error {
		return idx.IndexField(ctx, &v1alpha1.BreakglassEscalation{}, "metadata.name", func(rawObj client.Object) []string {
			if be, ok := rawObj.(*v1alpha1.BreakglassEscalation); ok && be != nil && be.Name != "" {
				return []string{be.Name}
			}
			return nil
		})
	})

	register("ClusterConfig.metadata.name", func() error {
		return idx.IndexField(ctx, &v1alpha1.ClusterConfig{}, "metadata.name", func(rawObj client.Object) []string {
			if cc, ok := rawObj.(*v1alpha1.ClusterConfig); ok && cc != nil && cc.Name != "" {
				return []string{cc.Name}
			}
			return nil
		})
	})

	register("ClusterConfig.spec.clusterID", func() error {
		return idx.IndexField(ctx, &v1alpha1.ClusterConfig{}, "spec.clusterID", func(rawObj client.Object) []string {
			if cc, ok := rawObj.(*v1alpha1.ClusterConfig); ok && cc != nil && cc.Spec.ClusterID != "" {
				return []string{cc.Spec.ClusterID}
			}
			return nil
		})
	})
}
