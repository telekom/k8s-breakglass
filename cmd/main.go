package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/go-logr/zapr"
	"go.uber.org/zap"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes"
	typedcorev1 "k8s.io/client-go/kubernetes/typed/core/v1"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/tools/record"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/telekom/k8s-breakglass/pkg/api"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/breakglass/clusterconfig"
	"github.com/telekom/k8s-breakglass/pkg/breakglass/debug"
	"github.com/telekom/k8s-breakglass/pkg/breakglass/escalation"
	"github.com/telekom/k8s-breakglass/pkg/breakglass/eventrecorder"
	"github.com/telekom/k8s-breakglass/pkg/cert"
	"github.com/telekom/k8s-breakglass/pkg/cli"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/leaderelection"
	"github.com/telekom/k8s-breakglass/pkg/mail"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"github.com/telekom/k8s-breakglass/pkg/policy"
	"github.com/telekom/k8s-breakglass/pkg/ratelimit"
	"github.com/telekom/k8s-breakglass/pkg/reconciler"
	"github.com/telekom/k8s-breakglass/pkg/system"
	"github.com/telekom/k8s-breakglass/pkg/telemetry"
	"github.com/telekom/k8s-breakglass/pkg/utils"
	"github.com/telekom/k8s-breakglass/pkg/webhook"
)

// RBAC markers for resources managed by non-reconciler components (cleanup, API handlers, etc.)
// These are collected here so `make manifests` generates the complete RBAC role.

// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=breakglasssessions,verbs=get;list;watch;create;update;patch;delete;deletecollection
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=breakglasssessions/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=breakglasssessions/finalizers,verbs=update
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=clusterconfigs,verbs=get;list;watch
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=clusterconfigs/status,verbs=get;update;patch
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=denypolicies,verbs=get;list;watch
// +kubebuilder:rbac:groups=breakglass.t-caas.telekom.com,resources=denypolicies/status,verbs=get
// +kubebuilder:rbac:groups="",resources=namespaces,verbs=get;list;watch
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch;create;update;patch;delete
// NOTE: Impersonate permissions (users, groups) and selfsubjectaccessreviews are in a separate
// handwritten role (config/rbac/impersonate_role.yaml) because they may need different binding
// patterns for hub vs spoke cluster deployments.

func main() {
	if err := run(); err != nil {
		fmt.Fprintf(os.Stderr, "fatal: %v\n", err)
		os.Exit(1)
	}
}

// run contains all controller startup logic so that errors bubble up to a single
// exit point in main(), the logic is testable without os.Exit, and resource cleanup
// is possible via defer.
//
// DEPLOYMENT PATTERNS
// ===================
// The breakglass controller supports multiple deployment patterns via component enable flags:
//
// 1. MONOLITHIC (default):
//
//	All components run in a single instance. Use defaults or:
//	breakglass-controller
//
// 2. WEBHOOK-ONLY INSTANCE (validating webhooks only):
//
//	Runs only Kubernetes validating webhooks (CRD validation) with separate metrics.
//	breakglass-controller \
//	  --enable-frontend=false \
//	  --enable-api=false \
//	  --enable-cleanup=false \
//	  --webhooks-metrics-bind-address=0.0.0.0:8083
//
// 3. API-ONLY INSTANCE (frontend, REST API, SAR webhook):
//
//	Runs API endpoints (Session/Escalation), web UI, and SAR authorization webhook.
//	breakglass-controller \
//	  --enable-webhooks=false \
//	  --enable-cleanup=false
//
// 4. FRONTEND-ONLY INSTANCE:
//
//	Runs only the frontend web UI without webhooks, API, or SAR.
//	breakglass-controller \
//	  --enable-api=false \
//	  --enable-webhooks=false \
//	  --enable-cleanup=false
//
// 5. CLEANUP-ONLY INSTANCE:
//
//	Runs only the background cleanup routine for expired sessions.
//	breakglass-controller \
//	  --enable-frontend=false \
//	  --enable-api=false \
//	  --enable-webhooks=false
//
// COMPONENT ARCHITECTURE
// ======================
//
//	Frontend/API/SAR:      Gin HTTP server (port 8080) - runs if enable-frontend or enable-api
//	Validating Webhooks:   controller-runtime webhook server (port 9443) - runs if enable-webhooks
//	Cleanup Routine:       background goroutine - runs if enable-cleanup
//
// METRICS
// =======
// All breakglass metrics are registered with controller-runtime's registry and exposed on port 8081:
//
//	Unified metrics:  0.0.0.0:8081/metrics  (all breakglass + controller-runtime metrics)
//	Health probe:     0.0.0.0:8082          (health checks)
//
// ENVIRONMENT VARIABLES
// =====================
// All flags can be set via environment variables with UPPERCASE_SNAKE_CASE names:
//
//	ENABLE_FRONTEND=true          # Web UI
//	ENABLE_API=true               # REST API and SAR webhook
//	ENABLE_CLEANUP=true           # Background cleanup
//	ENABLE_WEBHOOKS=true          # Validating webhooks (CRD validation)
//	ENABLE_VALIDATING_WEBHOOKS=true  # Which validating webhooks to register
func run() error {
	cliConfig := cli.Parse()

	// Setup logging with zap
	zapLogger, err := utils.SetupLogger(cliConfig.Debug)
	if err != nil {
		return fmt.Errorf("setup logger: %w", err)
	}

	// Replace the global zap logger so that any code still using zap.S() or zap.L()
	// (e.g. standalone utility functions, webhook validators) logs through the
	// configured logger instead of the default no-op.
	zap.ReplaceGlobals(zapLogger)

	defer func() {
		_ = zapLogger.Sync()
	}()

	ctrl.SetLogger(zapr.NewLogger(zapLogger))

	log := zapLogger.Sugar()
	log.Infow("Starting breakglass controller", "version", system.Version)

	if cliConfig.Debug {
		log.Debug("Debug logging enabled")
	}

	// Log all startup configuration flags for debuggability
	cliConfig.Print(log)

	// Load configuration from config.yaml
	cfg, err := config.Load(cliConfig.ConfigPath)
	if err != nil {
		return fmt.Errorf("load config for breakglass controller: %w", err)
	}

	if cliConfig.Debug {
		log.Infow("Configuration loaded (redacted)",
			"configPath", cliConfig.ConfigPath,
			"enableFrontend", cliConfig.EnableFrontend,
			"enableAPI", cliConfig.EnableAPI,
			"enableWebhooks", cliConfig.EnableWebhooks,
			"enableCleanup", cliConfig.EnableCleanup,
			"frontendBaseURL", cfg.Frontend.BaseURL,
			"trustedProxies", len(cfg.Server.TrustedProxies))
	}

	// Setup authentication
	auth := api.NewAuth(log, cfg)

	// Initialise OpenTelemetry tracing.
	// CLI flags override config-file values; disabled by default.
	otelExporter := resolveStringConfig(cliConfig.OTelExporter, cfg.Telemetry.Exporter, "otlp")
	otelEndpoint := resolveStringConfig(cliConfig.OTelEndpoint, cfg.Telemetry.Endpoint, "localhost:4317")
	// Sampling rate uses -1 as sentinel for "not explicitly set" because 0.0 is a
	// valid value (disable sampling). See resolveOTelSamplingRate.
	otelSamplingRate := resolveOTelSamplingRate(cliConfig.OTelSamplingRate, cfg.Telemetry.SamplingRate, 1.0)
	initCtx, initCancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer initCancel()
	_, otelShutdown, err := telemetry.Init(initCtx, telemetry.Options{
		Enabled:        cliConfig.OTelEnabled || cfg.Telemetry.Enabled,
		ServiceName:    "k8s-breakglass",
		ServiceVersion: system.Version,
		Exporter:       otelExporter,
		Endpoint:       otelEndpoint,
		Insecure:       cliConfig.OTelInsecure || cfg.Telemetry.Insecure,
		SamplingRate:   otelSamplingRate,
		Logger:         log,
	})
	if err != nil {
		log.Warnw("OpenTelemetry initialization failed, tracing disabled", "error", err)
		otelShutdown = func(context.Context) error { return nil }
	}

	server := api.NewServer(zapLogger, cfg, cliConfig.Debug, auth)

	// Create a unified scheme with all CRDs registered
	scheme, err := utils.CreateScheme()
	if err != nil {
		return fmt.Errorf("create scheme: %w", err)
	}
	log.Debugw("Scheme initialized with CRDs", "types", "corev1, BreakglassSession, BreakglassEscalation, ClusterConfig, IdentityProvider, MailProvider, DenyPolicy")

	restConfig, err := ctrl.GetConfig()
	if err != nil {
		return fmt.Errorf("get kubernetes config: %w", err)
	}

	uncachedClient, err := client.New(restConfig, client.Options{
		Scheme:          scheme,
		FieldOwner:      utils.FieldOwnerController,
		FieldValidation: metav1.FieldValidationWarn,
	})
	if err != nil {
		return fmt.Errorf("create uncached kubernetes client: %w", err)
	}

	reconcilerMgr, err := reconciler.NewManager(restConfig, scheme, cliConfig.MetricsAddr, cliConfig.MetricsSecure,
		cliConfig.MetricsCertPath, cliConfig.MetricsCertName, cliConfig.MetricsCertKey, cliConfig.ProbeAddr, cliConfig.EnableHTTP2, log)
	if err != nil {
		return fmt.Errorf("create controller-runtime manager: %w", err)
	}

	svcs, err := setupServices(context.Background(), cliConfig, cfg, reconcilerMgr, uncachedClient, scheme, zapLogger, auth, server)
	if err != nil {
		return err
	}

	// Make IdentityProvider available to API server for frontend configuration
	if svcs.idpConfig != nil {
		server.SetIdentityProvider(svcs.idpConfig)
		log.Infow("identity_provider_set_on_api_server", "type", svcs.idpConfig.Type)
	}

	// Both frontend and API share the same HTTP server, so we check both flags
	shouldEnableHTTPServer := cliConfig.EnableFrontend || cliConfig.EnableAPI

	if shouldEnableHTTPServer {
		err = server.RegisterAll(svcs.apiControllers)
		if err != nil {
			return fmt.Errorf("register breakglass controllers: %w", err)
		}
	} else {
		log.Infow("HTTP server disabled: both --enable-frontend and --enable-api are false")
	}

	// Add signal handler for graceful shutdown
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	// Get hostname (typically the pod name in Kubernetes) for event source
	hostname, err := os.Hostname()
	if err != nil {
		log.Warnw("Failed to get hostname for event source, using empty string", "error", err)
		hostname = ""
	}

	kubeClientset, eventsRecorder, err := createEventRecorder(restConfig, scheme, hostname, cliConfig.PodNamespace, log)
	if err != nil {
		return fmt.Errorf("create event recorder: %w", err)
	}

	resourceLock, leaderBroadcaster, err := createLeaderElectionLock(
		kubeClientset, scheme, hostname, cliConfig, log)
	if err != nil {
		return err
	}
	defer leaderBroadcaster.Shutdown()

	// Create channels for leader election signal and background error propagation
	leaderElectedCh := make(chan struct{})
	errCh := make(chan error, 4) // buffer matches sender count: background, cert-manager, webhook-server, reconciler

	var wg sync.WaitGroup
	managerCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	startBackgroundRoutines(managerCtx, &wg, errCh, leaderElectedCh, &backgroundDeps{
		cliConfig:         cliConfig,
		cfg:               cfg,
		log:               log,
		sessionManager:    svcs.sessionManager,
		escalationManager: svcs.escalationManager,
		reconcilerMgr:     reconcilerMgr,
		mailService:       svcs.mailService,
		auditService:      svcs.auditService,
		ccProvider:        svcs.ccProvider,
		idpLoader:         svcs.idpLoader,
		eventsRecorder:    eventsRecorder,
		server:            server,
		scheme:            scheme,
		resourceLock:      resourceLock,
		hostname:          hostname,
		webhookCtrl:       svcs.webhookCtrl,
	})

	// Optionally setup webhooks if enabled (webhooks are optional, reconcilers are not)
	certMgrErr := make(chan error, 1) // buffered so non-blocking send in startCertManagerIfNeeded is reliable
	if cliConfig.EnableWebhooks {
		log.Infow("Webhooks enabled via --enable-webhooks flag")
		certsReady := startCertManagerIfNeeded(managerCtx, &wg, errCh, certMgrErr, leaderElectedCh,
			cliConfig, scheme, log)
		if cliConfig.Webhook.CertGeneration {
			if err := cert.Ensure(cliConfig.Webhook.CertPath, cliConfig.Webhook.CertName, certsReady, certMgrErr, log); err != nil {
				return fmt.Errorf("ensure webhook certificates: %w", err)
			}
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := webhook.Setup(managerCtx, log, scheme, &cliConfig.Webhook, cliConfig.EnableValidatingWebhooks,
				cliConfig.EnableHTTP2, cliConfig.Webhook.CertGeneration); err != nil {
				errCh <- fmt.Errorf("webhook server failed: %w", err)
			}
		}()
	} else {
		log.Infow("Webhooks disabled via --enable-webhooks flag")
	}

	// Start HTTP server if either frontend or API is enabled
	if shouldEnableHTTPServer {
		go func() { server.Listen() }()
	}

	runErr := awaitShutdownSignal(sigChan, errCh, log)

	shutdownServices(cfg, server, svcs.mailService, svcs.auditService, svcs.webhookCtrl, shouldEnableHTTPServer, otelShutdown, log)

	cancel()
	log.Info("Waiting for all goroutines to finish")
	wg.Wait()
	log.Info("Breakglass controller shutdown complete")

	return runErr
}

// services holds the runtime services created during initialization.
type services struct {
	idpLoader         *config.IdentityProviderLoader
	idpConfig         *config.IdentityProviderConfig // may be nil if IDP load fails
	escalationManager *escalation.EscalationManager
	sessionManager    *breakglass.SessionManager
	ccProvider        *cluster.ClientProvider
	mailService       *mail.Service
	auditService      *audit.Service
	apiControllers    []api.APIController
	webhookCtrl       *webhook.WebhookController
}

// setupServices builds the business-logic services: IDP, escalation manager, session
// manager, cluster provider, deny-policy evaluator, mail, audit, and API controllers.
func setupServices(ctx context.Context, cliConfig *cli.Config, cfg config.Config,
	reconcilerMgr ctrl.Manager, uncachedClient client.Client, scheme *runtime.Scheme,
	zapLogger *zap.Logger, auth *api.AuthHandler, server *api.Server,
) (*services, error) {
	log := zapLogger.Sugar()

	idpLoader, err := config.DefaultIdentityProviderLoader(ctx, uncachedClient, scheme, log)
	if err != nil {
		return nil, fmt.Errorf("create identity provider loader: %w", err)
	}

	// Load primary IdentityProvider (non-fatal: group sync is disabled on error)
	idpConfig, err := idpLoader.LoadIdentityProvider(ctx)
	if err != nil {
		log.Warnf("Failed to load IdentityProvider: %v; group sync disabled", err)
		metrics.IdentityProviderLoadFailed.WithLabelValues("load_error").Inc()
		idpConfig = nil
	}

	resolver := escalation.SetupResolver(idpConfig, log)

	// Cached config loader avoids disk reads per request
	cfgLoader := config.NewCachedLoader(cliConfig.ConfigPath, 5*time.Second)
	escalationManager := escalation.NewEscalationManagerWithClient(
		reconcilerMgr.GetClient(), resolver, escalation.WithLogger(log), escalation.WithConfigLoader(cfgLoader))

	// Build shared cluster config provider & deny policy evaluator reusing kubernetes client
	ccProvider := cluster.NewClientProvider(escalationManager.Client, log)
	denyEval := policy.NewEvaluator(escalationManager.Client, log)

	// Create mail service with hot-reload capability
	mailService := mail.NewService(uncachedClient, cfg.Frontend.BrandingName, log)
	if err := mailService.Start(ctx); err != nil {
		log.Warnw("Mail service initialization failed - mail notifications disabled until MailProvider is created", "error", err)
	}

	// Create audit service for Kafka/webhook/log audit event emission
	auditService := audit.NewService(uncachedClient, zapLogger, cliConfig.BreakglassNamespace)

	// Enable multi-IDP support in auth handler for token verification
	auth.WithIdentityProviderLoader(idpLoader)

	sessionManager := breakglass.NewSessionManagerWithClientAndReader(
		reconcilerMgr.GetClient(), reconcilerMgr.GetAPIReader(),
		breakglass.WithSessionLogger(log.Named("session-manager")))

	// Authenticated rate limiter: 50 req/s per user, 10 req/s per IP (unauthenticated)
	apiRateLimiter := ratelimit.NewAuthenticated(ratelimit.DefaultAuthenticatedAPIConfig())
	authMiddleware := auth.MiddlewareWithRateLimiting(apiRateLimiter)

	// Setup session controller with all dependencies
	// Uses combined auth + rate limiting middleware
	sessionController := breakglass.NewBreakglassSessionController(log, cfg, &sessionManager, escalationManager,
		authMiddleware, cliConfig.ConfigPath, ccProvider, escalationManager.Client, cliConfig.DisableEmail).
		WithMailService(mailService).WithAuditService(auditService)

	// Setup debug session API controller with mail and audit services
	// Uses combined auth + rate limiting middleware
	// Uses APIReader for consistent reads after writes (avoids cache coherence issues)
	debugSessionAPICtrl := debug.NewDebugSessionAPIController(log, reconcilerMgr.GetClient(), ccProvider, authMiddleware).
		WithAPIReader(reconcilerMgr.GetAPIReader()).
		WithMailService(mailService, cfg.Frontend.BrandingName, cfg.Frontend.BaseURL).
		WithAuditService(auditService).
		WithDisableEmail(cliConfig.DisableEmail)

	// Note: ClusterBindingAPIController is not exposed as a public API endpoint.
	// Cluster bindings are aggregated internally through the template/clusters endpoint
	// (GET /api/debugSessions/templates/:name/clusters) for a unified user experience.

	// Register API controllers based on component flags
	apiControllers, webhookCtrl := api.Setup(sessionController, escalationManager, &sessionManager,
		cliConfig.EnableFrontend, cliConfig.EnableAPI, cliConfig.ConfigPath, auth,
		ccProvider, denyEval, &cfg, log, debugSessionAPICtrl, auditService)

	return &services{
		idpLoader:         idpLoader,
		idpConfig:         idpConfig,
		escalationManager: escalationManager,
		sessionManager:    &sessionManager,
		ccProvider:        ccProvider,
		mailService:       mailService,
		auditService:      auditService,
		apiControllers:    apiControllers,
		webhookCtrl:       webhookCtrl,
	}, nil
}

// createEventRecorder builds a Kubernetes clientset and event recorder for emitting
// Kubernetes events (persisted to API server).
func createEventRecorder(restConfig *rest.Config, scheme *runtime.Scheme,
	hostname, namespace string, log *zap.SugaredLogger,
) (*kubernetes.Clientset, *eventrecorder.K8sEventRecorder, error) {
	kubeClientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, nil, fmt.Errorf("create kubernetes clientset for event recorder: %w", err)
	}
	recorder := &eventrecorder.K8sEventRecorder{
		Clientset: kubeClientset,
		Source:    corev1.EventSource{Component: "breakglass-controller", Host: hostname},
		Scheme:    scheme,
		Namespace: namespace,
		Logger:    log,
	}
	return kubeClientset, recorder, nil
}

// createLeaderElectionLock sets up the leader election resource lock and event broadcaster.
// It returns the lock, broadcaster (caller must defer Shutdown), and any error.
func createLeaderElectionLock(kubeClientset kubernetes.Interface, scheme *runtime.Scheme,
	hostname string, cliConfig *cli.Config, log *zap.SugaredLogger,
) (resourcelock.Interface, record.EventBroadcaster, error) {
	leaseName := cliConfig.LeaderElectID
	leaseNamespace := cliConfig.LeaderElectNamespace
	if leaseNamespace == "" {
		leaseNamespace = cliConfig.PodNamespace
	}
	if leaseNamespace == "" {
		leaseNamespace = "default"
	}
	log.Infow("Creating leader election lease", "id", leaseName, "namespace", leaseNamespace)

	// hostname was already retrieved for event source - retry if it was empty (critical for leader election)
	if hostname == "" {
		var hostnameErr error
		hostname, hostnameErr = os.Hostname()
		if hostnameErr != nil {
			return nil, nil, fmt.Errorf("get hostname for leader election: %w", hostnameErr)
		}
	}

	broadcaster := record.NewBroadcaster()
	broadcaster.StartRecordingToSink(&typedcorev1.EventSinkImpl{Interface: kubeClientset.CoreV1().Events(leaseNamespace)})
	electionRecorder := broadcaster.NewRecorder(scheme, corev1.EventSource{Component: "breakglass-leader-election", Host: hostname})

	lock, err := resourcelock.New(
		"leases", leaseNamespace, leaseName,
		kubeClientset.CoreV1(), kubeClientset.CoordinationV1(),
		resourcelock.ResourceLockConfig{Identity: hostname, EventRecorder: electionRecorder},
	)
	if err != nil {
		broadcaster.Shutdown()
		return nil, nil, fmt.Errorf("create leader election resource lock: %w", err)
	}
	log.Infow("Leader election resource lock created", "id", leaseName, "namespace", leaseNamespace, "identity", hostname)
	return lock, broadcaster, nil
}

// backgroundDeps holds the dependencies needed by background goroutines.
type backgroundDeps struct {
	cliConfig         *cli.Config
	cfg               config.Config
	log               *zap.SugaredLogger
	sessionManager    *breakglass.SessionManager
	escalationManager *escalation.EscalationManager
	reconcilerMgr     ctrl.Manager
	mailService       *mail.Service
	auditService      *audit.Service
	ccProvider        *cluster.ClientProvider
	idpLoader         *config.IdentityProviderLoader
	eventsRecorder    *eventrecorder.K8sEventRecorder
	server            *api.Server
	scheme            *runtime.Scheme
	resourceLock      resourcelock.Interface
	hostname          string
	webhookCtrl       *webhook.WebhookController
}

// startBackgroundRoutines launches all leader-gated background goroutines: cleanup,
// cluster cache invalidation, escalation status updater, cluster config checker,
// leader election, and the reconciler manager.
func startBackgroundRoutines(ctx context.Context, wg *sync.WaitGroup, errCh chan<- error,
	leaderElectedCh chan struct{}, deps *backgroundDeps,
) {
	log := deps.log

	// Cleanup routine (optional)
	if deps.cliConfig.EnableCleanup {
		wg.Add(1)
		go func() {
			defer wg.Done()
			cr := breakglass.CleanupRoutine{
				Log:           log,
				Manager:       deps.sessionManager,
				LeaderElected: leaderElectedCh,
				MailService:   deps.mailService,
				BrandingName:  deps.cfg.Frontend.BrandingName,
				DisableEmail:  deps.cliConfig.DisableEmail,
			}
			// Plumb the activity tracker from the webhook controller so the
			// cleanup routine can prune orphaned entries.
			if at := deps.webhookCtrl.ActivityTrackerCleaner(); at != nil {
				cr.ActivityTracker = at
			}
			cr.CleanupRoutine(ctx)
		}()
		log.Infow("Cleanup routine enabled")
	} else {
		log.Infow("Cleanup routine disabled via --enable-cleanup=false")
	}

	if err := cluster.RegisterInvalidationHandlers(ctx, deps.reconcilerMgr, deps.ccProvider, log); err != nil {
		log.Warnw("Failed to register cluster cache invalidation handlers", "error", err)
	}

	// Escalation status updater with EventRecorder and IDPLoader
	wg.Add(1)
	go func() {
		defer wg.Done()
		escalation.EscalationStatusUpdater{
			Log:           log,
			K8sClient:     deps.escalationManager.Client,
			Resolver:      deps.escalationManager.GetResolver(),
			EventRecorder: deps.eventsRecorder,
			IDPLoader:     deps.idpLoader,
			Interval:      cli.ParseEscalationStatusUpdateInterval(deps.cliConfig.EscalationStatusUpdateInt, log),
			LeaderElected: leaderElectedCh,
		}.Start(ctx)
	}()

	// ClusterConfig checker: validates referenced kubeconfig secrets contain the expected key
	intervalStr := deps.cliConfig.ClusterConfigCheckInterval
	if intervalStr == "" && deps.cfg.Kubernetes.ClusterConfigCheckInterval != "" {
		intervalStr = deps.cfg.Kubernetes.ClusterConfigCheckInterval
	}
	interval := cli.ParseClusterConfigCheckInterval(intervalStr, log)
	wg.Add(1)
	go func() {
		defer wg.Done()
		clusterconfig.ClusterConfigChecker{
			Log: log, Client: deps.escalationManager.Client,
			Recorder: deps.eventsRecorder, Interval: interval, LeaderElected: leaderElectedCh,
		}.Start(ctx)
	}()

	// Leader election
	if deps.cliConfig.EnableLeaderElection {
		leaseNamespace := deps.cliConfig.LeaderElectNamespace
		if leaseNamespace == "" {
			leaseNamespace = deps.cliConfig.PodNamespace
		}
		if leaseNamespace == "" {
			leaseNamespace = "default"
		}
		wg.Add(1)
		go func() {
			leaderelection.Start(ctx, wg, &leaderElectedCh, deps.resourceLock,
				deps.hostname, deps.cliConfig.LeaderElectID, leaseNamespace, log)
		}()
	} else {
		log.Infow("Leader election disabled via --enable-leader-election=false, background loops will run on all replicas")
		close(leaderElectedCh)
	}

	// Reconciler manager (field indices and reconcilers always run)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := reconciler.Setup(ctx, deps.reconcilerMgr, deps.idpLoader, deps.server,
			deps.ccProvider, deps.auditService, deps.mailService, deps.escalationManager, log); err != nil {
			errCh <- fmt.Errorf("reconciler manager failed: %w", err)
		}
	}()
}

// startCertManagerIfNeeded launches the certificate manager goroutine when webhook
// certificate generation is enabled. Returns a certsReady channel (nil if not needed).
// certMgrErr is used to propagate start failures to cert.Ensure(), which blocks on it.
func startCertManagerIfNeeded(ctx context.Context, wg *sync.WaitGroup, errCh chan<- error,
	certMgrErr chan<- error, leaderElectedCh chan struct{}, cliConfig *cli.Config,
	scheme *runtime.Scheme, log *zap.SugaredLogger,
) chan struct{} {
	if !cliConfig.Webhook.CertGeneration {
		return nil
	}
	certsReady := make(chan struct{})
	certMgr := cert.NewManager(cliConfig.Webhook.SvcName, cliConfig.BreakglassNamespace,
		cliConfig.Webhook.CertPath, cliConfig.Webhook.ValidatingConfigName, certsReady, leaderElectedCh, log)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := certMgr.Start(ctx, scheme); err != nil {
			wrapped := fmt.Errorf("certificate manager failed: %w", err)
			// Notify cert.Ensure() via certMgrErr so it returns the real error
			// instead of succeeding against stale cert files. certMgrErr is
			// buffered(1) so this never blocks even if Ensure() hasn't started.
			certMgrErr <- wrapped
			errCh <- wrapped
		}
	}()
	return certsReady
}

// awaitShutdownSignal blocks until a termination signal or background error is received.
// Returns nil on clean signal, or the error from a failed background component.
func awaitShutdownSignal(sigChan <-chan os.Signal, errCh <-chan error, log *zap.SugaredLogger) error {
	select {
	case <-sigChan:
		log.Info("Received shutdown signal, initiating graceful shutdown")
		return nil
	case err := <-errCh:
		log.Errorf("background component failed, shutting down: %s", err.Error())
		return err
	}
}

// shutdownServices performs graceful shutdown of HTTP server, mail, audit, and activity tracker.
func shutdownServices(cfg config.Config, server *api.Server, mailService *mail.Service,
	auditService *audit.Service, webhookCtrl *webhook.WebhookController, httpEnabled bool,
	otelShutdown func(context.Context) error, log *zap.SugaredLogger,
) {
	// Create shutdown context with timeout for graceful shutdown of all components
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), cfg.Server.GetShutdownTimeout())
	defer shutdownCancel()

	// Gracefully shutdown HTTP server first to stop accepting new requests
	// and allow in-flight API/webhook calls to complete
	if httpEnabled {
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Warnw("HTTP server graceful shutdown error", "error", err)
		}
	}

	// Close rate limiters and other server resources
	server.Close()

	// Shutdown OpenTelemetry tracing (flush pending spans)
	if otelShutdown != nil {
		if err := otelShutdown(shutdownCtx); err != nil {
			log.Warnw("OpenTelemetry shutdown error", "error", err)
		} else {
			log.Infow("OpenTelemetry tracing shut down successfully")
		}
	}

	// Shutdown mail service
	if mailService != nil {
		if err := mailService.Stop(shutdownCtx); err != nil {
			log.Warnw("Mail service shutdown error", "error", err)
		} else {
			log.Info("Mail service shut down successfully")
		}
	}

	// Shutdown audit service (flushes pending events to Kafka)
	if auditService != nil {
		if err := auditService.Close(); err != nil {
			log.Warnw("Audit service shutdown error", "error", err)
		} else {
			log.Info("Audit service shut down successfully")
		}
	}

	// Stop activity tracker (flushes remaining session activity entries)
	webhookCtrl.StopActivityTracker(shutdownCtx)
}

// resolveStringConfig returns the first non-empty value in precedence order:
// CLI flag, config-file, hard-coded default.
func resolveStringConfig(cliValue, configValue, defaultValue string) string {
	if cliValue != "" {
		return cliValue
	}
	if configValue != "" {
		return configValue
	}
	return defaultValue
}

// resolveOTelSamplingRate resolves the trace sampling rate. The CLI flag uses
// -1 as a sentinel for "not explicitly set" so that an explicit
// --otel-sampling-rate=0 (disable all sampling) is not confused with "unset".
// The config-file field is a *float64 so the YAML decoder can distinguish an
// absent field (nil) from an explicit zero ("samplingRate: 0").
func resolveOTelSamplingRate(cliValue float64, configValue *float64, defaultValue float64) float64 {
	if cliValue >= 0 {
		return cliValue
	}
	if configValue != nil {
		return *configValue
	}
	return defaultValue
}
