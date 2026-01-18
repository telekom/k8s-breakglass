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
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/leaderelection/resourcelock"
	"k8s.io/client-go/tools/record"

	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/telekom/k8s-breakglass/pkg/api"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
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
// +kubebuilder:rbac:groups="",resources=configmaps,verbs=get;list;watch;create;update;patch;delete
// +kubebuilder:rbac:groups=coordination.k8s.io,resources=leases,verbs=get;list;watch;create;update;patch;delete

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
	// METRICS
	// =======
	// All breakglass metrics are registered with controller-runtime's registry and exposed on port 8081:
	//
	//   Unified metrics:  0.0.0.0:8081/metrics  (all breakglass + controller-runtime metrics)
	//   Health probe:     0.0.0.0:8082          (health checks)
	//
	// ENVIRONMENT VARIABLES
	// =====================
	// All flags can be set via environment variables with UPPERCASE_SNAKE_CASE names:
	//   ENABLE_FRONTEND=true          # Web UI
	//   ENABLE_API=true               # REST API and SAR webhook
	//   ENABLE_CLEANUP=true           # Background cleanup
	//   ENABLE_WEBHOOKS=true          # Validating webhooks (CRD validation)
	//   ENABLE_VALIDATING_WEBHOOKS=true  # Which validating webhooks to register
	//

	cliConfig := cli.Parse()

	// Setup logging with zap
	var zapLogger *zap.Logger
	var err error

	if zapLogger, err = utils.SetupLogger(cliConfig.Debug); err != nil {
		panic(fmt.Errorf("failed to setup logger: %w", err))
	}

	defer func() {
		_ = zapLogger.Sync()
	}()

	ctrl.SetLogger(zapr.NewLogger(zapLogger))

	log := zapLogger.Sugar()
	log.Infof("Starting breakglass controller (version: %s)", system.Version)

	if cliConfig.Debug {
		log.Debug("Debug logging enabled")
	}

	// Log all startup configuration flags for debuggability
	cliConfig.Print(log)

	// Load configuration from config.yaml
	cfg, err := config.Load(cliConfig.ConfigPath)
	if err != nil {
		log.Fatalf("Error loading config for breakglass controller: %v", err)
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
	server := api.NewServer(zapLogger, cfg, cliConfig.Debug, auth)

	// Create a unified scheme with all CRDs registered
	scheme, err := utils.CreateScheme()
	if err != nil {
		log.Fatalf("failed to create scheme: %v", err)
	}
	log.Debugw("Scheme initialized with CRDs", "types", "corev1, BreakglassSession, BreakglassEscalation, ClusterConfig, IdentityProvider, MailProvider, DenyPolicy")

	restConfig, err := ctrl.GetConfig()
	if err != nil {
		log.Fatalf("Error getting Kubernetes config: %v", err)
	}

	uncachedClient, err := client.New(restConfig, client.Options{Scheme: scheme})
	if err != nil {
		log.Fatalf("Failed to create uncached Kubernetes client: %v", err)
	}

	reconcilerMgr, err := reconciler.NewManager(restConfig, scheme, cliConfig.MetricsAddr, cliConfig.MetricsSecure,
		cliConfig.MetricsCertPath, cliConfig.MetricsCertName, cliConfig.MetricsCertKey, cliConfig.ProbeAddr, cliConfig.EnableHTTP2, log)
	if err != nil {
		log.Fatalf("Failed to create controller-runtime manager: %v", err)
	}

	ctx := context.Background()
	idpLoader, err := config.DefaultIdentityProviderLoader(ctx, uncachedClient, scheme, log)
	if err != nil {
		log.Fatal(err)
	}

	// Load primary IdentityProvider to check for Keycloak group sync
	idpConfig, err := idpLoader.LoadIdentityProvider(ctx)
	if err != nil {
		log.Warnf("Failed to load IdentityProvider: %v; group sync disabled", err)
		metrics.IdentityProviderLoadFailed.WithLabelValues("load_error").Inc()
		idpConfig = nil
	}

	resolver := breakglass.SetupResolver(idpConfig, log)

	// Create cached config loader to avoid disk reads per request
	cfgLoader := config.NewCachedLoader(cliConfig.ConfigPath, 5*time.Second)

	escalationManager := breakglass.NewEscalationManagerWithClient(reconcilerMgr.GetClient(), resolver, log, cfgLoader)

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
	// This allows the backend to verify tokens from any configured IDP, not just the default one
	auth.WithIdentityProviderLoader(idpLoader)

	sessionManager := breakglass.NewSessionManagerWithClientAndReader(reconcilerMgr.GetClient(), reconcilerMgr.GetAPIReader())

	// Create authenticated rate limiter for API endpoints
	// Authenticated users get 50 req/s (per user), unauthenticated get 10 req/s (per IP)
	apiRateLimiter := ratelimit.NewAuthenticated(ratelimit.DefaultAuthenticatedAPIConfig())

	// Setup session controller with all dependencies
	// Uses combined auth + rate limiting middleware
	sessionController := breakglass.NewBreakglassSessionController(log, cfg, &sessionManager, escalationManager,
		auth.MiddlewareWithRateLimiting(apiRateLimiter), cliConfig.ConfigPath, ccProvider, escalationManager.Client, cliConfig.DisableEmail).WithMailService(mailService).WithAuditService(auditService)

	// Setup debug session API controller with mail and audit services
	// Uses combined auth + rate limiting middleware
	debugSessionAPICtrl := breakglass.NewDebugSessionAPIController(log, reconcilerMgr.GetClient(), ccProvider, auth.MiddlewareWithRateLimiting(apiRateLimiter)).
		WithMailService(mailService, cfg.Frontend.BrandingName, cfg.Frontend.BaseURL).
		WithAuditService(auditService).
		WithDisableEmail(cliConfig.DisableEmail)

	// Register API controllers based on component flags
	apiControllers := api.Setup(sessionController, escalationManager, &sessionManager, cliConfig.EnableFrontend,
		cliConfig.EnableAPI, cliConfig.ConfigPath, auth, ccProvider, denyEval, &cfg, log, debugSessionAPICtrl, auditService)

	// Make IdentityProvider available to API server for frontend configuration
	if idpConfig != nil {
		server.SetIdentityProvider(idpConfig)
		log.Infow("identity_provider_set_on_api_server", "type", idpConfig.Type)
	}

	// Both frontend and API share the same HTTP server, so we check both flags
	shouldEnableHTTPServer := cliConfig.EnableFrontend || cliConfig.EnableAPI

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

	var wg sync.WaitGroup

	// Escalation approver group expansion updater (Keycloak read-only sync)
	managerCtx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Background routines (cleanup routine is optional)
	if cliConfig.EnableCleanup {
		wg.Add(1)
		go func() {
			defer wg.Done()
			breakglass.CleanupRoutine{
				Log:           log,
				Manager:       &sessionManager,
				LeaderElected: leaderElectedCh,
				MailService:   mailService,
				BrandingName:  cfg.Frontend.BrandingName,
				DisableEmail:  cliConfig.DisableEmail,
			}.CleanupRoutine(managerCtx)
		}()
		log.Infow("Cleanup routine enabled")
	} else {
		log.Infow("Cleanup routine disabled via --enable-cleanup=false")
	}

	if err := cluster.RegisterInvalidationHandlers(managerCtx, reconcilerMgr, ccProvider, log); err != nil {
		log.Warnw("Failed to register cluster cache invalidation handlers", "error", err)
	}

	// Event recorder for emitting Kubernetes events (persisted to API server)
	kubeClientset, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		log.Fatalf("failed to create kubernetes clientset for event recorder: %v", err)
	}

	// Now create the leader election resourcelock using the kubeClientset
	eventBroadcaster := record.NewBroadcaster()
	eventRecorder := eventBroadcaster.NewRecorder(scheme, corev1.EventSource{Component: "breakglass-controller"})

	// Start the escalation status updater with EventRecorder and IDPLoader so it can:
	// - Emit events when IDP group sync fails (surfaced via kubectl describe identityprovider)
	// - Fetch group members from multiple IDPs for status.groupSyncErrors and status.IDPGroupMemberships
	wg.Add(1)
	go func() {
		defer wg.Done()
		breakglass.EscalationStatusUpdater{
			Log:           log,
			K8sClient:     escalationManager.Client,
			Resolver:      escalationManager.GetResolver(),
			EventRecorder: eventRecorder,
			IDPLoader:     idpLoader,
			Interval:      cli.ParseEscalationStatusUpdateInterval(cliConfig.EscalationStatusUpdateInt, log),
			LeaderElected: leaderElectedCh,
		}.Start(managerCtx)
	}()

	// Determine the namespace for the lease
	// If not specified via flag, use the pod's namespace from the environment
	leaseName := cliConfig.LeaderElectID
	leaseNamespace := cliConfig.LeaderElectNamespace
	if leaseNamespace == "" {
		leaseNamespace = cliConfig.PodNamespace
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
	resourceLock, err := resourcelock.New(
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

	recorder := &breakglass.K8sEventRecorder{Clientset: kubeClientset, Source: corev1.EventSource{Component: "breakglass-controller"}, Namespace: cliConfig.PodNamespace, Logger: log}

	// Determine interval from CLI flag first, then config (fallback to 10m)
	intervalStr := cliConfig.ClusterConfigCheckInterval
	if intervalStr == "" && cfg.Kubernetes.ClusterConfigCheckInterval != "" {
		intervalStr = cfg.Kubernetes.ClusterConfigCheckInterval
	}
	interval := cli.ParseClusterConfigCheckInterval(intervalStr, log)

	// ClusterConfig checker: validates that referenced kubeconfig secrets contain the expected key
	wg.Add(1)
	go func() {
		defer wg.Done()
		breakglass.ClusterConfigChecker{Log: log, Client: escalationManager.Client, Recorder: recorder, Interval: interval, LeaderElected: leaderElectedCh}.Start(managerCtx)
	}()

	var certsReady chan struct{}
	certMgrErr := make(chan error)
	defer close(certMgrErr)

	if cliConfig.EnableWebhooks && cliConfig.Webhook.CertGeneration {
		certsReady = make(chan struct{})
		certMgr := cert.NewManager(cliConfig.Webhook.SvcName, cliConfig.BreakglassNamespace, cliConfig.Webhook.CertPath,
			cliConfig.Webhook.ValidatingConfigName, certsReady, leaderElectedCh, log)
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := certMgr.Start(managerCtx, scheme); err != nil {
				// log.Errorw("certificate manager failed", "err", err)
				certMgrErr <- err
			}
		}()
	}

	// Start leader election if enabled
	// This coordinates background loops (cleanup, escalation updater, cluster config checker)
	// to run only on the leader replica using the resourcelock
	if cliConfig.EnableLeaderElection {
		wg.Add(1)
		go func() {
			leaderelection.Start(managerCtx, &wg, &leaderElectedCh, resourceLock, hostname, leaseName, leaseNamespace, log)
		}()
	} else {
		// If leader election is disabled, immediately signal that we're the leader
		// This allows background loops to run on all replicas
		log.Infow("Leader election disabled via --enable-leader-election=false, background loops will run on all replicas")
		close(leaderElectedCh)
	}

	// Always start the reconciler manager (field indices and reconcilers always run)
	// The manager does NOT do leader election; background loops handle that
	recMgrErr := make(chan error)
	wg.Add(1)
	go func() {
		defer wg.Done()
		if err := reconciler.Setup(managerCtx, reconcilerMgr, idpLoader, server, ccProvider, auditService, mailService, escalationManager, log); err != nil {
			recMgrErr <- err
		}
	}()

	// Optionally setup webhooks if enabled (webhooks are optional, reconcilers are not)
	webhookErr := make(chan error)
	defer close(webhookErr)

	if cliConfig.EnableWebhooks {
		log.Infow("Webhooks enabled via --enable-webhooks flag")
		if cliConfig.Webhook.CertGeneration {
			if err := cert.Ensure(cliConfig.Webhook.CertPath, cliConfig.Webhook.CertName, certsReady, certMgrErr, log); err != nil {
				log.Fatal(err)
			}
		}
		wg.Add(1)
		go func() {
			defer wg.Done()
			if err := webhook.Setup(managerCtx, log, scheme, &cliConfig.Webhook, cliConfig.EnableValidatingWebhooks,
				cliConfig.EnableHTTP2, cliConfig.Webhook.CertGeneration); err != nil {
				webhookErr <- err
			}
		}()
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
	select {
	case <-sigChan:
		log.Info("Received shutdown signal, initiating graceful shutdown")
	case err := <-webhookErr:
		log.Errorf("webhook server failed, shutting down: %s", err.Error())
	case err := <-recMgrErr:
		log.Errorf("reconciler manager failed, shutting down: %s", err.Error())
	}

	// Create shutdown context with timeout for graceful shutdown of all components
	shutdownCtx, shutdownCancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer shutdownCancel()

	// Gracefully shutdown HTTP server first to stop accepting new requests
	// and allow in-flight API/webhook calls to complete
	if shouldEnableHTTPServer {
		if err := server.Shutdown(shutdownCtx); err != nil {
			log.Warnw("HTTP server graceful shutdown error", "error", err)
		}
	}

	// Close rate limiters and other server resources
	server.Close()

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

	cancel()
	log.Info("Waiting for all goroutines to finish")
	wg.Wait()
	log.Info("Breakglass controller shutdown complete")
}
