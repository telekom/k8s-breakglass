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

func main() {
	debug := true
	flag.BoolVar(&debug, "debug", false, "enable debug level logging")
	flag.Parse()

	zl := setupLogger(debug)
	// Ensure controller-runtime uses our zap logger to avoid its default stacktrace output
	zaprLogger := zapr.NewLogger(zl)
	ctrl.SetLogger(zaprLogger)

	log := zl.Sugar()
	log.With("version", system.Version).Info("Starting breakglass api")

	cfg, err := config.Load()
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

	sessionController := breakglass.NewBreakglassSessionController(log, cfg, &sessionManager, &escalationManager, auth.Middleware(), ccProvider, escalationManager.Client).WithQueue(mailQueue)

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
	podNs := os.Getenv("POD_NAMESPACE")
	if podNs == "" {
		podNs = "default"
	}
	recorder := &breakglass.K8sEventRecorder{Clientset: kubeClientset, Source: corev1.EventSource{Component: "breakglass-controller"}, Namespace: podNs, Logger: log}

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
	enableWebhookMgr := os.Getenv("ENABLE_WEBHOOK_MANAGER")
	go func() {
		// Reuse the unified scheme for consistency across all Kubernetes clients
		log.Debugw("Starting manager with unified scheme")

		// Configure webhook port (default 8443, can be overridden via WEBHOOK_PORT env var)
		webhookPort := 9443
		if wPort := os.Getenv("WEBHOOK_PORT"); wPort != "" {
			if p, err := strconv.Atoi(wPort); err == nil {
				webhookPort = p
				log.Infow("Using custom webhook port", "port", webhookPort)
			} else {
				log.Warnw("Invalid WEBHOOK_PORT value, using default", "value", wPort, "default", webhookPort)
			}
		}

		log.Debugw("Configuring webhook server options", "port", webhookPort, "webhooksEnabled", (enableWebhookMgr == "" || enableWebhookMgr == "true"))

		mgrOpts := ctrl.Options{
			Scheme: scheme,
		}

		// Set webhook port if webhooks are enabled
		if enableWebhookMgr == "" || enableWebhookMgr == "true" {
			log.Debugw("Creating webhook server", "port", webhookPort)
			mgrOpts.WebhookServer = ctrlwebhook.NewServer(ctrlwebhook.Options{
				Port: webhookPort,
			})
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
		log.Infow("Controller-runtime manager created successfully", "webhookEnabled", (enableWebhookMgr == "" || enableWebhookMgr == "true"))

		// Setup certificate rotation for webhook TLS certificates using cert-controller
		setupFinished := make(chan struct{})
		certRotatorEnabled := os.Getenv("ENABLE_CERT_ROTATION")
		podNamespace := os.Getenv("POD_NAMESPACE")
		if podNamespace == "" {
			podNamespace = "system"
		}
		webhookSecretName := os.Getenv("WEBHOOK_SECRET_NAME")
		if webhookSecretName == "" {
			webhookSecretName = "webhook-certs"
		}

		log.Debugw("Certificate rotation configuration", "enabled", (certRotatorEnabled == "" || certRotatorEnabled == "true"), "namespace", podNamespace, "secretName", webhookSecretName)

		if certRotatorEnabled == "" || certRotatorEnabled == "true" {
			log.Infow("Setting up certificate rotation for webhooks", "namespace", podNamespace, "secretName", webhookSecretName, "webhookName", "breakglass-webhook")
			if _, err := cert.SetupRotator(mgr, "breakglass-webhook", false, setupFinished); err != nil {
				log.Fatalf("Failed to setup certificate rotation - controller cannot proceed without webhook certificates: %v", err)
			} else {
				log.Debugw("Certificate rotator setup successful, waiting for certificates to be ready", "timeout", "60s")
				// Wait for certs to be ready with a timeout to prevent hanging forever
				ticker := time.NewTicker(10 * time.Second)
				defer ticker.Stop()
				timeout := time.After(60 * time.Second)
				certReady := false

				for !certReady {
					select {
					case <-setupFinished:
						log.Infow("Webhook certificates ready and loaded")
						certReady = true
					case <-ticker.C:
						log.Debugw("Still waiting for webhook certificates to be generated...")
					case <-timeout:
						log.Fatalf("Timeout waiting for webhook certificates after 60s - certificate generation failed or stalled, controller cannot proceed without webhooks. Check if webhook-certs secret exists and cert-rotator logs for errors")
					}
				}
			}
		} else {
			log.Infow("Certificate rotation disabled via ENABLE_CERT_ROTATION env var - webhooks will not be available")
			close(setupFinished)
		}

		// Register field indices to support efficient cache-based lookups by controller-runtime clients.
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

		// Conditionally register webhooks (can be disabled via ENABLE_WEBHOOK_MANAGER env var)
		if enableWebhookMgr == "" || enableWebhookMgr == "true" {
			log.Debugw("Starting webhook registration for BreakglassSession")
			if err := (&v1alpha1.BreakglassSession{}).SetupWebhookWithManager(mgr); err != nil {
				log.Errorw("Failed to setup BreakglassSession webhook with manager", "error", err, "errorType", fmt.Sprintf("%T", err))
				return
			}
			log.Infow("Successfully registered BreakglassSession webhook")

			log.Debugw("Starting webhook registration for BreakglassEscalation")
			if err := (&v1alpha1.BreakglassEscalation{}).SetupWebhookWithManager(mgr); err != nil {
				log.Errorw("Failed to setup BreakglassEscalation webhook with manager", "error", err, "errorType", fmt.Sprintf("%T", err))
				return
			}
			log.Infow("Successfully registered BreakglassEscalation webhook")

			log.Debugw("Starting webhook registration for ClusterConfig")
			if err := (&v1alpha1.ClusterConfig{}).SetupWebhookWithManager(mgr); err != nil {
				log.Errorw("Failed to setup ClusterConfig webhook with manager", "error", err, "errorType", fmt.Sprintf("%T", err))
				return
			}
			log.Infow("Successfully registered ClusterConfig webhook")

			log.Debugw("Starting webhook registration for IdentityProvider")
			if err := (&v1alpha1.IdentityProvider{}).SetupWebhookWithManager(mgr); err != nil {
				log.Errorw("Failed to setup IdentityProvider webhook with manager", "error", err, "errorType", fmt.Sprintf("%T", err))
				return
			}
			log.Infow("Successfully registered IdentityProvider webhook")
			log.Infow("All webhooks registered successfully", "count", 4, "webhooks", "BreakglassSession,BreakglassEscalation,ClusterConfig,IdentityProvider")
		} else {
			log.Infow("Webhook registration disabled via ENABLE_WEBHOOK_MANAGER env var", "value", enableWebhookMgr)
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

		// Start manager (blocks) but we run it in a goroutine so it doesn't prevent the API server
		log.Infow("Starting controller-runtime manager", "port", webhookPort, "certRotationEnabled", (certRotatorEnabled == "" || certRotatorEnabled == "true"))
		if err := mgr.Start(ctx); err != nil {
			log.Warnw("controller-runtime manager exited", "error", err)
		}
	}()

	// If webhooks are disabled, log it
	if enableWebhookMgr == "false" {
		log.Infow("Webhook manager disabled via ENABLE_WEBHOOK_MANAGER", "value", enableWebhookMgr)
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
