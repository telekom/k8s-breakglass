package main

import (
	"context"
	"flag"
	stdlog "log"
	"os"
	"time"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"

	"github.com/go-logr/zapr"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/kubernetes"

	v1alpha1 "github.com/telekom/das-schiff-breakglass/api/v1alpha1"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"

	"github.com/telekom/das-schiff-breakglass/pkg/api"
	"github.com/telekom/das-schiff-breakglass/pkg/breakglass"
	"github.com/telekom/das-schiff-breakglass/pkg/cluster"
	"github.com/telekom/das-schiff-breakglass/pkg/config"
	"github.com/telekom/das-schiff-breakglass/pkg/policy"
	"github.com/telekom/das-schiff-breakglass/pkg/system"
	"github.com/telekom/das-schiff-breakglass/pkg/webhook"
)

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

	config, err := config.Load()
	if err != nil {
		log.Fatalf("Error loading config for breakglass controller: %v", err)
	}

	if debug {
		log.Infof("%#v", config)
	}

	auth := api.NewAuth(log, config)
	server := api.NewServer(log.Desugar(), config, debug, auth)

	kubeContext := config.Kubernetes.Context
	sessionManager, err := breakglass.NewSessionManager(kubeContext)
	if err != nil {
		log.Fatalf("Error creating breakglass session manager: %v", err)
		return
	}
	var resolver breakglass.GroupMemberResolver
	if !config.Keycloak.Disable && config.Keycloak.BaseURL != "" && config.Keycloak.Realm != "" && config.Keycloak.ClientID != "" {
		resolver = breakglass.NewKeycloakGroupMemberResolver(log, config.Keycloak)
		log.Infow("Keycloak group sync enabled", "baseURL", config.Keycloak.BaseURL, "realm", config.Keycloak.Realm)
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

	err = server.RegisterAll([]api.APIController{
		breakglass.NewBreakglassSessionController(log, config, &sessionManager, &escalationManager, auth.Middleware(), ccProvider, escalationManager.Client),
		breakglass.NewBreakglassEscalationController(log, &escalationManager, auth.Middleware()),
		webhook.NewWebhookController(log, config, &sessionManager, &escalationManager, ccProvider, denyEval),
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
	cfg := ctrl.GetConfigOrDie()
	kubeClientset, err := kubernetes.NewForConfig(cfg)
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
	if config.Kubernetes.ClusterConfigCheckInterval != "" {
		if d, err := time.ParseDuration(config.Kubernetes.ClusterConfigCheckInterval); err == nil {
			interval = d
		} else {
			log.Warnw("Invalid clusterConfigCheckInterval in config; using default 10m", "value", config.Kubernetes.ClusterConfigCheckInterval, "error", err)
		}
	}

	// ClusterConfig checker: validates that referenced kubeconfig secrets contain the expected key
	go breakglass.ClusterConfigChecker{Log: log, Client: escalationManager.Client, Recorder: recorder, Interval: interval}.Start(ctx)

	// Optionally start a controller-runtime manager to register webhooks (non-blocking).
	// Control via ENABLE_WEBHOOK_MANAGER env var (default: true).
	enableMgr := os.Getenv("ENABLE_WEBHOOK_MANAGER")
	if enableMgr == "" || enableMgr == "true" {
		go func() {
			mgr, merr := ctrl.NewManager(ctrl.GetConfigOrDie(), ctrl.Options{})
			if merr != nil {
				log.Warnw("Failed to start controller-runtime manager; webhooks will not be registered", "error", merr)
				return
			}
			// Register BreakglassSession, BreakglassEscalation and ClusterConfig webhooks with manager
			// Also register field indices to support efficient cache-based lookups by controller-runtime clients.
			// Index fields: spec.cluster, spec.user, spec.grantedGroup
			idx := mgr.GetFieldIndexer()
			if idx != nil {
				if err := idx.IndexField(ctx, &v1alpha1.BreakglassSession{}, "spec.cluster", func(rawObj client.Object) []string {
					bs := rawObj.(*v1alpha1.BreakglassSession)
					return []string{bs.Spec.Cluster}
				}); err != nil {
					log.Warnw("Failed to index BreakglassSession.spec.cluster", "error", err)
				}
				if err := idx.IndexField(ctx, &v1alpha1.BreakglassSession{}, "spec.user", func(rawObj client.Object) []string {
					bs := rawObj.(*v1alpha1.BreakglassSession)
					return []string{bs.Spec.User}
				}); err != nil {
					log.Warnw("Failed to index BreakglassSession.spec.user", "error", err)
				}
				if err := idx.IndexField(ctx, &v1alpha1.BreakglassSession{}, "spec.grantedGroup", func(rawObj client.Object) []string {
					bs := rawObj.(*v1alpha1.BreakglassSession)
					return []string{bs.Spec.GrantedGroup}
				}); err != nil {
					log.Warnw("Failed to index BreakglassSession.spec.grantedGroup", "error", err)
				}

				// Index BreakglassEscalation helpful fields for quick lookups
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
					log.Warnw("Failed to index BreakglassEscalation.spec.allowed.cluster/clusterConfigRefs", "error", err)
				}

				if err := idx.IndexField(ctx, &v1alpha1.BreakglassEscalation{}, "spec.allowed.group", func(rawObj client.Object) []string {
					be := rawObj.(*v1alpha1.BreakglassEscalation)
					if be == nil {
						return nil
					}
					return be.Spec.Allowed.Groups
				}); err != nil {
					log.Warnw("Failed to index BreakglassEscalation.spec.allowed.group", "error", err)
				}

				if err := idx.IndexField(ctx, &v1alpha1.BreakglassEscalation{}, "spec.escalatedGroup", func(rawObj client.Object) []string {
					be := rawObj.(*v1alpha1.BreakglassEscalation)
					if be == nil || be.Spec.EscalatedGroup == "" {
						return nil
					}
					return []string{be.Spec.EscalatedGroup}
				}); err != nil {
					log.Warnw("Failed to index BreakglassEscalation.spec.escalatedGroup", "error", err)
				}

				// Index ClusterConfig by metadata.name and spec.clusterID for fast lookup by name
				if err := idx.IndexField(ctx, &v1alpha1.ClusterConfig{}, "metadata.name", func(rawObj client.Object) []string {
					cc := rawObj.(*v1alpha1.ClusterConfig)
					if cc == nil {
						return nil
					}
					return []string{cc.Name}
				}); err != nil {
					log.Warnw("Failed to index ClusterConfig.metadata.name", "error", err)
				}

				if err := idx.IndexField(ctx, &v1alpha1.ClusterConfig{}, "spec.clusterID", func(rawObj client.Object) []string {
					cc := rawObj.(*v1alpha1.ClusterConfig)
					if cc == nil || cc.Spec.ClusterID == "" {
						return nil
					}
					return []string{cc.Spec.ClusterID}
				}); err != nil {
					log.Warnw("Failed to index ClusterConfig.spec.clusterID", "error", err)
				}
			}

			// Register webhooks
			if err := (&v1alpha1.BreakglassSession{}).SetupWebhookWithManager(mgr); err != nil {
				log.Warnw("Failed to setup BreakglassSession webhook with manager", "error", err)
				return
			}
			if err := (&v1alpha1.BreakglassEscalation{}).SetupWebhookWithManager(mgr); err != nil {
				log.Warnw("Failed to setup BreakglassEscalation webhook with manager", "error", err)
				return
			}
			if err := (&v1alpha1.ClusterConfig{}).SetupWebhookWithManager(mgr); err != nil {
				log.Warnw("Failed to setup ClusterConfig webhook with manager", "error", err)
				return
			}
			// Start manager (blocks) but we run it in a goroutine so it doesn't prevent the API server
			if err := mgr.Start(ctx); err != nil {
				log.Warnw("controller-runtime manager exited", "error", err)
			}
		}()
	} else {
		log.Infow("Webhook manager disabled via ENABLE_WEBHOOK_MANAGER", "value", enableMgr)
	}

	server.Listen()
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
