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

	ctrl "sigs.k8s.io/controller-runtime"

	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/api"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/breakglass"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/cluster"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/config"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/policy"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/system"
	"gitlab.devops.telekom.de/schiff/engine/go-breakglass.git/pkg/webhook"
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
	recorder := &breakglass.K8sEventRecorder{Clientset: kubeClientset, Source: corev1.EventSource{Component: "breakglass-controller"}, Namespace: podNs}

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
