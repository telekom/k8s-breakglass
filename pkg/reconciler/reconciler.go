package reconciler

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	"github.com/telekom/k8s-breakglass/pkg/api"
	"github.com/telekom/k8s-breakglass/pkg/cli"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/indexer"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func NewManager(
	restCfg *rest.Config,
	scheme *runtime.Scheme,
	metricsAddr string,
	metricsSecure bool,
	metricsCertPath string,
	metricsCertName string,
	metricsCertKey string,
	probeAddr string,
	enableHTTP2 bool,
	log *zap.SugaredLogger,
) (ctrl.Manager, error) {
	tlsOpts := []func(*tls.Config){}
	if !enableHTTP2 {
		tlsOpts = append(tlsOpts, cli.DisableHTTP2)
	}

	metricsServerOptions := metricsserver.Options{
		BindAddress:   metricsAddr,
		SecureServing: metricsSecure,
		TLSOpts:       tlsOpts,
	}

	if len(metricsCertPath) > 0 {
		log.Infow("Initializing metrics certificate watcher using provided certificates",
			"metrics-cert-path", metricsCertPath, "metrics-cert-name", metricsCertName,
			"metrics-cert-key", metricsCertKey)
		metricsServerOptions.CertDir = metricsCertPath
		metricsServerOptions.CertName = metricsCertName
		metricsServerOptions.KeyName = metricsCertKey
	}

	return ctrl.NewManager(restCfg, ctrl.Options{
		Scheme:                 scheme,
		Metrics:                metricsServerOptions,
		HealthProbeBindAddress: probeAddr,
		WebhookServer:          nil,
		LeaderElection:         false,
	})
}

// Setup starts the controller-runtime manager with field indices and IdentityProvider reconciler.
// This function handles:
// - Metrics server configuration with secure serving
// - Field index setup for efficient queries
// - IdentityProvider reconciler setup
// - Manager startup and leader election
// - Broadcasting leadership signal to background loops when acquired
func Setup(
	ctx context.Context,
	mgr ctrl.Manager,
	idpLoader *config.IdentityProviderLoader,
	server *api.Server,
	log *zap.SugaredLogger,
) error {
	// Register health check handlers for liveness and readiness probes
	// These endpoints are exposed at the health probe bind address (default :8082)
	if err := mgr.AddHealthzCheck("ping", healthz.Ping); err != nil {
		return fmt.Errorf("failed to add healthz check to reconciler manager: %w", err)
	}
	if err := mgr.AddReadyzCheck("ping", healthz.Ping); err != nil {
		return fmt.Errorf("failed to add readyz check to reconciler manager: %w", err)
	}
	log.Info("Health check handlers registered")

	if err := indexer.RegisterCommonFieldIndexes(ctx, mgr.GetFieldIndexer(), log); err != nil {
		return fmt.Errorf("failed to register common field indexes: %w", err)
	}

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
		return fmt.Errorf("failed to setup IdentityProvider reconciler with manager: %w", err)
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
		return fmt.Errorf("failed to setup BreakglassEscalation reconciler with manager: %w", err)
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
		return fmt.Errorf("controller-runtime reconciler manager exited: %w", err)
	}

	return nil
}
