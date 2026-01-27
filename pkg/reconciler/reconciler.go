package reconciler

import (
	"context"
	"crypto/tls"
	"fmt"
	"time"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/api"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/breakglass"
	"github.com/telekom/k8s-breakglass/pkg/cli"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"github.com/telekom/k8s-breakglass/pkg/config"
	"github.com/telekom/k8s-breakglass/pkg/indexer"
	"github.com/telekom/k8s-breakglass/pkg/mail"
	"github.com/telekom/k8s-breakglass/pkg/metrics"
	"github.com/telekom/k8s-breakglass/pkg/utils"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/rest"
	ctrl "sigs.k8s.io/controller-runtime"
	crclient "sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

func boolPtr(val bool) *bool {
	return &val
}

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
		Client: crclient.Options{
			FieldOwner:      utils.FieldOwnerController,
			FieldValidation: metav1.FieldValidationWarn,
		},
		Controller: ctrlconfig.Controller{
			EnableWarmup:          boolPtr(true),
			UsePriorityQueue:      boolPtr(true),
			ReconciliationTimeout: 5 * time.Minute,
		},
	})
}

// Setup starts the controller-runtime manager with field indices and IdentityProvider reconciler.
// This function handles:
// - Metrics server configuration with secure serving
// - Field index setup for efficient queries
// - IdentityProvider reconciler setup
// - MailProvider reconciler setup with mail service hot-reload
// - DebugSession reconciler setup
// - AuditConfig reconciler setup with audit service wiring
// - Manager startup and leader election
// - Broadcasting leadership signal to background loops when acquired
func Setup(
	ctx context.Context,
	mgr ctrl.Manager,
	idpLoader *config.IdentityProviderLoader,
	server *api.Server,
	ccProvider *cluster.ClientProvider,
	auditService *audit.Service,
	mailService *mail.Service,
	escalationManager *breakglass.EscalationManager,
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

	// Assert that all expected indexes are registered
	if err := indexer.AssertIndexesRegistered(log); err != nil {
		return fmt.Errorf("index registration assertion failed: %w", err)
	}

	// Register IdentityProvider Reconciler with controller-runtime manager
	log.Debugw("Setting up IdentityProvider reconciler")
	idpReconciler := config.NewIdentityProviderReconciler(
		mgr.GetClient(),
		log,
		func(reloadCtx context.Context) error {
			// Reload the IdentityProvider configuration in the API server
			if err := server.ReloadIdentityProvider(idpLoader); err != nil {
				return err
			}

			// Also update the EscalationManager's resolver to use the new Keycloak config
			// This ensures group member resolution uses the latest IdentityProvider settings
			if escalationManager != nil {
				idpConfig, loadErr := idpLoader.LoadIdentityProvider(reloadCtx)
				if loadErr != nil {
					log.Warnw("Failed to load IdentityProvider config for resolver update", "error", loadErr)
					// Don't fail the reload - the API server was updated successfully
					// The resolver will continue using its current (possibly stale) config
					return nil
				}
				newResolver := breakglass.SetupResolver(idpConfig, log)
				escalationManager.SetResolver(newResolver)
				log.Infow("Updated EscalationManager resolver after IdentityProvider change")
			}

			return nil
		},
	)
	idpReconciler.WithErrorHandler(func(ctx context.Context, err error) {
		log.Errorw("IdentityProvider reconciliation error", "error", err)
		metrics.IdentityProviderLoadFailed.WithLabelValues("reconciler_error").Inc()
	})
	idpReconciler.WithEventRecorder(mgr.GetEventRecorder("breakglass-controller"))
	idpReconciler.WithResyncPeriod(10 * time.Minute)

	// Set reconciler in API server so it can use the cached IDPs
	// This prevents the API from querying the Kubernetes APIServer on every /api/config/idps request
	server.SetIdentityProviderReconciler(idpReconciler)

	if err := idpReconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("failed to setup IdentityProvider reconciler with manager: %w", err)
	}
	log.Infow("Successfully registered IdentityProvider reconciler", "resyncPeriod", "10m")

	// Register MailProvider Reconciler with controller-runtime manager
	log.Debugw("Setting up MailProvider reconciler")
	mailProviderReconciler := &config.MailProviderReconciler{
		Client: mgr.GetClient(),
		Scheme: mgr.GetScheme(),
		Log:    log.Named("mail-provider-reconciler"),
		Loader: config.NewMailProviderLoader(mgr.GetClient()).WithLogger(log),
		OnMailProviderChange: func(providerName string) {
			log.Infow("MailProvider changed, reloading mail service", "provider", providerName)
			if mailService != nil {
				if err := mailService.Reload(context.Background()); err != nil {
					log.Warnw("Failed to reload mail service after MailProvider change", "error", err)
				}
			}
		},
	}
	if err := mailProviderReconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("failed to setup MailProvider reconciler with manager: %w", err)
	}
	log.Infow("Successfully registered MailProvider reconciler")

	// Register BreakglassEscalation Reconciler with controller-runtime manager
	log.Debugw("Setting up BreakglassEscalation reconciler")
	escalationReconciler := config.NewEscalationReconciler(
		mgr.GetClient(),
		log,
		mgr.GetEventRecorder("breakglass-escalation-controller"),
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

	// Register DenyPolicy Reconciler with controller-runtime manager
	log.Debugw("Setting up DenyPolicy reconciler")
	denyPolicyReconciler := config.NewDenyPolicyReconciler(mgr.GetClient(), log)
	if err := denyPolicyReconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("failed to setup DenyPolicy reconciler with manager: %w", err)
	}
	log.Infow("Successfully registered DenyPolicy reconciler")

	// Register DebugSessionTemplate Reconciler with controller-runtime manager
	log.Debugw("Setting up DebugSessionTemplate reconciler")
	debugSessionTemplateReconciler := config.NewDebugSessionTemplateReconciler(mgr.GetClient(), log)
	if err := debugSessionTemplateReconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("failed to setup DebugSessionTemplate reconciler with manager: %w", err)
	}
	log.Infow("Successfully registered DebugSessionTemplate reconciler")

	// Register DebugPodTemplate Reconciler with controller-runtime manager
	log.Debugw("Setting up DebugPodTemplate reconciler")
	debugPodTemplateReconciler := config.NewDebugPodTemplateReconciler(mgr.GetClient(), log)
	if err := debugPodTemplateReconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("failed to setup DebugPodTemplate reconciler with manager: %w", err)
	}
	log.Infow("Successfully registered DebugPodTemplate reconciler")

	// Register DebugSessionClusterBinding Reconciler with controller-runtime manager
	log.Debugw("Setting up DebugSessionClusterBinding reconciler")
	clusterBindingReconciler := config.NewDebugSessionClusterBindingReconciler(mgr.GetClient(), log)
	if err := clusterBindingReconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("failed to setup DebugSessionClusterBinding reconciler with manager: %w", err)
	}
	log.Infow("Successfully registered DebugSessionClusterBinding reconciler")

	// Register DebugSession Reconciler with controller-runtime manager
	log.Debugw("Setting up DebugSession reconciler")
	debugSessionReconciler := breakglass.NewDebugSessionController(log, mgr.GetClient(), ccProvider)
	if err := debugSessionReconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("failed to setup DebugSession reconciler with manager: %w", err)
	}
	log.Infow("Successfully registered DebugSession reconciler")

	// Register AuditConfig Reconciler with controller-runtime manager
	log.Debugw("Setting up AuditConfig reconciler")
	auditConfigReconciler := config.NewAuditConfigReconciler(
		mgr.GetClient(),
		log,
		mgr.GetEventRecorder("breakglass-audit-controller"),
		func(ctx context.Context, auditConfigs []*breakglassv1alpha1.AuditConfig) error {
			// Reload audit service with aggregated configuration from all AuditConfigs
			if auditService == nil {
				log.Warnw("AuditConfig changed but audit service is nil - skipping reload")
				return nil
			}
			if err := auditService.ReloadMultiple(ctx, auditConfigs); err != nil {
				log.Errorw("Failed to reload audit service", "error", err)
				return err
			}
			if len(auditConfigs) == 0 {
				log.Infow("No enabled AuditConfigs found - audit logging stopped")
			} else {
				var names []string
				totalSinks := 0
				for _, cfg := range auditConfigs {
					names = append(names, cfg.Name)
					totalSinks += len(cfg.Spec.Sinks)
				}
				log.Infow("AuditConfigs reloaded (aggregated)", "configs", names, "totalSinks", totalSinks)
			}
			return nil
		},
		func(ctx context.Context, err error) {
			log.Errorw("AuditConfig reconciliation error", "error", err)
			metrics.AuditConfigReloads.WithLabelValues("reconciler_error").Inc()
		},
		10*time.Minute,
	)

	// Set up sink health provider to report circuit breaker status
	if auditService != nil {
		auditConfigReconciler.SetSinkHealthProvider(func() []config.SinkHealthInfo {
			sinkHealth := auditService.GetSinkHealth()
			result := make([]config.SinkHealthInfo, len(sinkHealth))
			for i, h := range sinkHealth {
				result[i] = config.SinkHealthInfo{
					Name:                h.Name,
					Ready:               h.Healthy,
					CircuitState:        h.CircuitState,
					ConsecutiveFailures: h.ConsecutiveFailures,
					LastError:           h.LastError,
				}
			}
			return result
		})

		// Set up stats provider to report event processing metrics
		auditConfigReconciler.SetStatsProvider(func() *config.AuditStats {
			stats := auditService.GetStats()
			if stats == nil {
				return nil
			}
			return &config.AuditStats{
				ProcessedEvents: stats.ProcessedEvents,
				DroppedEvents:   stats.DroppedEvents,
			}
		})
	}

	if err := auditConfigReconciler.SetupWithManager(mgr); err != nil {
		return fmt.Errorf("failed to setup AuditConfig reconciler with manager: %w", err)
	}
	log.Infow("Successfully registered AuditConfig reconciler", "resyncPeriod", "10m")

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
