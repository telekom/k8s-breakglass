package cert

import (
	"context"
	"encoding/pem"
	"fmt"
	"os"
	"path"
	"time"

	"github.com/open-policy-agent/cert-controller/pkg/rotator"
	"github.com/telekom/k8s-breakglass/pkg/utils"
	"go.uber.org/zap"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
)

// +kubebuilder:rbac:groups="",resources=secrets,verbs=get;list;watch;create;update
// +kubebuilder:rbac:groups=admissionregistration.k8s.io,resources=mutatingwebhookconfigurations;validatingwebhookconfigurations,verbs=get;list;watch;update

const (
	DefaultWebhookPath = "/tmp/k8s-webhook-server/serving-certs"
	DefaultTLSCertFile = "tls.crt"
	DefaultTLSKeyFile  = "tls.key"

	DefaultValidatingWebhookConfigurationName = "breakglass-validating-webhook-configuration"
)

type Manager struct {
	name                               string
	namespace                          string
	path                               string
	validatingWebhookConfigurationName string
	certsReady                         chan struct{}
	leaderElected                      <-chan struct{}
	log                                *zap.SugaredLogger
	managerFactory                     func(*runtime.Scheme) (ctrl.Manager, error)
	rotatorAdder                       func(ctrl.Manager, *rotator.CertRotator) error
}

func NewManager(name, namespace, path, validatingWebhookConfigurationName string,
	certsReady chan struct{}, leaderElected <-chan struct{}, log *zap.SugaredLogger) *Manager {
	if path == "" {
		path = DefaultWebhookPath
	}

	if validatingWebhookConfigurationName == "" {
		validatingWebhookConfigurationName = DefaultValidatingWebhookConfigurationName
	}

	return &Manager{
		name:                               name,
		namespace:                          namespace,
		path:                               path,
		validatingWebhookConfigurationName: validatingWebhookConfigurationName,
		certsReady:                         certsReady,
		leaderElected:                      leaderElected,
		log:                                log.With("component", "CertControllerManager"),
		rotatorAdder:                       rotator.AddRotator,
	}
}

func (m *Manager) setupRotator(mgr ctrl.Manager) error {
	cr := m.newCertRotator()
	if err := m.getRotatorAdder()(mgr, cr); err != nil {
		return fmt.Errorf("unable to setup cert rotation: %w", err)
	}

	return nil
}

func (m *Manager) Start(ctx context.Context, scheme *runtime.Scheme) error {
	// Wait for leadership signal if provided (enables multi-replica scaling with leader election)
	if m.leaderElected != nil {
		m.log.Info("Cert-controller's manager waiting for leadership signal before starting...")
		select {
		case <-ctx.Done():
			m.log.Infow("Cert-controller's manager stopping before acquiring leadership (context cancelled)")
			return fmt.Errorf("context error: %w", ctx.Err())
		case <-m.leaderElected:
			m.log.Info("Leadership acquired - cert-controller's manager")
		}
	}

	m.log.Infow("Configuring cert-controller's manager")
	// Create a manager for cert-controller
	mgr, err := m.getManagerFactory()(scheme)
	if err != nil {
		return fmt.Errorf("failed to start cert-controller: %w", err)
	}

	m.log.Infow("Setting up cert-controller's rotator", "webhook-service-name", m.name, "namespace", m.namespace,
		"webhook-cert-path", m.path, "webhook-validating-config-name", m.validatingWebhookConfigurationName)
	if err := m.setupRotator(mgr); err != nil {
		return fmt.Errorf("failed to setup cert-controller's rotator: %w", err)
	}

	m.log.Infow("Starting cert-controller's manager")
	// Start the manager in a blocking call (in goroutine) that will also handle cache synchronization
	if err := mgr.Start(ctx); err != nil {
		return fmt.Errorf("cert-controller's manager failed to start or exited with error: %w", err)
	}

	return nil
}

func (m *Manager) newCertRotator() *rotator.CertRotator {
	return &rotator.CertRotator{
		SecretKey: types.NamespacedName{
			Namespace: m.namespace,
			Name:      m.name,
		},
		CertDir:               m.path,
		CAName:                fmt.Sprintf("%s-ca", m.name),
		CAOrganization:        "breakglass",
		DNSName:               fmt.Sprintf("%s.%s.svc", m.name, m.namespace),
		ExtraDNSNames:         []string{fmt.Sprintf("%s.%s.svc.cluster.local", m.name, m.namespace), m.name},
		IsReady:               m.certsReady,
		RequireLeaderElection: false,
		Webhooks: []rotator.WebhookInfo{
			{
				Name: m.validatingWebhookConfigurationName,
				Type: rotator.Validating,
			},
		},
		RestartOnSecretRefresh: false,
	}
}

func (m *Manager) getManagerFactory() func(*runtime.Scheme) (ctrl.Manager, error) {
	if m.managerFactory != nil {
		return m.managerFactory
	}

	return func(scheme *runtime.Scheme) (ctrl.Manager, error) {
		cfg, err := ctrl.GetConfig()
		if err != nil {
			return nil, fmt.Errorf("failed to load kubeconfig: %w", err)
		}
		return ctrl.NewManager(cfg, ctrl.Options{
			Scheme:           scheme,
			LeaderElection:   false,
			LeaderElectionID: "",
			Metrics: metricsserver.Options{
				BindAddress: "0", // disable metrics server
			},
			Client: client.Options{
				FieldOwner:      utils.FieldOwnerController,
				FieldValidation: metav1.FieldValidationWarn,
			},
		})
	}
}

func (m *Manager) getRotatorAdder() func(ctrl.Manager, *rotator.CertRotator) error {
	if m.rotatorAdder != nil {
		return m.rotatorAdder
	}

	return rotator.AddRotator
}

func Ensure(path string, name string, certsReady chan struct{}, certMgrErr chan error, log *zap.SugaredLogger) error {
	log.Debugw("waiting for certs generation")
	select {
	case <-certsReady:
		log.Debugw("certs ready")
		if err := wait(path, name, 30*time.Second, 100*time.Millisecond); err != nil {
			return fmt.Errorf("certificates are not present: %w", err)
		} else {
			log.Debugw("certificates loaded")
			return nil
		}
	case err := <-certMgrErr:
		close(certsReady)
		return fmt.Errorf("certificates not ready due to cert-controller error: %w", err)
	}
}

func wait(webhookCertPath, webhookCertName string, timeout, tick time.Duration) error {
	to := time.After(timeout)
	t := time.Tick(tick)
	p := path.Join(webhookCertPath, webhookCertName)

	for {
		select {
		case <-to:
			// stop waiting for the file and log error
			return fmt.Errorf("waiting for certificates timed out after %s", timeout.String())
		case <-t:
			// check if file contains proper PEM data
			data, err := os.ReadFile(p)
			if err == nil {
				b, _ := pem.Decode(data)
				if b != nil {
					return nil
				}
			}
		}
	}
}
