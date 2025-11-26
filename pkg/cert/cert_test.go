package cert

import (
	"context"
	"errors"
	"net/http"
	"testing"
	"time"

	"github.com/go-logr/logr"
	"github.com/open-policy-agent/cert-controller/pkg/rotator"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"k8s.io/apimachinery/pkg/api/meta"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/record"
	ctrl "sigs.k8s.io/controller-runtime"
	crcache "sigs.k8s.io/controller-runtime/pkg/cache"
	"sigs.k8s.io/controller-runtime/pkg/client"
	ctrlconfig "sigs.k8s.io/controller-runtime/pkg/config"
	"sigs.k8s.io/controller-runtime/pkg/healthz"
	"sigs.k8s.io/controller-runtime/pkg/manager"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

func TestNewManagerAppliesDefaults(t *testing.T) {
	mgr := NewManager("svc", "ns", "", "", make(chan struct{}), nil, zap.NewNop().Sugar())

	require.Equal(t, DefaultWebhookPath, mgr.path)
	require.Equal(t, DefaultValidatingWebhookConfigurationName, mgr.validatingWebhookConfigurationName)
}

func TestNewCertRotatorConfiguration(t *testing.T) {
	certsReady := make(chan struct{})
	mgr := NewManager("svc", "ns", "/tmp/certs", "custom-config", certsReady, nil, zap.NewNop().Sugar())

	cr := mgr.newCertRotator()

	require.Equal(t, types.NamespacedName{Namespace: "ns", Name: "svc"}, cr.SecretKey)
	require.Equal(t, "/tmp/certs", cr.CertDir)
	require.Equal(t, "svc-ca", cr.CAName)
	require.Equal(t, []string{"svc.ns.svc.cluster.local", "svc"}, cr.ExtraDNSNames)
	require.Equal(t, certsReady, cr.IsReady)
	require.Len(t, cr.Webhooks, 1)
	require.Equal(t, "custom-config", cr.Webhooks[0].Name)
	require.Equal(t, rotator.Validating, cr.Webhooks[0].Type)
	require.False(t, cr.RequireLeaderElection)
}

func TestSetupRotatorPassesConfiguration(t *testing.T) {
	mgr := NewManager("svc", "ns", "/tmp/certs", "cfg", make(chan struct{}), nil, zap.NewNop().Sugar())
	fakeMgr := newFakeCtrlManager(t)

	var received *rotator.CertRotator
	mgr.rotatorAdder = func(_ ctrl.Manager, cr *rotator.CertRotator) error {
		received = cr
		return nil
	}

	require.NoError(t, mgr.setupRotator(fakeMgr))
	require.NotNil(t, received)
	require.Equal(t, "svc-ca", received.CAName)
}

func TestSetupRotatorPropagatesError(t *testing.T) {
	mgr := NewManager("svc", "ns", "/tmp/certs", "cfg", make(chan struct{}), nil, zap.NewNop().Sugar())
	fakeMgr := newFakeCtrlManager(t)

	mgr.rotatorAdder = func(ctrl.Manager, *rotator.CertRotator) error {
		return errors.New("boom")
	}

	err := mgr.setupRotator(fakeMgr)
	require.ErrorContains(t, err, "unable to setup cert rotation")
}

func TestManagerStartHappyPath(t *testing.T) {
	mgr, fakeMgr := newTestCertManager(t)
	captured := make(chan *rotator.CertRotator, 1)
	mgr.rotatorAdder = func(_ ctrl.Manager, cr *rotator.CertRotator) error {
		captured <- cr
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	err := mgr.Start(ctx, runtime.NewScheme())
	require.NoError(t, err)
	require.True(t, fakeMgr.startCalled)
	require.NotNil(t, <-captured)
}

func TestManagerStartWaitsForLeaderElection(t *testing.T) {
	mgr, fakeMgr := newTestCertManager(t)
	leaderCh := make(chan struct{})
	mgr.leaderElected = leaderCh

	captured := make(chan struct{}, 1)
	mgr.rotatorAdder = func(_ ctrl.Manager, _ *rotator.CertRotator) error {
		captured <- struct{}{}
		return nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	result := make(chan error, 1)
	go func() {
		result <- mgr.Start(ctx, runtime.NewScheme())
	}()

	select {
	case err := <-result:
		t.Fatalf("start returned early: %v", err)
	case <-time.After(50 * time.Millisecond):
	}

	close(leaderCh)

	select {
	case err := <-result:
		require.NoError(t, err)
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for manager to finish")
	}

	require.True(t, fakeMgr.startCalled)
	require.NotNil(t, <-captured)
}

func TestManagerStartContextCancelledBeforeLeadership(t *testing.T) {
	mgr, _ := newTestCertManager(t)
	leaderCh := make(chan struct{})
	mgr.leaderElected = leaderCh

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := mgr.Start(ctx, runtime.NewScheme())
	require.ErrorContains(t, err, "context error")
}

func TestManagerStartManagerFactoryError(t *testing.T) {
	mgr := NewManager("svc", "ns", "/tmp", "cfg", make(chan struct{}), nil, zap.NewNop().Sugar())
	mgr.managerFactory = func(*runtime.Scheme) (ctrl.Manager, error) {
		return nil, errors.New("factory failure")
	}

	err := mgr.Start(context.Background(), runtime.NewScheme())
	require.ErrorContains(t, err, "failed to start cert-controller")
}

func TestManagerStartRotatorError(t *testing.T) {
	mgr, _ := newTestCertManager(t)
	mgr.rotatorAdder = func(ctrl.Manager, *rotator.CertRotator) error {
		return errors.New("rotator failure")
	}

	err := mgr.Start(context.Background(), runtime.NewScheme())
	require.ErrorContains(t, err, "failed to setup cert-controller's rotator")
}

func TestManagerStartManagerStartError(t *testing.T) {
	mgr, fakeMgr := newTestCertManager(t)
	fakeMgr.startErr = errors.New("start failure")
	mgr.rotatorAdder = func(_ ctrl.Manager, _ *rotator.CertRotator) error {
		return nil
	}

	err := mgr.Start(context.Background(), runtime.NewScheme())
	require.ErrorContains(t, err, "cert-controller's manager failed to start")
}

func newTestCertManager(t *testing.T) (*Manager, *fakeCtrlManager) {
	t.Helper()

	certsReady := make(chan struct{})
	mgr := NewManager("svc", "ns", "/tmp/certs", "cfg", certsReady, nil, zap.NewNop().Sugar())
	fakeMgr := newFakeCtrlManager(t)
	mgr.managerFactory = func(*runtime.Scheme) (ctrl.Manager, error) {
		return fakeMgr, nil
	}
	return mgr, fakeMgr
}

func newFakeCtrlManager(t testing.TB) *fakeCtrlManager {
	t.Helper()

	ch := make(chan struct{})
	close(ch)

	return &fakeCtrlManager{
		webhookSrv: &fakeWebhookServer{},
		logger:     logr.Discard(),
		electedCh:  ch,
	}
}

var _ manager.Manager = (*fakeCtrlManager)(nil)

type fakeCtrlManager struct {
	addErr      error
	startErr    error
	startCalled bool
	startCtx    context.Context

	httpClient        *http.Client
	cfg               *rest.Config
	cache             crcache.Cache
	scheme            *runtime.Scheme
	client            client.Client
	fieldIndexer      client.FieldIndexer
	recorder          record.EventRecorder
	restMapper        meta.RESTMapper
	apiReader         client.Reader
	webhookSrv        webhook.Server
	logger            logr.Logger
	controllerOptions ctrlconfig.Controller
	electedCh         chan struct{}
}

func (f *fakeCtrlManager) Add(manager.Runnable) error {
	if f.addErr != nil {
		return f.addErr
	}
	return nil
}

func (f *fakeCtrlManager) Elected() <-chan struct{} {
	return f.electedCh
}

func (f *fakeCtrlManager) AddMetricsServerExtraHandler(string, http.Handler) error { return nil }
func (f *fakeCtrlManager) AddHealthzCheck(string, healthz.Checker) error           { return nil }
func (f *fakeCtrlManager) AddReadyzCheck(string, healthz.Checker) error            { return nil }

func (f *fakeCtrlManager) Start(ctx context.Context) error {
	f.startCalled = true
	f.startCtx = ctx
	if f.startErr != nil {
		return f.startErr
	}
	return nil
}

func (f *fakeCtrlManager) GetWebhookServer() webhook.Server {
	return f.webhookSrv
}

func (f *fakeCtrlManager) GetLogger() logr.Logger {
	return f.logger
}

func (f *fakeCtrlManager) GetControllerOptions() ctrlconfig.Controller {
	return f.controllerOptions
}

func (f *fakeCtrlManager) GetHTTPClient() *http.Client { return f.httpClient }
func (f *fakeCtrlManager) GetConfig() *rest.Config     { return f.cfg }
func (f *fakeCtrlManager) GetCache() crcache.Cache     { return f.cache }
func (f *fakeCtrlManager) GetScheme() *runtime.Scheme  { return f.scheme }
func (f *fakeCtrlManager) GetClient() client.Client    { return f.client }
func (f *fakeCtrlManager) GetFieldIndexer() client.FieldIndexer {
	return f.fieldIndexer
}
func (f *fakeCtrlManager) GetEventRecorderFor(string) record.EventRecorder { return f.recorder }
func (f *fakeCtrlManager) GetRESTMapper() meta.RESTMapper                  { return f.restMapper }
func (f *fakeCtrlManager) GetAPIReader() client.Reader                     { return f.apiReader }

type fakeWebhookServer struct{}

var _ webhook.Server = (*fakeWebhookServer)(nil)

func (f *fakeWebhookServer) NeedLeaderElection() bool      { return false }
func (f *fakeWebhookServer) Register(string, http.Handler) {}
func (f *fakeWebhookServer) Start(context.Context) error   { return nil }
func (f *fakeWebhookServer) StartedChecker() healthz.Checker {
	return func(*http.Request) error { return nil }
}
func (f *fakeWebhookServer) WebhookMux() *http.ServeMux { return http.NewServeMux() }
