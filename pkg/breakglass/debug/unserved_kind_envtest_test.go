// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/audit"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// TestPlatformUnservedKindEnvtest reproduces #1663 against a real API server
// that, like a management cluster without Kyverno, does not serve
// policies.kyverno.io PolicyException.
func TestPlatformUnservedKindEnvtest(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS required")
	}
	t.Setenv("BREAKGLASS_DISABLE_LOOPBACK_REWRITE", "true")
	env := &envtest.Environment{CRDDirectoryPaths: []string{filepath.Join("..", "..", "..", "config", "crd", "bases")}, ErrorIfCRDPathMissing: true}
	cfg, err := env.Start()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, env.Stop()) })
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme.Scheme))
	hub, err := client.New(cfg, client.Options{Scheme: scheme.Scheme})
	require.NoError(t, err)
	ctx := context.Background()
	const ns = "unserved-kind"
	require.NoError(t, hub.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}))
	raw, err := clientcmd.Write(clientcmdapi.Config{Clusters: map[string]*clientcmdapi.Cluster{"target": {Server: cfg.Host, CertificateAuthorityData: cfg.CAData}}, AuthInfos: map[string]*clientcmdapi.AuthInfo{"admin": {ClientCertificateData: cfg.CertData, ClientKeyData: cfg.KeyData}}, Contexts: map[string]*clientcmdapi.Context{"target": {Cluster: "target", AuthInfo: "admin"}}, CurrentContext: "target"})
	require.NoError(t, err)
	require.NoError(t, hub.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: ns}, Data: map[string][]byte{"value": raw}}))
	clusterConfig := &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: ns}, Spec: breakglassv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{Name: "target", Namespace: ns}}}
	require.NoError(t, hub.Create(ctx, clusterConfig))
	clusterConfig.Status.ObservedGeneration = clusterConfig.Generation
	clusterConfig.Status.Conditions = []metav1.Condition{{Type: string(breakglassv1alpha1.ClusterConfigConditionReady), Status: metav1.ConditionTrue, Reason: "Ready", ObservedGeneration: clusterConfig.Generation, LastTransitionTime: metav1.Now()}}
	require.NoError(t, hub.Status().Update(ctx, clusterConfig))

	exception := breakglassv1alpha1.AuxiliaryResource{
		Name: "policy-exception", Category: "policy-exceptions", CreateBefore: ptrBool(true), DeleteAfter: ptrBool(true),
		TemplateString: "apiVersion: policies.kyverno.io/v1\nkind: PolicyException\nmetadata:\n  name: {{ .session.name }}\n",
	}
	template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "unserved-template"}, Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
		Mode: breakglassv1alpha1.DebugSessionModeKubectlDebug, TargetNamespace: "default",
		KubectlDebug:                        &breakglassv1alpha1.KubectlDebugConfig{EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{Enabled: true, AllowedImages: []string{"busybox:*"}, RequireNonRoot: true}},
		Allowed:                             &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"target"}, Groups: []string{"debug"}},
		Constraints:                         &breakglassv1alpha1.DebugSessionConstraints{MaxDuration: "2m", DefaultDuration: "2m"},
		AuxiliaryResources:                  []breakglassv1alpha1.AuxiliaryResource{exception},
		RequiredAuxiliaryResourceCategories: []string{"policy-exceptions"},
	}}
	require.NoError(t, hub.Create(ctx, template))

	newController := func(handling bool, sink *cleanupAuditCaptureSink) (*DebugSessionController, *audit.Manager) {
		manager := audit.NewManager(sink, audit.ManagerConfig{QueueSize: 64, WorkerCount: 1}, zap.NewNop())
		c := NewDebugSessionController(zap.NewNop().Sugar(), hub, cluster.NewClientProvider(hub, zap.NewNop().Sugar())).
			WithLiveReader(hub).WithQuotaNamespace(ns).WithAuditManager(manager).WithUnservedKindHandling(handling)
		// envtest runs no admission webhook; the acknowledgement test stands in for it.
		c.acknowledgementWebhookActive = webhookActive
		return c, manager
	}
	countEvents := func(sink *cleanupAuditCaptureSink, eventType audit.EventType) int {
		n := 0
		for _, event := range sink.Events() {
			if event.Type == eventType {
				n++
			}
		}
		return n
	}

	activate := func(t *testing.T, name string, handling bool) *breakglassv1alpha1.DebugSession {
		t.Helper()
		ds := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}, Spec: breakglassv1alpha1.DebugSessionSpec{Cluster: "target", TemplateRef: template.Name, RequestedBy: "requester", RequestedByIdentities: []string{"requester", "requester-sub"}, RequestedDuration: "2m", TargetNamespace: "default", Reason: "unserved kind regression"}}
		require.NoError(t, hub.Create(ctx, ds))
		sink := &cleanupAuditCaptureSink{}
		c, manager := newController(handling, sink)
		for attempt := 0; attempt < 6; attempt++ {
			_, err := c.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(ds)})
			require.NoError(t, err)
		}
		require.NoError(t, manager.Close())
		require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(ds), ds))
		require.Equal(t, breakglassv1alpha1.DebugSessionStateFailed, ds.Status.State, ds.Status.Message)
		assert.False(t, hasTrackedSpokeResources(ds), "no cleanup residual may remain: %+v", ds.Status.AuxiliaryResourceStatuses)
		assert.False(t, cleanupConditionFailed(ds))
		assert.Zero(t, countEvents(sink, audit.EventDebugSessionCleanupFailed), "a cleanly failed session emits no cleanup_failed events")
		return ds
	}

	t.Run("activation preflight fails early", func(t *testing.T) {
		ds := activate(t, "preflight", true)
		assert.Contains(t, ds.Status.Message, `auxiliary resource "policy-exception" requires policies.kyverno.io/v1 PolicyException, which target cluster "target" does not serve`)
		assert.Empty(t, ds.Status.AuxiliaryResourceStatuses, "nothing was applied")
	})

	t.Run("opt-out still retires the rejected create", func(t *testing.T) {
		ds := activate(t, "no-preflight", false)
		assert.Contains(t, ds.Status.Message, `no matches for kind "PolicyException"`)
	})

	// The lab state: a session that failed before this fix with a create
	// intent that never reached the API server.
	failedWithUnresolvedIntent := func(t *testing.T, name string) *breakglassv1alpha1.DebugSession {
		t.Helper()
		ds := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns}, Spec: breakglassv1alpha1.DebugSessionSpec{Cluster: "target", TemplateRef: template.Name, RequestedBy: "requester", RequestedByIdentities: []string{"requester", "requester-sub"}, RequestedDuration: "2m", TargetNamespace: "default", Reason: "unserved kind regression"}}
		require.NoError(t, hub.Create(ctx, ds))
		ds.Status.State = breakglassv1alpha1.DebugSessionStateFailed
		ds.Status.ResolvedTemplate = template.Spec.DeepCopy()
		ds.Status.AuxiliaryResourceStatuses = []breakglassv1alpha1.AuxiliaryResourceStatus{{
			Name: exception.Name, Category: exception.Category, APIVersion: "policies.kyverno.io/v1", Kind: "PolicyException",
			Namespace: "default", ResourceName: name, Created: true, CreateOperationID: "lost-create",
		}}
		ds.Status.Conditions = []metav1.Condition{{Type: string(breakglassv1alpha1.DebugSessionConditionCleanupFailed), Status: metav1.ConditionTrue, Reason: "CleanupFailed", Message: boundedCleanupConditionMessage(ds), LastTransitionTime: metav1.NewTime(time.Now().Add(-time.Minute))}}
		require.NoError(t, hub.Status().Update(ctx, ds))
		return ds
	}

	// A recorded object of an uninstalled CRD gets NoMatch forever; only an
	// operator acknowledgement retires it, and it never bypasses the audit.
	t.Run("acknowledgement completes cleanup", func(t *testing.T) {
		ds := failedWithUnresolvedIntent(t, "lab-ack")
		ds.Status.AuxiliaryResourceStatuses[0].UID = "uid-of-removed-crd-object"
		ds.Status.AuxiliaryResourceStatuses[0].CreateOperationID = ""
		ds.Status.Conditions[0].Message = boundedCleanupConditionMessage(ds)
		require.NoError(t, hub.Status().Update(ctx, ds))
		sink := &cleanupAuditCaptureSink{}
		c, manager := newController(true, sink)

		result, err := c.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(ds)})
		require.NoError(t, err)
		assert.Greater(t, result.RequeueAfter, ExpiredSessionRequeue, "without acknowledgement the residual backs off")
		require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(ds), ds))
		require.False(t, ds.Status.AuxiliaryResourceStatuses[0].Deleted)

		// envtest runs without the admission webhook, which would otherwise
		// require acknowledgedBy to name the creating user.
		require.NoError(t, hub.Create(ctx, &breakglassv1alpha1.DebugSessionCleanupAcknowledgement{
			ObjectMeta: metav1.ObjectMeta{Name: "lab-ack-1", Namespace: ns},
			Spec: breakglassv1alpha1.DebugSessionCleanupAcknowledgementSpec{
				SessionName: ds.Name, SessionUID: string(ds.UID), AcknowledgedBy: "operator@example.com",
				Identities: []breakglassv1alpha1.CleanupAcknowledgedIdentity{{APIVersion: "policies.kyverno.io/v1", Kind: "PolicyException", Namespace: "default", Name: ds.Name, UID: "uid-of-removed-crd-object"}},
			},
		}))
		// The spec is immutable on the real API server.
		created := &breakglassv1alpha1.DebugSessionCleanupAcknowledgement{}
		require.NoError(t, hub.Get(ctx, client.ObjectKey{Namespace: ns, Name: "lab-ack-1"}, created))
		created.Spec.Reason = "changed"
		require.Error(t, hub.Update(ctx, created), "acknowledgement spec must be immutable")
		result, err = c.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(ds)})
		require.NoError(t, err)
		require.NoError(t, manager.Close())
		assert.Zero(t, result.RequeueAfter, "acknowledged cleanup is complete")
		require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(ds), ds))
		assert.True(t, ds.Status.AuxiliaryResourceStatuses[0].Deleted)
		condition := ds.GetCondition(string(breakglassv1alpha1.DebugSessionConditionCleanupFailed))
		require.NotNil(t, condition)
		assert.Equal(t, metav1.ConditionFalse, condition.Status)
		assert.Equal(t, "CleanupAcknowledged", condition.Reason)
		assert.Equal(t, 1, countEvents(sink, audit.EventDebugSessionCleanupAcknowledged))
		require.Len(t, ds.Status.CleanupAcknowledgements, 1)
		assert.Equal(t, "operator@example.com", ds.Status.CleanupAcknowledgements[0].AcknowledgedBy)
		assert.Equal(t, 1, countEvents(sink, audit.EventDebugSessionCleanupRecovered))
	})

	t.Run("unresolved intent is never retired automatically and backs off", func(t *testing.T) {
		ds := failedWithUnresolvedIntent(t, "lab-intent")
		sink := &cleanupAuditCaptureSink{}
		c, manager := newController(true, sink)
		for range 3 {
			result, err := c.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(ds)})
			require.NoError(t, err)
			assert.Greater(t, result.RequeueAfter, ExpiredSessionRequeue, "retries back off from the persisted failure start")
		}
		require.NoError(t, manager.Close())
		require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(ds), ds))
		assert.False(t, ds.Status.AuxiliaryResourceStatuses[0].Deleted)
		assert.True(t, cleanupConditionFailed(ds))
		assert.Zero(t, countEvents(sink, audit.EventDebugSessionCleanupFailed), "an unchanged residual set is not re-reported")
	})
}
