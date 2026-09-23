// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"github.com/telekom/k8s-breakglass/pkg/quotas"
	"go.uber.org/zap"
	coordinationv1 "k8s.io/api/coordination/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestFreshKubectlDebugSessionActivatesWithRealAPI(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS required")
	}
	env := &envtest.Environment{CRDDirectoryPaths: []string{filepath.Join("..", "..", "..", "config", "crd", "bases")}, ErrorIfCRDPathMissing: true}
	cfg, err := env.Start()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, env.Stop()) })
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme.Scheme))
	hub, err := client.New(cfg, client.Options{Scheme: scheme.Scheme})
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, hub.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "activation-test"}}))
	raw, err := clientcmd.Write(clientcmdapi.Config{Clusters: map[string]*clientcmdapi.Cluster{"target": {Server: cfg.Host, CertificateAuthorityData: cfg.CAData}}, AuthInfos: map[string]*clientcmdapi.AuthInfo{"admin": {ClientCertificateData: cfg.CertData, ClientKeyData: cfg.KeyData}}, Contexts: map[string]*clientcmdapi.Context{"target": {Cluster: "target", AuthInfo: "admin"}}, CurrentContext: "target"})
	require.NoError(t, err)
	require.NoError(t, hub.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: "activation-test"}, Data: map[string][]byte{"value": raw}}))
	require.NoError(t, hub.Create(ctx, &breakglassv1alpha1.ClusterConfig{ObjectMeta: metav1.ObjectMeta{Name: "target", Namespace: "activation-test"}, Spec: breakglassv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{Name: "target", Namespace: "activation-test"}}}))
	template := &breakglassv1alpha1.DebugSessionTemplate{ObjectMeta: metav1.ObjectMeta{Name: "activation-template"}, Spec: breakglassv1alpha1.DebugSessionTemplateSpec{Mode: breakglassv1alpha1.DebugSessionModeKubectlDebug, TargetNamespace: "default", KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{Enabled: true, AllowedImages: []string{"busybox:*"}, RequireNonRoot: true}}, Allowed: &breakglassv1alpha1.DebugSessionAllowed{Clusters: []string{"target"}, Groups: []string{"debug"}}, Constraints: &breakglassv1alpha1.DebugSessionConstraints{MaxDuration: "2m", DefaultDuration: "2m"}}}
	require.NoError(t, hub.Create(ctx, template))
	ds := &breakglassv1alpha1.DebugSession{ObjectMeta: metav1.ObjectMeta{Name: "fresh-session", Namespace: "activation-test"}, Spec: breakglassv1alpha1.DebugSessionSpec{Cluster: "target", TemplateRef: template.Name, RequestedBy: "requester", RequestedDuration: "2m", TargetNamespace: "default", Reason: "Hard-expiry activation regression"}, Status: breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStatePending}}
	require.NoError(t, hub.Create(ctx, ds))
	require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(ds), ds))
	require.Empty(t, ds.Status.State, "real API discards status on creation")
	c := NewDebugSessionController(zap.NewNop().Sugar(), hub, cluster.NewClientProvider(hub, zap.NewNop().Sugar())).WithLiveReader(hub).WithQuotaNamespace("activation-test")
	for attempt := 0; attempt < 3; attempt++ {
		_, err = c.Reconcile(ctx, ctrl.Request{NamespacedName: client.ObjectKeyFromObject(ds)})
		require.NoError(t, err)
		require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(ds), ds))
		if ds.Status.State == breakglassv1alpha1.DebugSessionStateActive {
			break
		}
	}
	require.NoError(t, hub.Get(ctx, client.ObjectKeyFromObject(ds), ds))
	require.Equal(t, breakglassv1alpha1.DebugSessionStateActive, ds.Status.State, ds.Status.Message)
	require.Equal(t, quotas.Ready, ds.Annotations[quotas.AdmissionAnnotation])
	require.NotNil(t, ds.Status.ConnectionLease)
	require.NotEmpty(t, ds.Status.ConnectionLease.UID)
	var lease coordinationv1.Lease
	require.NoError(t, hub.Get(ctx, client.ObjectKey{Namespace: ds.Status.ConnectionLease.Namespace, Name: ds.Status.ConnectionLease.Name}, &lease))
	require.Equal(t, ds.Status.ConnectionLease.UID, lease.UID)
	require.Equal(t, string(ds.UID), *lease.Spec.HolderIdentity)
}
