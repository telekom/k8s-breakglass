// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
	"go.uber.org/zap"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	policyv1 "k8s.io/api/policy/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

type deletionTimestampSessionReader struct {
	client.Reader
}

func (r deletionTimestampSessionReader) Get(ctx context.Context, key client.ObjectKey, obj client.Object, opts ...client.GetOption) error {
	if err := r.Reader.Get(ctx, key, obj, opts...); err != nil {
		return err
	}
	if session, ok := obj.(*breakglassv1alpha1.DebugSession); ok {
		now := metav1.Now()
		session.DeletionTimestamp = &now
	}
	return nil
}

// newDeploymentFenceFixture uses the real privileged provider, while replacing
// only the target client with a fake. This keeps the test on the production
// deployDebugResources path and exercises the provider's credential/config
// snapshot validation at every write boundary.
func newDeploymentFenceFixture(t *testing.T) (*DebugSessionController, *breakglassv1alpha1.DebugSession, *breakglassv1alpha1.DebugSessionTemplate, client.Client) {
	t.Helper()
	s := runtime.NewScheme()
	require.NoError(t, scheme.AddToScheme(s))
	require.NoError(t, breakglassv1alpha1.AddToScheme(s))
	raw, err := clientcmd.Write(clientcmdapi.Config{
		APIVersion: "v1", Kind: "Config",
		Clusters:       map[string]*clientcmdapi.Cluster{"spoke": {Server: "https://spoke.invalid"}},
		AuthInfos:      map[string]*clientcmdapi.AuthInfo{"admin": {Token: "token"}},
		Contexts:       map[string]*clientcmdapi.Context{"ctx": {Cluster: "spoke", AuthInfo: "admin"}},
		CurrentContext: "ctx",
	})
	require.NoError(t, err)
	cc := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "spoke", Namespace: "default", UID: "cluster-uid"},
		Spec:       breakglassv1alpha1.ClusterConfigSpec{KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{Name: "spoke-kubeconfig", Namespace: "default"}},
	}
	secret := &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: "spoke-kubeconfig", Namespace: "default", ResourceVersion: "1"}, Data: map[string][]byte{"value": raw}}
	now := metav1.NewTime(time.Now().Add(time.Hour))
	ds := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: "debug-fenced", Namespace: "default", UID: "session-uid", Labels: map[string]string{}},
		Spec:       breakglassv1alpha1.DebugSessionSpec{Cluster: "default/spoke", TemplateRef: "template", RequestedBy: "tester"},
		Status:     breakglassv1alpha1.DebugSessionStatus{State: breakglassv1alpha1.DebugSessionStateActive, ExpiresAt: &now},
	}
	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: "template"},
		Spec:       breakglassv1alpha1.DebugSessionTemplateSpec{Mode: breakglassv1alpha1.DebugSessionModeWorkload, PodTemplateString: "apiVersion: v1\nkind: Pod\nspec:\n  containers:\n  - name: debug\n    image: busybox\n", WorkloadType: breakglassv1alpha1.DebugWorkloadDeployment},
	}
	hub := fake.NewClientBuilder().
		WithScheme(s).
		WithObjects(cc, secret, ds, template).
		WithStatusSubresource(&breakglassv1alpha1.DebugSession{}).
		Build()
	target := fake.NewClientBuilder().WithScheme(s).WithObjects(&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "breakglass-debug"}}).Build()
	c := NewDebugSessionController(zap.NewNop().Sugar(), hub, cluster.NewClientProvider(hub, zap.NewNop().Sugar()))
	c.targetClientFactory = func(_ *rest.Config) (client.Client, error) { return target, nil }
	return c, ds, template, target
}

func TestDeployDebugResourcesRejectsSessionInvalidationBeforeEachWrite(t *testing.T) {
	for _, tc := range []struct {
		name      string
		configure func(*breakglassv1alpha1.DebugSessionTemplate)
	}{
		{name: "resource quota", configure: func(t *breakglassv1alpha1.DebugSessionTemplate) {
			maxAvailable := int32(1)
			t.Spec.ResourceQuota = &breakglassv1alpha1.DebugResourceQuotaConfig{MaxPods: &maxAvailable}
		}},
		{name: "pod disruption budget", configure: func(t *breakglassv1alpha1.DebugSessionTemplate) {
			minAvailable := int32(1)
			t.Spec.PodDisruptionBudget = &breakglassv1alpha1.DebugPDBConfig{Enabled: true, MinAvailable: &minAvailable}
		}},
		{name: "workload", configure: func(*breakglassv1alpha1.DebugSessionTemplate) {}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, ds, template, target := newDeploymentFenceFixture(t)
			tc.configure(template)
			c.beforeDebugTargetWrite = func(_ string) {
				live := &breakglassv1alpha1.DebugSession{}
				require.NoError(t, c.client.Get(context.Background(), client.ObjectKeyFromObject(ds), live))
				live.Status.State = breakglassv1alpha1.DebugSessionStateExpired
				require.NoError(t, c.client.Status().Update(context.Background(), live))
			}
			err := c.deployDebugResources(context.Background(), ds, template)
			require.Error(t, err)
			var rqs corev1.ResourceQuotaList
			require.NoError(t, target.List(context.Background(), &rqs))
			require.Empty(t, rqs.Items, "session invalidation must prevent target writes")
			var deployments appsv1.DeploymentList
			require.NoError(t, target.List(context.Background(), &deployments))
			require.Empty(t, deployments.Items)
			var pdbs policyv1.PodDisruptionBudgetList
			require.NoError(t, target.List(context.Background(), &pdbs))
			require.Empty(t, pdbs.Items)
		})
	}
}

func TestActivateSessionEstablishesLeaseBeforeDeployment(t *testing.T) {
	c, ds, template, target := newDeploymentFenceFixture(t)
	ds.Status.State = breakglassv1alpha1.DebugSessionStatePending
	ds.Status.Approval = &breakglassv1alpha1.DebugSessionApproval{Required: false}

	_, err := c.activateSession(context.Background(), ds, template, nil)
	require.NoError(t, err)
	require.Equal(t, breakglassv1alpha1.DebugSessionStateActive, ds.Status.State)
	require.NotNil(t, ds.Status.ExpiresAt)

	deployment := &appsv1.Deployment{}
	require.NoError(t, target.Get(context.Background(), client.ObjectKey{Namespace: "breakglass-debug", Name: ds.Name}, deployment))
}

func TestDeployDebugResourcesRejectsClusterConfigRotationBeforeWrite(t *testing.T) {
	c, ds, template, target := newDeploymentFenceFixture(t)
	c.beforeDebugTargetWrite = func(_ string) {
		live := &breakglassv1alpha1.ClusterConfig{}
		require.NoError(t, c.client.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "spoke"}, live))
		live.Spec.AuthType = breakglassv1alpha1.ClusterAuthTypeOIDC
		require.NoError(t, c.client.Update(context.Background(), live))
	}
	err := c.deployDebugResources(context.Background(), ds, template)
	t.Logf("deploy error: %v", err)
	require.Error(t, err)
	var deployments appsv1.DeploymentList
	require.NoError(t, target.List(context.Background(), &deployments))
	require.Empty(t, deployments.Items, "rotated ClusterConfig must not permit a cached client write")
}

func TestDeployDebugResourcesRejectsCredentialRotationBeforeWrite(t *testing.T) {
	c, ds, template, target := newDeploymentFenceFixture(t)
	c.beforeDebugTargetWrite = func(_ string) {
		secret := &corev1.Secret{}
		require.NoError(t, c.client.Get(context.Background(), client.ObjectKey{Namespace: "default", Name: "spoke-kubeconfig"}, secret))
		secret.Data["value"] = []byte("rotated-credential")
		require.NoError(t, c.client.Update(context.Background(), secret))
	}
	err := c.deployDebugResources(context.Background(), ds, template)
	require.Error(t, err)
	var deployments appsv1.DeploymentList
	require.NoError(t, target.List(context.Background(), &deployments))
	require.Empty(t, deployments.Items, "rotated credential must not permit a target write")
}

func TestDeployDebugResourcesRejectsDeletionBeforeWrite(t *testing.T) {
	c, ds, template, target := newDeploymentFenceFixture(t)
	c.reader = deletionTimestampSessionReader{Reader: c.client}
	err := c.deployDebugResources(context.Background(), ds, template)
	require.Error(t, err)
	var deployments appsv1.DeploymentList
	require.NoError(t, target.List(context.Background(), &deployments))
	require.Empty(t, deployments.Items, "deleting session must not permit a target write")
}

func TestDeployDebugResourcesFencesEveryPodTemplateDocument(t *testing.T) {
	c, ds, template, target := newDeploymentFenceFixture(t)
	template.Spec.PodTemplateString = `containers:
  - name: debug
    image: busybox
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: first
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: second
`
	writeBoundaries := 0
	c.beforeDebugTargetWrite = func(_ string) {
		writeBoundaries++
		if writeBoundaries != 2 {
			return
		}
		live := &breakglassv1alpha1.DebugSession{}
		require.NoError(t, c.client.Get(context.Background(), client.ObjectKeyFromObject(ds), live))
		live.Status.State = breakglassv1alpha1.DebugSessionStateExpired
		require.NoError(t, c.client.Status().Update(context.Background(), live))
	}
	err := c.deployDebugResources(context.Background(), ds, template)
	require.Error(t, err)
	first := &corev1.ConfigMap{}
	require.NoError(t, target.Get(context.Background(), client.ObjectKey{Namespace: "breakglass-debug", Name: "first"}, first))
	second := &corev1.ConfigMap{}
	secondErr := target.Get(context.Background(), client.ObjectKey{Namespace: "breakglass-debug", Name: "second"}, second)
	require.True(t, apierrors.IsNotFound(secondErr), "second pod-template document must be fenced")
}

func TestDeployDebugResourcesFencesEveryAuxiliaryDocument(t *testing.T) {
	c, ds, template, target := newDeploymentFenceFixture(t)
	template.Spec.AuxiliaryResources = []breakglassv1alpha1.AuxiliaryResource{{
		Name: "multi-doc", Category: "configuration", CreateBefore: true,
		TemplateString: "apiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: first\n---\napiVersion: v1\nkind: ConfigMap\nmetadata:\n  name: second\n",
	}}
	ds.Spec.SelectedAuxiliaryResources = []string{"multi-doc"}
	writeBoundaries := 0
	c.beforeDebugTargetWrite = func(_ string) {
		writeBoundaries++
		if writeBoundaries != 3 { // auxiliary phase fence, first document fence, second document fence
			return
		}
		live := &breakglassv1alpha1.DebugSession{}
		require.NoError(t, c.client.Get(context.Background(), client.ObjectKeyFromObject(ds), live))
		live.Status.State = breakglassv1alpha1.DebugSessionStateExpired
		require.NoError(t, c.client.Status().Update(context.Background(), live))
	}
	err := c.deployDebugResources(context.Background(), ds, template)
	t.Logf("deploy error: %v; fence callbacks: %d", err, writeBoundaries)
	require.Error(t, err)
	second := &corev1.ConfigMap{}
	secondErr := target.Get(context.Background(), client.ObjectKey{Namespace: "breakglass-debug", Name: "second"}, second)
	require.True(t, apierrors.IsNotFound(secondErr), "the second document must be fenced, got: %v", secondErr)
}
