// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap/zaptest"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
)

// TestCreateImpersonatedClient_DoesNotPoisonSharedRESTConfig is a regression test
// for a cross-request identity-confusion bug.
//
// ClientProvider.GetRESTConfig returns a POINTER INTO ITS TTL CACHE: every caller
// for the same spoke receives the same *rest.Config. The webhook's RBAC probe and
// per-session SubjectAccessReview checks call it on every authorization decision.
//
// If createImpersonatedClient writes Impersonate onto that shared pointer, then for
// the remainder of the cache TTL every unrelated request for that spoke silently
// runs as the debug session's impersonated ServiceAccount. In an authorization
// webhook that is both a wrong-allow and a wrong-deny risk: probes answer for the
// wrong identity.
//
// Before the fix this test fails with the shared config carrying
// Impersonate.UserName == "system:serviceaccount:kube-system:debugger".
func TestCreateImpersonatedClient_DoesNotPoisonSharedRESTConfig(t *testing.T) {
	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))

	const clusterName = "default/spoke-a"

	kubeconfig := clientcmdapi.Config{
		APIVersion:     "v1",
		Kind:           "Config",
		Clusters:       map[string]*clientcmdapi.Cluster{"c": {Server: "https://spoke-a.example.com:6443"}},
		AuthInfos:      map[string]*clientcmdapi.AuthInfo{"u": {}},
		Contexts:       map[string]*clientcmdapi.Context{"ctx": {Cluster: "c", AuthInfo: "u"}},
		CurrentContext: "ctx",
	}
	raw, err := clientcmd.Write(kubeconfig)
	require.NoError(t, err)

	cc := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Name: "spoke-a", Namespace: "default"},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{
				Name: "spoke-a-kubeconfig", Namespace: "default",
			},
		},
	}
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Name: "spoke-a-kubeconfig", Namespace: "default"},
		Data:       map[string][]byte{"value": raw},
	}

	fakeClient := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cc, secret).Build()
	log := zaptest.NewLogger(t).Sugar()
	provider := cluster.NewClientProvider(fakeClient, log)

	ctx := context.Background()

	// The shared, cached config that every other caller for this spoke will get.
	shared, err := provider.GetRESTConfig(ctx, clusterName)
	require.NoError(t, err)
	require.Empty(t, shared.Impersonate.UserName,
		"precondition: the cached config must start out un-impersonated")

	controller := NewDebugSessionController(log, fakeClient, provider)

	impConfig := &breakglassv1alpha1.ImpersonationConfig{
		ServiceAccountRef: &breakglassv1alpha1.ServiceAccountReference{
			Name: "debugger", Namespace: "kube-system",
		},
	}

	_, err = controller.createImpersonatedClient(ctx, clusterName, impConfig)
	require.NoError(t, err)

	// The shared cached pointer must be untouched.
	assert.Empty(t, shared.Impersonate.UserName,
		"createImpersonatedClient mutated the SHARED cached rest.Config; for the rest of the "+
			"cache TTL every request for this spoke — including the webhook's RBAC probe and "+
			"session SAR checks — would silently run as the impersonated ServiceAccount")
	assert.Empty(t, shared.Impersonate.Groups)

	// And the next caller must still get a clean config.
	again, err := provider.GetRESTConfig(ctx, clusterName)
	require.NoError(t, err)
	assert.Same(t, shared, again, "precondition: the provider hands out a shared pointer")
	assert.Empty(t, again.Impersonate.UserName,
		"a subsequent unrelated caller inherited the debug session's impersonated identity")
}

// TestApplyImpersonation_MutatesOnlyTheCopyItIsGiven documents the narrower
// contract: applyImpersonation is allowed to write to the config it receives, so the
// duty to copy belongs to the caller.
func TestApplyImpersonation_MutatesOnlyTheCopyItIsGiven(t *testing.T) {
	base := &rest.Config{Host: "https://spoke.example.com"}
	copied := rest.CopyConfig(base)

	c := &DebugSessionController{log: zaptest.NewLogger(t).Sugar()}

	err := c.applyImpersonation(context.Background(), copied, "spoke",
		&breakglassv1alpha1.ImpersonationConfig{
			ServiceAccountRef: &breakglassv1alpha1.ServiceAccountReference{
				Name: "debugger", Namespace: "kube-system",
			},
		})
	require.NoError(t, err)

	assert.Equal(t, "system:serviceaccount:kube-system:debugger", copied.Impersonate.UserName,
		"applyImpersonation must set the identity on the config it was handed")
	assert.Empty(t, base.Impersonate.UserName,
		"the original config must be untouched")
}

func TestCreateImpersonatedClientFromRESTConfigUsesValidatedBase(t *testing.T) {
	controller := &DebugSessionController{log: zaptest.NewLogger(t).Sugar()}
	base := &rest.Config{Host: "https://spoke.example.com"}

	client, err := controller.createImpersonatedClientFromRESTConfig(
		context.Background(), base, "spoke", &breakglassv1alpha1.ImpersonationConfig{
			ServiceAccountRef: &breakglassv1alpha1.ServiceAccountReference{Namespace: "kube-system", Name: "debugger"},
		})
	require.NoError(t, err)
	require.NotNil(t, client)
	assert.Empty(t, base.Impersonate.UserName, "validated base config must not be mutated")
}
