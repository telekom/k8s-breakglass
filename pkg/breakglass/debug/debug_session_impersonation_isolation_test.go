/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package debug

import (
	"context"
	"sync"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/pkg/cluster"
)

// impersonationTestClusterName is the namespaced cluster key used by the fixtures below.
const impersonationTestClusterName = "default/spoke-a"

// newImpersonationTestController wires a DebugSessionController onto a real
// cluster.ClientProvider backed by a fake hub client holding a valid kubeconfig
// Secret. Using the real provider (rather than a stub) is deliberate: the defect
// under test is that GetRESTConfig hands back the *shared cached pointer*, and only
// the real provider reproduces that caching behaviour.
func newImpersonationTestController(t *testing.T) *DebugSessionController {
	t.Helper()

	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))

	kubeconfig, err := clientcmd.Write(clientcmdapi.Config{
		APIVersion:     "v1",
		Kind:           "Config",
		Clusters:       map[string]*clientcmdapi.Cluster{"spoke": {Server: "https://spoke-a.example.com:6443"}},
		AuthInfos:      map[string]*clientcmdapi.AuthInfo{"admin": {Token: "hub-controller-token"}},
		Contexts:       map[string]*clientcmdapi.Context{"ctx": {Cluster: "spoke", AuthInfo: "admin"}},
		CurrentContext: "ctx",
	})
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
		Data:       map[string][]byte{"value": kubeconfig},
	}

	hub := fake.NewClientBuilder().WithScheme(scheme).WithObjects(cc, secret).Build()

	return &DebugSessionController{
		log:        zap.NewNop().Sugar(),
		client:     hub,
		ccProvider: cluster.NewClientProvider(hub, zap.NewNop().Sugar()),
	}
}

func saImpersonation(namespace, name string) *breakglassv1alpha1.ImpersonationConfig {
	return &breakglassv1alpha1.ImpersonationConfig{
		ServiceAccountRef: &breakglassv1alpha1.ServiceAccountReference{
			Namespace: namespace,
			Name:      name,
		},
	}
}

// TestCreateImpersonatedClient_DoesNotPoisonSharedCachedRESTConfig pins the defect.
//
// createImpersonatedClient obtains the spoke REST config from
// ClientProvider.GetRESTConfig, which returns the SHARED cached *rest.Config pointer.
// Before the fix it wrote Impersonate directly onto that shared object, so the
// impersonation identity of one DebugSession leaked onto the cache entry and every
// later consumer of the same spoke config silently acted as that ServiceAccount until
// the TTL expired.
//
// Assertion: after impersonating on a client built for session A, a fresh
// GetRESTConfig for the same cluster must still be un-impersonated.
func TestCreateImpersonatedClient_DoesNotPoisonSharedCachedRESTConfig(t *testing.T) {
	c := newImpersonationTestController(t)
	ctx := context.Background()

	// Warm the cache and record the pristine state of the shared entry.
	shared, err := c.ccProvider.GetRESTConfig(ctx, impersonationTestClusterName)
	require.NoError(t, err)
	require.Empty(t, shared.Impersonate.UserName, "precondition: cached config must start un-impersonated")

	// Session A impersonates a ServiceAccount on the spoke.
	_, err = c.createImpersonatedClient(ctx, impersonationTestClusterName,
		saImpersonation("kube-system", "debug-sa"))
	require.NoError(t, err)

	// The shared cached object must be untouched.
	assert.Empty(t, shared.Impersonate.UserName,
		"impersonation leaked onto the SHARED cached rest.Config; every other consumer "+
			"of this spoke's config would now act as the impersonated ServiceAccount")

	// And an independent consumer obtaining the config again must see no impersonation.
	again, err := c.ccProvider.GetRESTConfig(ctx, impersonationTestClusterName)
	require.NoError(t, err)
	assert.Same(t, shared, again, "provider is expected to hand back the same cached pointer")
	assert.Empty(t, again.Impersonate.UserName,
		"a subsequent unrelated consumer inherited impersonation from an earlier DebugSession")
}

// TestCreateImpersonatedClient_SessionsDoNotSeeEachOthersIdentity asserts the
// per-session isolation that the shared-pointer mutation destroyed: two sessions
// impersonating different ServiceAccounts against the same spoke must not observe
// each other's identity, and neither may reach the cache entry.
func TestCreateImpersonatedClient_SessionsDoNotSeeEachOthersIdentity(t *testing.T) {
	c := newImpersonationTestController(t)
	ctx := context.Background()

	shared, err := c.ccProvider.GetRESTConfig(ctx, impersonationTestClusterName)
	require.NoError(t, err)

	_, err = c.createImpersonatedClient(ctx, impersonationTestClusterName,
		saImpersonation("team-a", "sa-a"))
	require.NoError(t, err)
	assert.Empty(t, shared.Impersonate.UserName, "session A poisoned the cache")

	_, err = c.createImpersonatedClient(ctx, impersonationTestClusterName,
		saImpersonation("team-b", "sa-b"))
	require.NoError(t, err)
	assert.Empty(t, shared.Impersonate.UserName, "session B poisoned the cache")
}

// TestCreateImpersonatedClient_NoImpersonationConfigIsUnchanged proves the
// non-buggy path is behaviour-identical: with no impersonation configured, nothing
// is written and the client is built from an un-impersonated config.
func TestCreateImpersonatedClient_NoImpersonationConfigIsUnchanged(t *testing.T) {
	c := newImpersonationTestController(t)
	ctx := context.Background()

	shared, err := c.ccProvider.GetRESTConfig(ctx, impersonationTestClusterName)
	require.NoError(t, err)

	for name, impConfig := range map[string]*breakglassv1alpha1.ImpersonationConfig{
		"nil config":                    nil,
		"config without serviceAccount": {},
	} {
		t.Run(name, func(t *testing.T) {
			client, err := c.createImpersonatedClient(ctx, impersonationTestClusterName, impConfig)
			require.NoError(t, err)
			assert.NotNil(t, client)
			assert.Empty(t, shared.Impersonate.UserName)
		})
	}

	// Non-impersonation fields of the shared config must survive untouched.
	assert.Equal(t, "https://spoke-a.example.com:6443", shared.Host)
	assert.Equal(t, "hub-controller-token", shared.BearerToken)
}

// TestCreateImpersonatedClient_ConcurrentSessionsAreRaceFree exercises the data-race
// half of the defect. Run under `go test -race`: concurrent reconciles writing
// Impersonate onto one shared struct is an unsynchronised write, which the race
// detector reports. Copying first removes the shared write entirely.
func TestCreateImpersonatedClient_ConcurrentSessionsAreRaceFree(t *testing.T) {
	c := newImpersonationTestController(t)
	ctx := context.Background()

	// Warm the cache so every goroutine takes the cache-hit path that returns the
	// shared pointer.
	shared, err := c.ccProvider.GetRESTConfig(ctx, impersonationTestClusterName)
	require.NoError(t, err)

	const goroutines = 16
	var wg sync.WaitGroup
	errs := make([]error, goroutines)

	for i := range goroutines {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			// Half impersonate, half just read the config concurrently — the mix of
			// concurrent read and write on the shared object is what races.
			if idx%2 == 0 {
				_, errs[idx] = c.createImpersonatedClient(ctx, impersonationTestClusterName,
					saImpersonation("team", "sa"))
				return
			}
			_, errs[idx] = c.ccProvider.GetRESTConfig(ctx, impersonationTestClusterName)
		}(i)
	}
	wg.Wait()

	for i, err := range errs {
		require.NoError(t, err, "goroutine %d", i)
	}
	assert.Empty(t, shared.Impersonate.UserName,
		"concurrent sessions mutated the shared cached rest.Config")
}
