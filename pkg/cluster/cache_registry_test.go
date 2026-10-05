// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package cluster

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/t-caas-go-library/pkg/remoteclient"
	"go.uber.org/zap/zaptest"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/controller-runtime/pkg/client/fake"
)

func registryTestProvider(t *testing.T, data []byte) (*ClientProvider, *corev1.Secret) {
	t.Helper()
	secret := &corev1.Secret{
		ObjectMeta: metav1.ObjectMeta{Namespace: "registry", Name: "credentials"},
		Data:       map[string][]byte{"value": data},
	}
	cc := &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Namespace: "registry", Name: "target", UID: "target-uid"},
		Spec: breakglassv1alpha1.ClusterConfigSpec{
			KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{Namespace: secret.Namespace, Name: secret.Name},
		},
	}
	live := fake.NewClientBuilder().WithScheme(testScheme()).WithObjects(cc, secret).Build()
	return NewClientProvider(live, zaptest.NewLogger(t).Sugar()).WithLiveReader(live), secret
}

func TestKubeconfigRegistryReusesFreshPrivilegedClient(t *testing.T) {
	p, _ := registryTestProvider(t, mustBuildKubeconfigYAML("https://target.example"))
	ctx := context.Background()
	target, snapshot, err := p.GetClientForPrivilegedOperation(ctx, "registry/target")
	require.NoError(t, err)
	defer p.ReleasePrivilegedOperationClusterConfig(snapshot)
	registered, ok := p.remoteClients.Get(types.NamespacedName{Namespace: "registry", Name: "target"})
	require.True(t, ok)
	require.Same(t, registered, target)
	require.NoError(t, p.ValidatePrivilegedOperationClusterConfig(ctx, snapshot))
	p.Invalidate("registry", "target")
	_, ok = p.remoteClients.Get(types.NamespacedName{Namespace: "registry", Name: "target"})
	require.False(t, ok)
}

func TestKubeconfigFactoryDoesNotRetainConfigArgument(t *testing.T) {
	p, _ := registryTestProvider(t, mustBuildKubeconfigYAML("https://target.example"))
	original, err := clientcmd.RESTConfigFromKubeConfig(mustBuildKubeconfigYAML("https://target.example"))
	require.NoError(t, err)
	originalWrapped, copiedWrapped := false, false
	original.WrapTransport = func(transport http.RoundTripper) http.RoundTripper {
		originalWrapped = true
		return transport
	}
	build := &kubeconfigClientBuild{cluster: &breakglassv1alpha1.ClusterConfig{
		ObjectMeta: metav1.ObjectMeta{Namespace: "registry", Name: "target"},
	}}
	ctx := context.WithValue(context.Background(), kubeconfigClientBuildKey{}, build)
	remote, err := p.newKubeconfigClient(ctx, original, &http.Client{Transport: http.DefaultTransport})
	require.NoError(t, err)
	require.NotNil(t, remote)
	require.NotSame(t, original, build.config, "the registry adapter stores a provider-owned copy")
	build.config.Host = "https://different.example"
	build.config.WrapTransport = func(transport http.RoundTripper) http.RoundTripper {
		copiedWrapped = true
		return transport
	}
	require.Equal(t, "https://target.example", original.Host)
	original.WrapTransport(http.DefaultTransport)
	require.True(t, originalWrapped)
	require.False(t, copiedWrapped, "later provider mutations do not alter the factory argument")
}

func TestKubeconfigRegistryPreservesLazyTransportErrors(t *testing.T) {
	p, secret := registryTestProvider(t, mustBuildKubeconfigYAML("https://target.example"))
	ctx := context.Background()
	_, err := p.GetRESTConfig(ctx, "registry/target")
	require.NoError(t, err)
	key := types.NamespacedName{Namespace: "registry", Name: "target"}
	old, ok := p.remoteClients.Get(key)
	require.True(t, ok)
	raw, err := clientcmd.Load(secret.Data["value"])
	require.NoError(t, err)
	cluster := raw.Clusters[raw.Contexts[raw.CurrentContext].Cluster]
	cluster.InsecureSkipTLSVerify = false
	cluster.CertificateAuthorityData = []byte("invalid CA")
	secret.Data["value"], err = clientcmd.Write(*raw)
	require.NoError(t, err)
	require.NoError(t, p.k8s.Update(ctx, secret))
	p.rest["registry/target"].expiresAt = time.Now().Add(-time.Second)
	cfg, err := p.GetRESTConfig(ctx, "registry/target")
	require.NoError(t, err, "transport errors remain deferred until a client is needed")
	require.Equal(t, []byte("invalid CA"), cfg.CAData)
	registered, ok := p.remoteClients.Get(key)
	require.True(t, ok, "the library preserves the previous client after failed refresh")
	require.Same(t, old, registered)
	require.NotSame(t, cfg, registered.(*kubeconfigClientBuild).config)
	require.True(t, p.IsSecretTracked(secret.Namespace, secret.Name))
	target, snapshot, err := p.GetClientForPrivilegedOperation(ctx, "registry/target")
	require.Error(t, err, "a privileged operation must not receive the previous valid client")
	require.Nil(t, target)
	require.Nil(t, snapshot)
	require.Empty(t, p.privilegedInputVersions)
	p.InvalidateSecret(secret.Namespace, secret.Name)
	_, ok = p.remoteClients.Get(key)
	require.False(t, ok)
	require.False(t, p.IsSecretTracked(secret.Namespace, secret.Name))
}

func TestKubeconfigRegistryRequiresEmbeddedCredentials(t *testing.T) {
	for _, kind := range []string{"exec", "auth-provider", "token-file", "certificate-file", "key-file", "ca-file"} {
		for _, placement := range []string{"active", "unused"} {
			t.Run(kind+"/"+placement, func(t *testing.T) {
				raw, err := clientcmd.Load(mustBuildKubeconfigYAML("https://target.example"))
				require.NoError(t, err)
				active := raw.Contexts[raw.CurrentContext]
				auth, cluster := raw.AuthInfos[active.AuthInfo], raw.Clusters[active.Cluster]
				if placement == "unused" {
					auth, cluster = &clientcmdapi.AuthInfo{}, &clientcmdapi.Cluster{Server: "https://unused.example"}
					raw.AuthInfos["unused"], raw.Clusters["unused"] = auth, cluster
				}
				const marker = "private-credential-marker"
				switch kind {
				case "exec":
					auth.Exec = &clientcmdapi.ExecConfig{Command: marker}
				case "auth-provider":
					auth.AuthProvider = &clientcmdapi.AuthProviderConfig{Name: marker}
				case "token-file":
					auth.TokenFile = marker
				case "certificate-file":
					auth.ClientCertificate = marker
				case "key-file":
					auth.ClientKey = marker
				case "ca-file":
					cluster.CertificateAuthority = marker
				}
				data, err := clientcmd.Write(*raw)
				require.NoError(t, err)
				if placement == "unused" {
					native, err := clientcmd.RESTConfigFromKubeConfig(data)
					require.NoError(t, err, "unused entries do not affect the selected native config")
					require.Equal(t, "https://target.example", native.Host)
				}
				p, _ := registryTestProvider(t, data)
				cfg, err := p.GetRESTConfig(context.Background(), "registry/target")
				require.ErrorIs(t, err, remoteclient.ErrInvalidKubeconfig)
				require.NotContains(t, err.Error(), marker)
				require.Nil(t, cfg)
			})
		}
	}
}
