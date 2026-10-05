// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package clusterconfig

import (
	"context"
	"os"
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/t-caas-go-library/pkg/remoteclient"
	"go.uber.org/zap/zaptest"
	corev1 "k8s.io/api/core/v1"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/tools/clientcmd"
	clientcmdapi "k8s.io/client-go/tools/clientcmd/api"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestClusterConfigReadinessEmbeddedKubeconfig(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("envtest assets required; run make test-cluster-clients")
	}
	environment := &envtest.Environment{CRDDirectoryPaths: []string{"../../../config/crd/bases"}, ErrorIfCRDPathMissing: true}
	config, err := environment.Start()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, environment.Stop()) })
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	live, err := client.New(config, client.Options{Scheme: scheme})
	require.NoError(t, err)
	ctx := context.Background()
	require.NoError(t, live.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "embedded-readiness"}}))
	checker := ClusterConfigChecker{Client: live, Log: zaptest.NewLogger(t).Sugar()}

	for _, kind := range []string{"embedded", "exec", "auth-provider", "token-file", "certificate-file", "key-file", "ca-file"} {
		for _, placement := range []string{"active", "unused"} {
			t.Run(kind+"/"+placement, func(t *testing.T) {
				raw := clientcmdapi.Config{
					Clusters: map[string]*clientcmdapi.Cluster{"target": {Server: config.Host, CertificateAuthorityData: config.CAData}},
					AuthInfos: map[string]*clientcmdapi.AuthInfo{"admin": {
						ClientCertificateData: config.CertData, ClientKeyData: config.KeyData,
					}},
					Contexts:       map[string]*clientcmdapi.Context{"target": {Cluster: "target", AuthInfo: "admin"}},
					CurrentContext: "target",
				}
				auth, target := raw.AuthInfos["admin"], raw.Clusters["target"]
				if placement == "unused" {
					auth, target = &clientcmdapi.AuthInfo{}, &clientcmdapi.Cluster{Server: "https://unused.example"}
					raw.AuthInfos["unused"], raw.Clusters["unused"] = auth, target
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
					target.CertificateAuthority = marker
				}
				data, err := clientcmd.Write(raw)
				require.NoError(t, err)
				if placement == "unused" {
					_, err := clientcmd.RESTConfigFromKubeConfig(data)
					require.NoError(t, err)
				}
				name := kind + "-" + placement
				secret := &corev1.Secret{
					ObjectMeta: metav1.ObjectMeta{Namespace: "embedded-readiness", Name: name},
					Data:       map[string][]byte{"value": data},
				}
				require.NoError(t, live.Create(ctx, secret))
				cc := &breakglassv1alpha1.ClusterConfig{
					ObjectMeta: metav1.ObjectMeta{Namespace: secret.Namespace, Name: name},
					Spec: breakglassv1alpha1.ClusterConfigSpec{
						KubeconfigSecretRef: &breakglassv1alpha1.SecretKeyReference{Namespace: secret.Namespace, Name: secret.Name},
					},
				}
				require.NoError(t, live.Create(ctx, cc))
				if kind != "embedded" {
					cc.Status.Conditions = []metav1.Condition{{
						Type: "Ready", Status: metav1.ConditionTrue, Reason: "PreviouslyReady",
						Message: "before credential restriction", LastTransitionTime: metav1.Now(),
					}}
					require.NoError(t, live.Status().Update(ctx, cc))
					_, err := RestConfigFromKubeConfig(data)
					require.ErrorIs(t, err, remoteclient.ErrInvalidKubeconfig)
					require.NotContains(t, err.Error(), marker)
				}
				checker.runOnce(ctx, checker.Log)
				require.NoError(t, live.Get(ctx, client.ObjectKeyFromObject(cc), cc))
				ready := apimeta.FindStatusCondition(cc.Status.Conditions, "Ready")
				require.NotNil(t, ready)
				if kind == "embedded" {
					require.Equal(t, metav1.ConditionTrue, ready.Status, "embedded credentials reach the real API")
				} else {
					require.Equal(t, metav1.ConditionFalse, ready.Status, "unusable credentials cannot remain Ready")
					require.Equal(t, "KubeconfigParseFailed", ready.Reason)
					require.NotContains(t, ready.Message, marker)
				}
				require.NoError(t, live.Delete(ctx, cc))
				require.NoError(t, live.Delete(ctx, secret))
			})
		}
	}
}
