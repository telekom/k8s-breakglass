// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package cert

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/uuid"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestLibraryCertificateBootstrapEnvtest(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS required")
	}
	environment := &envtest.Environment{}
	cfg, err := environment.Start()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, environment.Stop()) })
	scheme := runtime.NewScheme()
	require.NoError(t, corev1.AddToScheme(scheme))
	require.NoError(t, admissionv1.AddToScheme(scheme))
	apiClient, err := client.New(cfg, client.Options{Scheme: scheme})
	require.NoError(t, err)
	ctx := context.Background()
	namespace := "cert-library-" + string(uuid.NewUUID())
	require.NoError(t, apiClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: namespace}}))
	key := client.ObjectKey{Namespace: namespace, Name: "webhook"}
	require.NoError(t, apiClient.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace}}))
	webhook := &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: namespace},
		Webhooks: []admissionv1.ValidatingWebhook{{
			Name: "library.example.com", AdmissionReviewVersions: []string{"v1"},
			SideEffects: ptr.To(admissionv1.SideEffectClassNone),
			ClientConfig: admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{
				Name: key.Name, Namespace: key.Namespace,
			}},
		}},
	}
	require.NoError(t, apiClient.Create(ctx, webhook))
	certDir := t.TempDir()
	ready := make(chan struct{})
	leadership := make(chan struct{})
	certManager := NewManager(cfg, key.Name, key.Namespace, certDir, webhook.Name, ready, leadership, zap.NewNop().Sugar())
	require.Nil(t, certManager.rotatorAdder, "exercise the real library registration, not the characterization hook")
	managerCtx, cancel := context.WithCancel(ctx)
	result := make(chan error, 1)
	go func() { result <- certManager.Start(managerCtx, scheme) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-result:
			require.NoError(t, err)
		case <-time.After(10 * time.Second):
			t.Error("certificate manager did not stop")
		}
	})
	secret := &corev1.Secret{}
	require.NoError(t, apiClient.Get(ctx, key, secret))
	require.Empty(t, secret.Data)
	close(leadership)
	require.Eventually(t, func() bool {
		return apiClient.Get(ctx, key, secret) == nil && len(secret.Data[DefaultTLSCertFile]) > 0
	}, 20*time.Second, 50*time.Millisecond)
	initialCA := append([]byte(nil), secret.Data["ca.crt"]...)
	initialLeaf := append([]byte(nil), secret.Data[DefaultTLSCertFile]...)
	require.Eventually(t, func() bool {
		return apiClient.Get(ctx, client.ObjectKeyFromObject(webhook), webhook) == nil &&
			string(webhook.Webhooks[0].ClientConfig.CABundle) == string(secret.Data["ca.crt"])
	}, 10*time.Second, 50*time.Millisecond)
	select {
	case <-ready:
		t.Fatal("library signaled readiness before Secret projection")
	default:
	}
	project := func() {
		t.Helper()
		require.NoError(t, os.WriteFile(filepath.Join(certDir, DefaultTLSCertFile), secret.Data[DefaultTLSCertFile], 0600))
		require.NoError(t, os.WriteFile(filepath.Join(certDir, DefaultTLSKeyFile), secret.Data[DefaultTLSKeyFile], 0600))
		pair, err := tls.LoadX509KeyPair(filepath.Join(certDir, DefaultTLSCertFile), filepath.Join(certDir, DefaultTLSKeyFile))
		require.NoError(t, err)
		leaf, err := x509.ParseCertificate(pair.Certificate[0])
		require.NoError(t, err)
		roots := x509.NewCertPool()
		require.True(t, roots.AppendCertsFromPEM(secret.Data["ca.crt"]))
		for _, dns := range []string{"webhook", "webhook." + namespace + ".svc", "webhook." + namespace + ".svc.cluster.local"} {
			_, err = leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: dns})
			require.NoError(t, err)
		}
		require.Equal(t, "webhook-ca", leaf.Issuer.CommonName)
		require.Equal(t, []string{"breakglass"}, leaf.Issuer.Organization)
	}
	project()
	select {
	case <-ready:
	case <-time.After(20 * time.Second):
		t.Fatal("library readiness did not reach the existing webhook gate")
	}
	require.NoError(t, Ensure(certDir, DefaultTLSCertFile, ready, make(chan error), zap.NewNop().Sugar()))
	delete(secret.Data, DefaultTLSCertFile)
	delete(secret.Data, DefaultTLSKeyFile)
	require.NoError(t, apiClient.Update(ctx, secret))
	require.Eventually(t, func() bool {
		return apiClient.Get(ctx, key, secret) == nil && len(secret.Data[DefaultTLSCertFile]) > 0 &&
			string(secret.Data[DefaultTLSCertFile]) != string(initialLeaf)
	}, 15*time.Second, 50*time.Millisecond)
	require.Equal(t, initialCA, secret.Data["ca.crt"])
	project()
	delete(secret.Data, "ca.key")
	require.NoError(t, apiClient.Update(ctx, secret))
	require.Eventually(t, func() bool {
		return apiClient.Get(ctx, key, secret) == nil && len(secret.Data["ca.key"]) > 0 &&
			string(secret.Data["ca.crt"]) != string(initialCA)
	}, 15*time.Second, 50*time.Millisecond)
	require.Eventually(t, func() bool {
		return apiClient.Get(ctx, client.ObjectKeyFromObject(webhook), webhook) == nil &&
			string(webhook.Webhooks[0].ClientConfig.CABundle) == string(secret.Data["ca.crt"])
	}, 10*time.Second, 50*time.Millisecond)
	project()
	require.NoError(t, Ensure(certDir, DefaultTLSCertFile, ready, make(chan error), zap.NewNop().Sugar()),
		"library rotation preserves the existing no-restart readiness gate")
}
