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

	"github.com/open-policy-agent/cert-controller/pkg/rotator"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	admissionv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	kptr "k8s.io/utils/ptr"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

func TestPlatformCertBootstrapRotationEnvtest(t *testing.T) {
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
	require.NoError(t, apiClient.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "cert-platform"}}))
	key := client.ObjectKey{Namespace: "cert-platform", Name: "webhook"}
	// Production manifests supply the empty Secret; envtest has no kubelet
	// to project the generated Secret into the serving-certificate directory.
	require.NoError(t, apiClient.Create(ctx, &corev1.Secret{ObjectMeta: metav1.ObjectMeta{Name: key.Name, Namespace: key.Namespace}}))
	webhook := &admissionv1.ValidatingWebhookConfiguration{
		ObjectMeta: metav1.ObjectMeta{Name: "platform-cert"},
		Webhooks: []admissionv1.ValidatingWebhook{{
			Name: "platform.example.com", AdmissionReviewVersions: []string{"v1"},
			SideEffects: kptr.To(admissionv1.SideEffectClassNone),
			ClientConfig: admissionv1.WebhookClientConfig{Service: &admissionv1.ServiceReference{
				Name: key.Name, Namespace: key.Namespace,
			}},
		}},
	}
	require.NoError(t, apiClient.Create(ctx, webhook))
	certDir := t.TempDir()
	ready := make(chan struct{})
	leadership := make(chan struct{})
	manager := NewManager(cfg, key.Name, key.Namespace, certDir, webhook.Name, ready, leadership, zap.NewNop().Sugar())
	manager.rotatorAdder = func(mgr ctrl.Manager, cr *rotator.CertRotator) error {
		cr.RotationCheckFrequency = 100 * time.Millisecond
		return rotator.AddRotator(mgr, cr)
	}
	managerCtx, cancel := context.WithCancel(ctx)
	managerResult := make(chan error, 1)
	go func() { managerResult <- manager.Start(managerCtx, scheme) }()
	t.Cleanup(func() {
		cancel()
		select {
		case err := <-managerResult:
			require.NoError(t, err)
		case <-time.After(10 * time.Second):
			t.Error("certificate manager did not stop")
		}
	})
	secret := &corev1.Secret{}
	require.NoError(t, apiClient.Get(ctx, key, secret))
	require.Empty(t, secret.Data, "external leadership gates certificate bootstrap")
	select {
	case <-ready:
		t.Fatal("webhook ready before leadership and certificate projection")
	default:
	}
	close(leadership)
	require.Eventually(t, func() bool {
		return apiClient.Get(ctx, key, secret) == nil && len(secret.Data[DefaultTLSCertFile]) > 0
	}, 20*time.Second, 50*time.Millisecond)
	initialCA := append([]byte(nil), secret.Data["ca.crt"]...)
	initialLeaf := append([]byte(nil), secret.Data[DefaultTLSCertFile]...)
	require.Eventually(t, func() bool {
		return apiClient.Get(ctx, client.ObjectKeyFromObject(webhook), webhook) == nil &&
			string(webhook.Webhooks[0].ClientConfig.CABundle) == string(initialCA)
	}, 10*time.Second, 50*time.Millisecond)
	select {
	case <-ready:
		t.Fatal("CA injection alone must not signal readiness without projected files")
	default:
	}
	project := func() {
		t.Helper()
		require.NoError(t, os.WriteFile(filepath.Join(certDir, DefaultTLSCertFile), secret.Data[DefaultTLSCertFile], 0600))
		require.NoError(t, os.WriteFile(filepath.Join(certDir, DefaultTLSKeyFile), secret.Data[DefaultTLSKeyFile], 0600))
		pair, loadErr := tls.LoadX509KeyPair(filepath.Join(certDir, DefaultTLSCertFile), filepath.Join(certDir, DefaultTLSKeyFile))
		require.NoError(t, loadErr)
		leaf, parseErr := x509.ParseCertificate(pair.Certificate[0])
		require.NoError(t, parseErr)
		roots := x509.NewCertPool()
		require.True(t, roots.AppendCertsFromPEM(secret.Data["ca.crt"]))
		for _, dns := range []string{"webhook", "webhook.cert-platform.svc", "webhook.cert-platform.svc.cluster.local"} {
			_, verifyErr := leaf.Verify(x509.VerifyOptions{Roots: roots, DNSName: dns})
			require.NoError(t, verifyErr)
		}
		require.Equal(t, "webhook-ca", leaf.Issuer.CommonName)
		require.Equal(t, []string{"breakglass"}, leaf.Issuer.Organization)
	}
	project()
	select {
	case <-ready:
	case <-time.After(20 * time.Second):
		t.Fatal("webhook readiness was not signaled")
	}
	require.NoError(t, Ensure(certDir, DefaultTLSCertFile, ready, make(chan error), zap.NewNop().Sugar()))

	delete(secret.Data, DefaultTLSCertFile)
	delete(secret.Data, DefaultTLSKeyFile)
	require.NoError(t, apiClient.Update(ctx, secret))
	require.Eventually(t, func() bool {
		return apiClient.Get(ctx, key, secret) == nil && len(secret.Data[DefaultTLSCertFile]) > 0 &&
			string(secret.Data[DefaultTLSCertFile]) != string(initialLeaf)
	}, 15*time.Second, 50*time.Millisecond)
	require.Equal(t, initialCA, secret.Data["ca.crt"], "leaf refresh preserves a valid CA")
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
		"rotation keeps the manager running and the readiness channel usable")
}
