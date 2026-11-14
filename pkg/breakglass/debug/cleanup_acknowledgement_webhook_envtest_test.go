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
	admissionregistrationv1 "k8s.io/api/admissionregistration/v1"
	corev1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	clientgoscheme "k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
	"sigs.k8s.io/controller-runtime/pkg/webhook"
)

// TestPlatformCleanupAcknowledgementWebhookEnvtest proves the breakglass
// validating webhook itself, served to a real API server from
// config/webhook and without the optional ValidatingAdmissionPolicy:
// it rejects a forged acknowledgedBy on CREATE and any spec change on
// UPDATE, even on a CRD without the CEL rule self == oldSelf (hubs where CEL
// validation is not enforced).
func TestPlatformCleanupAcknowledgementWebhookEnvtest(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS required")
	}
	root := filepath.Join("..", "..", "..")
	crd := readYAML[apiextensionsv1.CustomResourceDefinition](t, filepath.Join(root, "config", "crd", "bases", "breakglass.t-caas.telekom.com_debugsessioncleanupacknowledgements.yaml"))
	for i := range crd.Spec.Versions {
		spec := crd.Spec.Versions[i].Schema.OpenAPIV3Schema.Properties["spec"]
		require.NotEmpty(t, spec.XValidations, "the shipped CRD carries the CEL immutability rule")
		spec.XValidations = nil // only the webhook can reject spec changes now
		crd.Spec.Versions[i].Schema.OpenAPIV3Schema.Properties["spec"] = spec
	}
	webhooks := readYAML[admissionregistrationv1.ValidatingWebhookConfiguration](t, filepath.Join(root, "config", "webhook", "manifests.yaml"))
	var ackWebhook []admissionregistrationv1.ValidatingWebhook
	for _, w := range webhooks.Webhooks {
		if w.Name == cleanupAcknowledgementWebhookName {
			ackWebhook = append(ackWebhook, w)
		}
	}
	require.Len(t, ackWebhook, 1, "config/webhook registers the acknowledgement webhook")
	webhooks.Webhooks = ackWebhook

	env := &envtest.Environment{
		CRDInstallOptions:     envtest.CRDInstallOptions{CRDs: []*apiextensionsv1.CustomResourceDefinition{crd}},
		WebhookInstallOptions: envtest.WebhookInstallOptions{ValidatingWebhooks: []*admissionregistrationv1.ValidatingWebhookConfiguration{webhooks}},
	}
	cfg, err := env.Start()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, env.Stop()) })

	scheme := runtime.NewScheme()
	require.NoError(t, clientgoscheme.AddToScheme(scheme))
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme))
	opts := env.WebhookInstallOptions
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{Scheme: scheme, Metrics: metricsserver.Options{BindAddress: "0"},
		WebhookServer: webhook.NewServer(webhook.Options{Host: opts.LocalServingHost, Port: opts.LocalServingPort, CertDir: opts.LocalServingCertDir})})
	require.NoError(t, err)
	require.NoError(t, (&breakglassv1alpha1.DebugSessionCleanupAcknowledgement{}).SetupWebhookWithManager(mgr))
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = mgr.Start(ctx) }()

	admin, err := client.New(cfg, client.Options{Scheme: scheme})
	require.NoError(t, err)
	const ns = "ack-webhook"
	require.NoError(t, admin.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}))
	const operator = "operator@example.com"
	impersonated := *cfg
	impersonated.Impersonate.UserName = operator
	impersonated.Impersonate.Groups = []string{"system:masters"}
	asOperator, err := client.New(&impersonated, client.Options{Scheme: scheme})
	require.NoError(t, err)
	ack := func(name, by string) *breakglassv1alpha1.DebugSessionCleanupAcknowledgement {
		return &breakglassv1alpha1.DebugSessionCleanupAcknowledgement{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Spec: breakglassv1alpha1.DebugSessionCleanupAcknowledgementSpec{SessionName: "s", SessionUID: "uid", AcknowledgedBy: by, Reason: "CHG-1",
				Identities: []breakglassv1alpha1.CleanupAcknowledgedIdentity{{APIVersion: "v1", Kind: "ConfigMap", Name: "x"}}}}
	}

	// CREATE: the webhook (not a policy) rejects a forged actor.
	var forged error
	require.Eventually(t, func() bool {
		forged = asOperator.Create(ctx, ack("forged", "someone-else"))
		return apierrors.IsInvalid(forged)
	}, 30*time.Second, 200*time.Millisecond, "the webhook server must start serving")
	assert.ErrorContains(t, forged, `must equal the requesting user "operator@example.com"`)
	genuine := ack("genuine", operator)
	require.NoError(t, asOperator.Create(ctx, genuine))

	// UPDATE: metadata may change (the retention finalizer), the spec not.
	genuine.Labels = map[string]string{"x": "y"}
	require.NoError(t, asOperator.Update(ctx, genuine), "metadata changes are allowed")
	genuine.Spec.AcknowledgedBy = "someone-else"
	err = asOperator.Update(ctx, genuine)
	require.True(t, apierrors.IsInvalid(err), "a spec change must be rejected, got %v", err)
	assert.ErrorContains(t, err, "is immutable")
}

// readYAML decodes the single object in path.
func readYAML[T any](t *testing.T, path string) *T {
	t.Helper()
	f, err := os.Open(path)
	require.NoError(t, err)
	defer func() { _ = f.Close() }()
	obj := new(T)
	require.NoError(t, utilyaml.NewYAMLOrJSONDecoder(f, 4096).Decode(obj))
	return obj
}
