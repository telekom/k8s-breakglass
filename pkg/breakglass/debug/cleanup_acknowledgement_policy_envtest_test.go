// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"bytes"
	"errors"
	"context"
	"io"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	corev1 "k8s.io/api/core/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes/scheme"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
)

// TestPlatformCleanupAcknowledgementActorPolicyEnvtest proves that the
// ValidatingAdmissionPolicy shipped with the CRD enforces acknowledgedBy
// without the breakglass webhook (#1663).
func TestPlatformCleanupAcknowledgementActorPolicyEnvtest(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS required")
	}
	env := &envtest.Environment{CRDDirectoryPaths: []string{filepath.Join("..", "..", "..", "config", "crd", "bases")}, ErrorIfCRDPathMissing: true}
	cfg, err := env.Start()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, env.Stop()) })
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme.Scheme))
	admin, err := client.New(cfg, client.Options{Scheme: scheme.Scheme})
	require.NoError(t, err)
	ctx := context.Background()

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "crd", "policies", "debugsessioncleanupacknowledgement-actor.yaml"))
	require.NoError(t, err)
	decoder := utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(raw), 4096)
	for {
		obj := &unstructured.Unstructured{}
		err := decoder.Decode(&obj.Object)
		if errors.Is(err, io.EOF) {
			break
		}
		require.NoError(t, err)
		if len(obj.Object) > 0 {
			require.NoError(t, admin.Create(ctx, obj))
		}
	}
	const ns = "ack-policy"
	require.NoError(t, admin.Create(ctx, &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: ns}}))

	const operator = "operator@example.com"
	impersonated := *cfg
	impersonated.Impersonate.UserName = operator
	impersonated.Impersonate.Groups = []string{"system:masters"}
	asOperator, err := client.New(&impersonated, client.Options{Scheme: scheme.Scheme})
	require.NoError(t, err)
	ack := func(name, by string) *breakglassv1alpha1.DebugSessionCleanupAcknowledgement {
		return &breakglassv1alpha1.DebugSessionCleanupAcknowledgement{ObjectMeta: metav1.ObjectMeta{Name: name, Namespace: ns},
			Spec: breakglassv1alpha1.DebugSessionCleanupAcknowledgementSpec{SessionName: "s", SessionUID: "uid", AcknowledgedBy: by,
				Identities: []breakglassv1alpha1.CleanupAcknowledgedIdentity{{APIVersion: "v1", Kind: "ConfigMap", Name: "x"}}}}
	}
	// The policy takes effect asynchronously after it is created.
	require.Eventually(t, func() bool {
		err := asOperator.Create(ctx, ack("probe-"+time.Now().Format("150405.000000"), "someone-else"))
		return apierrors.IsInvalid(err)
	}, 30*time.Second, 200*time.Millisecond, "a forged acknowledgedBy must be rejected by the API server")
	assert.NoError(t, asOperator.Create(ctx, ack("genuine", operator)))
}
