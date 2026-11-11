// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"bytes"
	"context"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"go.uber.org/zap"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	utilyaml "k8s.io/apimachinery/pkg/util/yaml"
	"k8s.io/client-go/kubernetes/scheme"
	ctrl "sigs.k8s.io/controller-runtime"
	"sigs.k8s.io/controller-runtime/pkg/client"
	"sigs.k8s.io/controller-runtime/pkg/envtest"
	metricsserver "sigs.k8s.io/controller-runtime/pkg/metrics/server"
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

	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "components", "cleanup-acknowledgement-policy", "policy.yaml"))
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

	// An acknowledger holding only the shipped ClusterRole cannot write the
	// acknowledgement status, so it can neither forge an outcome nor block
	// processing with a claim.
	roleRaw, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "rbac", "debugsession_cleanup_acknowledger_role.yaml"))
	require.NoError(t, err)
	role := &rbacv1.ClusterRole{}
	require.NoError(t, utilyaml.NewYAMLOrJSONDecoder(bytes.NewReader(roleRaw), 4096).Decode(role))
	require.NoError(t, admin.Create(ctx, role))
	const acknowledger = "acknowledger@example.com"
	require.NoError(t, admin.Create(ctx, &rbacv1.ClusterRoleBinding{ObjectMeta: metav1.ObjectMeta{Name: "acknowledger"},
		RoleRef:  rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "ClusterRole", Name: role.Name},
		Subjects: []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: rbacv1.UserKind, Name: acknowledger}}}))
	limited := *cfg
	limited.Impersonate.UserName = acknowledger
	limited.Impersonate.Groups = []string{"system:authenticated"}
	asAcknowledger, err := client.New(&limited, client.Options{Scheme: scheme.Scheme})
	require.NoError(t, err)
	own := ack("own", acknowledger)
	require.Eventually(t, func() bool { return asAcknowledger.Create(ctx, own) == nil }, 30*time.Second, 200*time.Millisecond, "the role grants create")
	now := metav1.Now()
	own.Status = breakglassv1alpha1.DebugSessionCleanupAcknowledgementObjectStatus{Phase: breakglassv1alpha1.CleanupAcknowledgementApplied, ProcessedAt: &now}
	err = asAcknowledger.Status().Update(ctx, own)
	require.True(t, apierrors.IsForbidden(err), "acknowledgers must not write the acknowledgement status, got %v", err)
}

// TestPlatformControllerStartsWithoutAcknowledgementCRDEnvtest proves that
// the DebugSession controller still sets up on a hub without the optional
// DebugSessionCleanupAcknowledgement CRD.
func TestPlatformControllerStartsWithoutAcknowledgementCRDEnvtest(t *testing.T) {
	if os.Getenv("KUBEBUILDER_ASSETS") == "" {
		t.Skip("KUBEBUILDER_ASSETS required")
	}
	dir := t.TempDir()
	entries, err := os.ReadDir(filepath.Join("..", "..", "..", "config", "crd", "bases"))
	require.NoError(t, err)
	for _, entry := range entries {
		if strings.Contains(entry.Name(), "debugsessioncleanupacknowledgements") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join("..", "..", "..", "config", "crd", "bases", entry.Name()))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(filepath.Join(dir, entry.Name()), raw, 0o600))
	}
	env := &envtest.Environment{CRDDirectoryPaths: []string{dir}, ErrorIfCRDPathMissing: true}
	cfg, err := env.Start()
	require.NoError(t, err)
	t.Cleanup(func() { require.NoError(t, env.Stop()) })
	require.NoError(t, breakglassv1alpha1.AddToScheme(scheme.Scheme))
	mgr, err := ctrl.NewManager(cfg, ctrl.Options{Scheme: scheme.Scheme, Metrics: metricsserver.Options{BindAddress: "0"}})
	require.NoError(t, err)
	controller := NewDebugSessionController(zap.NewNop().Sugar(), mgr.GetClient(), nil)
	require.NoError(t, controller.SetupWithManager(mgr), "setup must not depend on the optional CRD")
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- mgr.Start(ctx) }()
	require.Eventually(t, func() bool { return mgr.GetCache().WaitForCacheSync(ctx) }, 30*time.Second, 200*time.Millisecond, "the manager starts and syncs")
	cancel()
	require.NoError(t, <-done)
}
