//go:build e2e_convergence

// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
	apimeta "k8s.io/apimachinery/pkg/api/meta"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// This checks that each Helm-installed template mode is reconciled Ready. It
// does not invoke the private T-CaaS Function or start any session; the etcd-*
// templates reuse the workload pod template and contain no etcd tooling.
func TestConvergenceInstallationVariants(t *testing.T) {
	s := helpers.SetupTest(t, helpers.WithTimeout(8*time.Minute))
	release := helpers.GenerateUniqueName("convergence-installation")
	chart := filepath.Join("..", "fixtures", "convergence-installation")
	run := func(ctx context.Context, args ...string) {
		t.Helper()
		out, err := exec.CommandContext(ctx, args[0], args[1:]...).CombinedOutput()
		require.NoError(t, err, "%v: %s", args, out)
	}
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
		defer cancel()
		out, err := exec.CommandContext(cleanupCtx, "helm", "uninstall", release, "-n", s.Namespace, "--ignore-not-found", "--wait", "--timeout=60s").CombinedOutput()
		assert.NoError(t, err, "uninstall fixture: %s", out)
	})
	run(s.Ctx, "helm", "upgrade", "--install", release, chart, "--namespace", s.Namespace, "--wait", "--timeout=90s")

	podTemplateKey := client.ObjectKey{Name: release + "-workload"}
	require.Eventually(t, func() bool {
		var template breakglassv1alpha1.DebugPodTemplate
		return s.Client.Get(s.Ctx, podTemplateKey, &template) == nil &&
			apimeta.IsStatusConditionTrue(template.Status.Conditions, "Ready")
	}, 90*time.Second, time.Second, "installed workload DebugPodTemplate must be reconciled Ready")

	for _, name := range []string{"workload", "node-debug", "emergency-node-debug", "etcd-snapshot", "etcd-defrag"} {
		t.Run(name, func(t *testing.T) {
			key := client.ObjectKey{Name: release + "-" + name}
			require.Eventually(t, func() bool {
				var template breakglassv1alpha1.DebugSessionTemplate
				return s.Client.Get(s.Ctx, key, &template) == nil &&
					apimeta.IsStatusConditionTrue(template.Status.Conditions, "Ready")
			}, 90*time.Second, time.Second, "installed template %q must be reconciled Ready", name)
		})
	}
}
