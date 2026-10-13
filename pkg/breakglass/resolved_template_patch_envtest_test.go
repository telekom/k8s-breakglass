// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package breakglass

import (
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/internal/ssatest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func falseDefaultsTemplate() *breakglassv1alpha1.DebugSessionTemplateSpec {
	return &breakglassv1alpha1.DebugSessionTemplateSpec{
		Mode: breakglassv1alpha1.DebugSessionModeKubectlDebug,
		KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{
			EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{Enabled: true, MaxCapabilities: []string{"NET_RAW"}},
			NodeDebug: &breakglassv1alpha1.NodeDebugConfig{
				Enabled:        true,
				HostNamespaces: &breakglassv1alpha1.HostNamespacesConfig{},
			},
		},
		Notification:   &breakglassv1alpha1.DebugSessionNotificationConfig{},
		ApprovalReason: &breakglassv1alpha1.DebugApprovalReasonConfig{},
		ResourceQuota:  &breakglassv1alpha1.DebugResourceQuotaConfig{},
		Audit:          &breakglassv1alpha1.DebugSessionAuditConfig{},
	}
}

func requireFalseDefaultsKept(t *testing.T, apiClient client.Client, session *breakglassv1alpha1.DebugSession) {
	t.Helper()
	live := &breakglassv1alpha1.DebugSession{}
	require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(session), live))
	resolved := live.Status.ResolvedTemplate
	require.NotNil(t, resolved)
	require.False(t, resolved.KubectlDebug.EphemeralContainers.RequireNonRoot)
	require.False(t, resolved.KubectlDebug.NodeDebug.HostNamespaces.HostNetwork)
	require.False(t, resolved.KubectlDebug.NodeDebug.HostNamespaces.HostPID)
	require.Equal(t, breakglassv1alpha1.DebugSessionNotificationConfig{}, *resolved.Notification)
	require.False(t, resolved.ApprovalReason.MandatoryForRejection)
	require.False(t, resolved.ResourceQuota.EnforceResourceRequests)
	require.False(t, resolved.ResourceQuota.EnforceResourceLimits)
	require.False(t, resolved.Audit.Enabled)
	require.False(t, resolved.Audit.EnableShellHistory)
}

// The CRD defaults these booleans to true. An explicit false copied from a
// template into status.resolvedTemplate must survive the status merge patch
// instead of being dropped by omitempty and re-defaulted by the API server.
func TestSSAEnvtestDebugSessionStatusKeepsResolvedTemplateFalseDefaults(t *testing.T) {
	apiClient := ssatest.Start(t)

	applied := ssatest.DebugSession(t, apiClient, "resolved-false-apply")
	applied.Status.ResolvedTemplate = falseDefaultsTemplate()
	require.NoError(t, ApplyDebugSessionStatus(t.Context(), apiClient, applied))
	requireFalseDefaultsKept(t, apiClient, applied)

	patched := ssatest.DebugSession(t, apiClient, "resolved-false-patch")
	require.NoError(t, PatchDebugSessionStatusWithOptimisticLock(t.Context(), apiClient, patched,
		func(status *breakglassv1alpha1.DebugSessionStatus) { status.ResolvedTemplate = falseDefaultsTemplate() }))
	requireFalseDefaultsKept(t, apiClient, patched)
}

func TestResolvedTemplateFalsePatchLeavesTrueAndUnsetFieldsAlone(t *testing.T) {
	spec := &breakglassv1alpha1.DebugSessionTemplateSpec{
		KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{
			EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{RequireNonRoot: true},
		},
		Audit: &breakglassv1alpha1.DebugSessionAuditConfig{Enabled: true},
	}
	require.Equal(t, map[string]any{"audit": map[string]any{"enableShellHistory": false}}, resolvedTemplateExplicitFalses(spec))
	require.Empty(t, resolvedTemplateExplicitFalses(&breakglassv1alpha1.DebugSessionTemplateSpec{}))
}
