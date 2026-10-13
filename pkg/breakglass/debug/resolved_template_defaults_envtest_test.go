// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package debug

import (
	"testing"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/internal/ssatest"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

// The CRD defaults these booleans to true. An explicit false copied from a
// template into the session status must survive the round trip instead of
// being dropped by JSON omitempty and re-defaulted to true by the API server.
func TestSSAEnvtestResolvedTemplateKeepsExplicitFalseForTrueDefaults(t *testing.T) {
	apiClient := ssatest.Start(t)
	session := ssatest.DebugSession(t, apiClient, "resolved-false-defaults")
	session.Status.ResolvedTemplate = &breakglassv1alpha1.DebugSessionTemplateSpec{
		Mode: breakglassv1alpha1.DebugSessionModeKubectlDebug,
		KubectlDebug: &breakglassv1alpha1.KubectlDebugConfig{
			EphemeralContainers: &breakglassv1alpha1.EphemeralContainersConfig{
				Enabled:         true,
				MaxCapabilities: []string{"NET_RAW"},
				RequireNonRoot:  false,
			},
			NodeDebug: &breakglassv1alpha1.NodeDebugConfig{
				Enabled:        true,
				HostNamespaces: &breakglassv1alpha1.HostNamespacesConfig{HostNetwork: false, HostPID: false},
			},
		},
		Notification:   &breakglassv1alpha1.DebugSessionNotificationConfig{},
		ApprovalReason: &breakglassv1alpha1.DebugApprovalReasonConfig{},
		ResourceQuota:  &breakglassv1alpha1.DebugResourceQuotaConfig{},
		Audit:          &breakglassv1alpha1.DebugSessionAuditConfig{},
	}
	require.NoError(t, apiClient.Status().Update(t.Context(), session))

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
