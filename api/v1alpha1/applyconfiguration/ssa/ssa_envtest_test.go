// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package ssa

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	ac "github.com/telekom/k8s-breakglass/api/v1alpha1/applyconfiguration/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/internal/ssatest"
	apierrors "k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/util/yaml"
	"sigs.k8s.io/controller-runtime/pkg/client"
)

func TestSSAEnvtestEveryStatusBuilder(t *testing.T) {
	apiClient := ssatest.Start(t)
	for _, tc := range []struct {
		name   string
		sample string
		obj    client.Object
		apply  func(*testing.T, client.Client, client.Object) (PatchApplyResult, error)
	}{
		{"session", "breakglass.t-caas.telekom.com_v1alpha1_breakglasssession.yaml", &breakglassv1alpha1.BreakglassSession{}, func(t *testing.T, c client.Client, o client.Object) (PatchApplyResult, error) {
			return PatchApplyBreakglassSessionStatus(t.Context(), c, o.(*breakglassv1alpha1.BreakglassSession))
		}},
		{"debug-session", "debug_sessions.yaml", &breakglassv1alpha1.DebugSession{}, func(t *testing.T, c client.Client, o client.Object) (PatchApplyResult, error) {
			return PatchApplyDebugSessionStatus(t.Context(), c, o.(*breakglassv1alpha1.DebugSession))
		}},
		{"escalation", "breakglass.t-caas.telekom.com_v1alpha1_breakglassescalation.yaml", &breakglassv1alpha1.BreakglassEscalation{}, func(t *testing.T, c client.Client, o client.Object) (PatchApplyResult, error) {
			return PatchApplyBreakglassEscalationStatus(t.Context(), c, o.(*breakglassv1alpha1.BreakglassEscalation))
		}},
		{"deny-policy", "breakglass_v1alpha1_denypolicy_comprehensive.yaml", &breakglassv1alpha1.DenyPolicy{}, func(t *testing.T, c client.Client, o client.Object) (PatchApplyResult, error) {
			return PatchApplyDenyPolicyStatus(t.Context(), c, o.(*breakglassv1alpha1.DenyPolicy))
		}},
		{"session-template", "debug_session_templates.yaml", &breakglassv1alpha1.DebugSessionTemplate{}, func(t *testing.T, c client.Client, o client.Object) (PatchApplyResult, error) {
			return PatchApplyDebugSessionTemplateStatus(t.Context(), c, o.(*breakglassv1alpha1.DebugSessionTemplate))
		}},
		{"pod-template", "debug-pod-template-minimal.yaml", &breakglassv1alpha1.DebugPodTemplate{}, func(t *testing.T, c client.Client, o client.Object) (PatchApplyResult, error) {
			return PatchApplyDebugPodTemplateStatus(t.Context(), c, o.(*breakglassv1alpha1.DebugPodTemplate))
		}},
		{"cluster-binding", "debug_session_cluster_binding.yaml", &breakglassv1alpha1.DebugSessionClusterBinding{}, func(t *testing.T, c client.Client, o client.Object) (PatchApplyResult, error) {
			return PatchApplyDebugSessionClusterBindingStatus(t.Context(), c, o.(*breakglassv1alpha1.DebugSessionClusterBinding))
		}},
		{"idp", "breakglass_v1alpha1_identityprovider_keycloak.yaml", &breakglassv1alpha1.IdentityProvider{}, func(t *testing.T, c client.Client, o client.Object) (PatchApplyResult, error) {
			return PatchApplyIdentityProviderStatus(t.Context(), c, o.(*breakglassv1alpha1.IdentityProvider))
		}},
		{"cluster-config", "breakglass_v1alpha1_clusterconfig_kubeconfig.yaml", &breakglassv1alpha1.ClusterConfig{}, func(t *testing.T, c client.Client, o client.Object) (PatchApplyResult, error) {
			return PatchApplyClusterConfigStatus(t.Context(), c, o.(*breakglassv1alpha1.ClusterConfig))
		}},
		{"mail", "breakglass_v1alpha1_mailprovider.yaml", &breakglassv1alpha1.MailProvider{}, func(t *testing.T, c client.Client, o client.Object) (PatchApplyResult, error) {
			return PatchApplyMailProviderStatus(t.Context(), c, o.(*breakglassv1alpha1.MailProvider))
		}},
		{"audit", "audit_config_stdout.yaml", &breakglassv1alpha1.AuditConfig{}, func(t *testing.T, c client.Client, o client.Object) (PatchApplyResult, error) {
			return PatchApplyAuditConfigStatus(t.Context(), c, o.(*breakglassv1alpha1.AuditConfig))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			file, err := os.Open(filepath.Join("..", "..", "..", "..", "config", "samples", tc.sample))
			require.NoError(t, err)
			t.Cleanup(func() { require.NoError(t, file.Close()) })
			manifest := &unstructured.Unstructured{}
			decoder := yaml.NewYAMLOrJSONDecoder(file, 4096)
			for manifest.GetKind() == "" {
				require.NoError(t, decoder.Decode(manifest))
			}
			manifest.SetName("ssa-" + tc.name)
			switch tc.obj.(type) {
			case *breakglassv1alpha1.BreakglassSession, *breakglassv1alpha1.BreakglassEscalation,
				*breakglassv1alpha1.DebugSession, *breakglassv1alpha1.ClusterConfig,
				*breakglassv1alpha1.DebugSessionClusterBinding:
				manifest.SetNamespace("default")
			}
			delete(manifest.Object, "status")
			require.NoError(t, runtime.DefaultUnstructuredConverter.FromUnstructured(manifest.Object, tc.obj))
			require.NoError(t, apiClient.Create(t.Context(), tc.obj))
			objectMap, err := runtime.DefaultUnstructuredConverter.ToUnstructured(tc.obj)
			require.NoError(t, err)
			now := metav1.NewTime(time.Now().UTC().Truncate(time.Second))
			objectMap["status"] = map[string]interface{}{
				"observedGeneration": int64(1),
				"conditions": []interface{}{map[string]interface{}{
					"type": "Ready", "status": "True", "reason": "Characterized",
					"message": "ready", "lastTransitionTime": now.Format(time.RFC3339),
				}},
			}
			require.NoError(t, runtime.DefaultUnstructuredConverter.FromUnstructured(objectMap, tc.obj))
			c := &ssatest.CountingClient{Client: apiClient}
			result, err := tc.apply(t, c, tc.obj)
			require.NoError(t, err)
			require.Equal(t, PatchApplyResultPatched, result)
			require.EqualValues(t, 1, c.StatusPatches.Load())
			// Read back the real server's canonical status/resource version.
			require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(tc.obj), tc.obj))
			result, err = tc.apply(t, c, tc.obj)
			require.NoError(t, err)
			require.Equal(t, PatchApplyResultSkipped, result)
			require.EqualValues(t, 1, c.StatusPatches.Load())
			require.NoError(t, apiClient.Delete(t.Context(), tc.obj))
			_, err = tc.apply(t, c, tc.obj)
			require.True(t, apierrors.IsNotFound(err), "%v", err)
			require.EqualValues(t, 1, c.StatusPatches.Load())
		})
	}
}

func TestSSAEnvtestStatusCompetingManagerAndEmptyLists(t *testing.T) {
	apiClient := ssatest.Start(t)
	session := ssatest.Session(t, apiClient, "status-ownership")
	session.Status.ActivityCount = 1
	session.Status.ObservedGeneration = 1
	session.Status.Approvers = []string{"first@example.com"}
	c := &ssatest.CountingClient{Client: apiClient}
	result, err := PatchApplyBreakglassSessionStatus(t.Context(), c, session)
	require.NoError(t, err)
	require.Equal(t, PatchApplyResultPatched, result)
	competing := &unstructured.Unstructured{Object: map[string]interface{}{
		"apiVersion": breakglassv1alpha1.GroupVersion.String(), "kind": "BreakglassSession",
		"metadata": map[string]interface{}{"name": session.Name, "namespace": session.Namespace},
		"status":   map[string]interface{}{"activityCount": int64(9), "reasonEnded": "foreign"},
	}}
	require.NoError(t, apiClient.SubResource("status").Apply(t.Context(), client.ApplyConfigurationFromUnstructured(competing), client.FieldOwner("competitor"), client.ForceOwnership))
	require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(session), session))
	session.Status.ActivityCount = 2
	session.Status.ObservedGeneration = 2
	session.Status.Approvers = []string{}
	result, err = PatchApplyBreakglassSessionStatus(t.Context(), c, session)
	require.NoError(t, err)
	require.Equal(t, PatchApplyResultPatched, result)
	require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(session), session))
	require.EqualValues(t, 9, session.Status.ActivityCount)
	require.Empty(t, session.Status.Approvers)
	require.Equal(t, "foreign", session.Status.ReasonEnded)
	require.EqualValues(t, 2, c.StatusPatches.Load())
}

func TestSSAEnvtestDebugStatusMergesLiveMonotonicFields(t *testing.T) {
	apiClient := ssatest.Start(t)
	session := ssatest.DebugSession(t, apiClient, "live-monotonic")
	now := metav1.NewTime(time.Now().UTC().Truncate(time.Second))
	retained := metav1.NewTime(now.Add(time.Hour))
	session.Status.State = breakglassv1alpha1.DebugSessionStateExpired
	session.Status.ActivityCount = 7
	session.Status.LastActivity = &now
	session.Status.RetainedUntil = &retained
	require.NoError(t, apiClient.Status().Update(t.Context(), session))
	stale := &breakglassv1alpha1.DebugSession{
		ObjectMeta: metav1.ObjectMeta{Name: session.Name, Namespace: session.Namespace, UID: session.UID},
		Status: breakglassv1alpha1.DebugSessionStatus{
			State: breakglassv1alpha1.DebugSessionStateExpired, ActivityCount: 1, Message: "terminal bookkeeping",
		},
	}
	c := &ssatest.CountingClient{Client: apiClient}
	result, err := PatchApplyDebugSessionStatus(t.Context(), c, stale)
	require.NoError(t, err)
	require.Equal(t, PatchApplyResultPatched, result)
	require.NotEmpty(t, stale.ResourceVersion)
	require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(session), session))
	require.EqualValues(t, 7, session.Status.ActivityCount)
	require.True(t, now.Equal(session.Status.LastActivity))
	require.True(t, retained.Equal(session.Status.RetainedUntil))
	stale.UID = "wrong-uid"
	stale.ResourceVersion = ""
	_, err = PatchApplyDebugSessionStatus(t.Context(), c, stale)
	require.ErrorContains(t, err, "UID changed")
	require.EqualValues(t, 1, c.StatusPatches.Load())
}

func TestSSAEnvtestExplicitEmptyDebugStatusList(t *testing.T) {
	apiClient := ssatest.Start(t)
	session := ssatest.DebugSession(t, apiClient, "empty-status-list")
	session.Status.AuxiliaryResourceStatuses = []breakglassv1alpha1.AuxiliaryResourceStatus{{Name: "auxiliary", Created: true}}
	c := &ssatest.CountingClient{Client: apiClient}
	result, err := PatchApplyDebugSessionStatus(t.Context(), c, session)
	require.NoError(t, err)
	require.Equal(t, PatchApplyResultPatched, result)
	require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(session), session))
	session.Status.AuxiliaryResourceStatuses = []breakglassv1alpha1.AuxiliaryResourceStatus{}
	result, err = PatchApplyDebugSessionStatus(t.Context(), c, session)
	require.NoError(t, err)
	require.Equal(t, PatchApplyResultPatched, result)
	require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(session), session))
	require.Empty(t, session.Status.AuxiliaryResourceStatuses)
	require.EqualValues(t, 2, c.StatusPatches.Load())
	session.Status.AuxiliaryResourceStatuses = []breakglassv1alpha1.AuxiliaryResourceStatus{}
	result, err = PatchApplyDebugSessionStatus(t.Context(), c, session)
	require.NoError(t, err)
	require.Equal(t, PatchApplyResultSkipped, result)
	require.EqualValues(t, 2, c.StatusPatches.Load())
}

func TestSSAEnvtestCustomStatusOwnerIsolation(t *testing.T) {
	apiClient := ssatest.Start(t)
	session := ssatest.Session(t, apiClient, "custom-status-owner")
	c := &ssatest.CountingClient{Client: apiClient}
	desired := ac.BreakglassSession(session.Name, session.Namespace).WithStatus(ac.BreakglassSessionStatus().WithActivityCount(2))
	result, err := PatchApplyViaUnstructuredWithOwner(t.Context(), c, desired, "activity-owner")
	require.NoError(t, err)
	require.Equal(t, PatchApplyResultPatched, result)
	require.NoError(t, ApplyViaUnstructuredWithOwner(t.Context(), c, desired, "activity-owner"))
	require.EqualValues(t, 1, c.StatusPatches.Load())
	require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(session), session))
	session.Status.State = breakglassv1alpha1.SessionStateApproved
	require.NoError(t, ApplyBreakglassSessionStatus(t.Context(), c, session))
	require.NoError(t, apiClient.Get(t.Context(), client.ObjectKeyFromObject(session), session))
	require.EqualValues(t, 2, session.Status.ActivityCount)
	require.Equal(t, breakglassv1alpha1.SessionStateApproved, session.Status.State)
	owners := map[string]bool{}
	for _, entry := range session.ManagedFields {
		if entry.Subresource == "status" && entry.Operation == metav1.ManagedFieldsOperationApply {
			owners[entry.Manager] = true
		}
	}
	require.True(t, owners["activity-owner"])
	require.True(t, owners[FieldOwnerController])
}
