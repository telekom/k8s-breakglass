// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/utils/ptr"
)

// TestDebugSessionBindingPerClusterCap proves maxActiveSessionsPerCluster on a
// real hub: a second session of the binding on the same cluster is refused
// while the first one is pending, and admitted again once the first one ends.
func TestDebugSessionBindingPerClusterCap(t *testing.T) {
	s := helpers.SetupTest(t, helpers.WithLongTimeout())
	user := helpers.TestUsers.SecurityRequester
	peer := helpers.TestUsers.SecurityApprover
	api := NewDebugSessionAPIClient(s.TC.OIDCProvider().GetTokenForUser(t, s.Ctx, user))
	approver := NewDebugSessionAPIClient(s.TC.OIDCProvider().GetTokenForUser(t, s.Ctx, peer))

	template := &breakglassv1alpha1.DebugSessionTemplate{
		ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("cluster-cap")},
		Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
			DisplayName: "per-cluster cap", Mode: breakglassv1alpha1.DebugSessionModeWorkload,
			TargetNamespace: "breakglass-debug",
			PodTemplateString: `apiVersion: v1
kind: Pod
spec:
  containers:
  - name: debug
    image: busybox:1.37
    command: ["sleep", "600"]
    securityContext:
      runAsNonRoot: true
      runAsUser: 65532
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      seccompProfile:
        type: RuntimeDefault
`,
		},
	}
	require.NoError(t, s.CreateResource(template))
	binding := &breakglassv1alpha1.DebugSessionClusterBinding{
		ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("cluster-cap-binding"), Namespace: s.Namespace},
		Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
			TemplateRef:                 &breakglassv1alpha1.TemplateReference{Name: template.Name},
			Clusters:                    []string{s.Cluster},
			Allowed:                     &breakglassv1alpha1.DebugSessionAllowed{Groups: []string{"security-test-requester"}},
			Approvers:                   &breakglassv1alpha1.DebugSessionApprovers{Users: []string{peer.Email}},
			MaxActiveSessionsPerCluster: ptr.To(int32(1)),
		},
	}
	require.NoError(t, s.CreateResource(binding))

	request := DebugSessionCreateRequest{TemplateRef: template.Name, Cluster: s.Cluster, RequestedDuration: "5m", Reason: "per-cluster cap"}
	var first *breakglassv1alpha1.DebugSession
	require.Eventually(t, func() bool {
		session, status, err := api.CreateDebugSession(s.Ctx, t, request)
		if err != nil || status != http.StatusCreated {
			return false
		}
		first = session
		return true
	}, helpers.WaitForStateTimeout, 2*time.Second, "the first session of the binding must be admitted")
	s.Cleanup.Add(first)

	_, status, err := api.CreateDebugSession(s.Ctx, t, request)
	require.Error(t, err)
	require.Equal(t, http.StatusForbidden, status, "a second session on the same cluster must be refused")
	require.Contains(t, err.Error(), "per cluster")

	// Only a session in PendingApproval can be rejected.
	helpers.WaitForDebugSessionState(t, s.Ctx, s.Client, first.Name, first.Namespace, breakglassv1alpha1.DebugSessionStatePendingApproval, helpers.WaitForStateTimeout)
	status, err = approver.RejectDebugSession(s.Ctx, t, first.Name, "free the per-cluster slot")
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)

	require.Eventually(t, func() bool {
		session, status, err := api.CreateDebugSession(s.Ctx, t, request)
		if err != nil || status != http.StatusCreated {
			return false
		}
		s.Cleanup.Add(session)
		return true
	}, helpers.WaitForStateTimeout, 2*time.Second, "the slot must be free once the first session ended")
}
