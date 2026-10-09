// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
)

func TestDebugSessionOptionalGrantAliasDiscoveryLifecycle(t *testing.T) {
	s := helpers.SetupTest(t, helpers.WithLongTimeout())
	user := helpers.TestUsers.SecurityRequester
	peer := helpers.TestUsers.SecurityApprover
	requester := s.TC.ClientForUser(user)
	api := NewDebugSessionAPIClient(s.TC.OIDCProvider().GetTokenForUser(t, s.Ctx, user))
	grantGroup := helpers.GenerateUniqueName("discovery-only-grant")
	newTemplate := func(name, allowedGroup string) *breakglassv1alpha1.DebugSessionTemplate {
		template := &breakglassv1alpha1.DebugSessionTemplate{
			ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName(name)},
			Spec: breakglassv1alpha1.DebugSessionTemplateSpec{
				DisplayName: name, Mode: breakglassv1alpha1.DebugSessionModeWorkload,
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
			ObjectMeta: metav1.ObjectMeta{Name: helpers.GenerateUniqueName("alias-binding"), Namespace: s.Namespace},
			Spec: breakglassv1alpha1.DebugSessionClusterBindingSpec{
				TemplateRef: &breakglassv1alpha1.TemplateReference{Name: template.Name},
				Clusters:    []string{s.Cluster},
				Allowed:     &breakglassv1alpha1.DebugSessionAllowed{Groups: []string{allowedGroup}},
				Approvers:   &breakglassv1alpha1.DebugSessionApprovers{Users: []string{peer.Email}},
			},
		}
		require.NoError(t, s.CreateResource(binding))
		return template
	}
	identityTemplate := newTemplate("identity-discovery", "security-test-requester")
	aliasTemplate := newTemplate("deprecated-alias-discovery", grantGroup)
	expectDiscovery := func(aliasVisible bool) {
		t.Helper()
		require.Eventually(t, func() bool {
			templates, status, err := api.ListTemplates(s.Ctx, t)
			if err != nil || status != http.StatusOK {
				return false
			}
			var identityFound, aliasFound bool
			for _, template := range templates {
				identityFound = identityFound || template.Name == identityTemplate.Name
				aliasFound = aliasFound || template.Name == aliasTemplate.Name
			}
			return identityFound && aliasFound == aliasVisible
		}, helpers.WaitForStateTimeout, time.Second,
			"identity discovery must not depend on a grant; alias visibility must reflect its real lease")
	}
	expectDiscovery(false)
	policy := helpers.NewEscalationBuilder(helpers.GenerateUniqueName("alias-policy"), s.Namespace).
		WithAllowedClusters(s.Cluster).WithAllowedGroups("security-test-requester").
		WithEscalatedGroup(grantGroup).WithApproverUsers(peer.Email).Build()
	require.NoError(t, s.CreateResource(policy))
	helpers.WaitForEscalationReady(t, s.Ctx, s.Client, policy.Name, s.Namespace, helpers.WaitForStateTimeout)
	grant, err := requester.CreateSessionAndWaitForPending(s.Ctx, t, helpers.SessionRequest{
		Cluster: s.Cluster, User: user.Email, Group: grantGroup, Reason: "optional discovery alias",
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err)
	s.Cleanup.Add(grant)
	t.Cleanup(func() { _ = requester.DropSessionViaAPI(context.Background(), t, grant.Name, grant.Namespace) })
	expectDiscovery(false)
	require.NoError(t, s.TC.ClientForUser(peer).ApproveSessionViaAPI(s.Ctx, t, grant.Name, grant.Namespace))
	helpers.WaitForSessionState(t, s.Ctx, s.Client, grant.Name, grant.Namespace, breakglassv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)
	expectDiscovery(true)
	_, status, err := api.CreateDebugSession(s.Ctx, t, DebugSessionCreateRequest{
		TemplateRef: aliasTemplate.Name, Cluster: s.Cluster, RequestedDuration: "5m",
	})
	require.Error(t, err)
	require.Equal(t, http.StatusForbidden, status, "a discovery alias must never authorize creation")
	require.NoError(t, requester.DropSessionViaAPI(s.Ctx, t, grant.Name, grant.Namespace))
	helpers.WaitForSessionState(t, s.Ctx, s.Client, grant.Name, grant.Namespace, breakglassv1alpha1.SessionStateExpired, helpers.WaitForStateTimeout)
	expectDiscovery(false)
}
