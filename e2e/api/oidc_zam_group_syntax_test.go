/*
Copyright 2026.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package api

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"
	"k8s.io/apimachinery/pkg/util/validation"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
	"github.com/telekom/k8s-breakglass/pkg/naming"
)

// TestOIDCZAMGroupSyntax proves that group names in the production ZAM syntax
// ("dttcaas-" + {tenant}_{scope}_{privilege}, up to the 64-character LDAP CN
// limit, mixed case, '.', '-' and '_') survive the whole OIDC path unchanged:
// Keycloak groups claim -> breakglass API (request and approval) -> session ->
// webhook SubjectAccessReview with the groups as the kube-apiserver presents them.
//
// The realm also holds dttcaas-ZAM-TENANT.123_appowner, which differs from the
// approver group only in case: its member must neither be notified nor be able
// to approve. The granted group sits at the 64-character CN limit, so the
// session's group label (max 63) must be the sanitized, truncated form.
//
// The single-cluster kind setup maps groups with the "oidc:" apiserver prefix,
// so the escalation lists the requester group in that prefixed form; the
// multi-cluster setup uses no prefix (as TDG does) and lists it unprefixed.
//
// Test ID: CC-OIDC-ZAM-001 (High)
func TestOIDCZAMGroupSyntax(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())
	if !helpers.IsWebhookTestEnabled() {
		t.Skip("Webhook tests disabled via E2E_SKIP_WEBHOOK_TESTS=true")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()
	tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)

	requester := helpers.TestUsers.ZAMRequester
	approver := helpers.TestUsers.ZAMApprover
	variant := helpers.TestUsers.ZAMApproverVariant
	requesterGroup := requester.Groups[0]
	approverGroup := approver.Groups[0]
	const escalatedGroup = "dttcaas-ZAM-Tenant.123_tcaas-mgmt-nord-1.prd.b_poweruser-elevate"
	require.Len(t, requesterGroup, 64, "fixture must sit at the ZAM LDAP CN limit")
	require.Len(t, escalatedGroup, 64, "granted group must sit at the ZAM LDAP CN limit")
	require.True(t, strings.EqualFold(approverGroup, variant.Groups[0]) && approverGroup != variant.Groups[0],
		"variant fixture must differ only in case")

	apiserverGroupPrefix := "oidc:"
	targetClient := cli
	if helpers.IsMultiClusterEnabled() {
		apiserverGroupPrefix = ""
		targetClient = helpers.GetSpokeAClient(t)
		require.NotNil(t, targetClient, "spoke A admin client is required for the target RBAC fixture")
	}
	presentedRequesterGroup := apiserverGroupPrefix + requesterGroup

	// Grant one operation to the ZAM-named escalated group on the target cluster.
	targetCleanup := helpers.NewCleanup(t, targetClient)
	targetNamespace := helpers.GenerateUniqueName("zam-group-target")
	targetNS := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: targetNamespace, Labels: helpers.E2ETestLabels()}}
	targetCleanup.Add(targetNS)
	require.NoError(t, targetClient.Create(ctx, targetNS))
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "zam-configmap-reader", Namespace: targetNamespace, Labels: helpers.E2ETestLabels()},
		Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get"}}},
	}
	targetCleanup.Add(role)
	require.NoError(t, targetClient.Create(ctx, role))
	binding := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "zam-configmap-reader", Namespace: targetNamespace, Labels: helpers.E2ETestLabels()},
		RoleRef:    rbacv1.RoleRef{APIGroup: rbacv1.GroupName, Kind: "Role", Name: role.Name},
		Subjects:   []rbacv1.Subject{{APIGroup: rbacv1.GroupName, Kind: "Group", Name: escalatedGroup}},
	}
	targetCleanup.Add(binding)
	require.NoError(t, targetClient.Create(ctx, binding))

	escalation := helpers.NewEscalationBuilder(helpers.GenerateUniqueName("e2e-zam-group-esc"), namespace).
		WithEscalatedGroup(escalatedGroup).
		WithAllowedClusters(clusterName).
		WithAllowedGroups(presentedRequesterGroup).
		WithApproverGroups(approverGroup).
		Build()
	cleanup.Add(escalation)
	require.NoError(t, cli.Create(ctx, escalation), "ZAM-syntax group names must pass CRD validation")
	require.NoError(t, helpers.ExpireActiveSessionsForUserAndGroup(ctx, cli, namespace, clusterName, requester.Email, escalatedGroup))

	sar := helpers.BuildResourceSAR(requester.Email, []string{presentedRequesterGroup}, "get", "configmaps", targetNamespace)
	before, status, err := helpers.SendSARToWebhook(t, ctx, sar, clusterName)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, status)
	require.False(t, before.Status.Allowed, "no access before the session is approved")

	session, err := tc.ClientForUser(requester).CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    requester.Email,
		Group:   escalatedGroup,
		Reason:  "CC-OIDC-ZAM-001 ZAM group syntax",
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err, "the token's ZAM group must match the escalation's allowed group")
	cleanup.Add(session)
	require.Equal(t, escalatedGroup, session.Spec.GrantedGroup, "granted group must not be normalized")
	groupLabel := session.Labels["breakglass.t-caas.telekom.com/group"]
	require.Equal(t, naming.ToRFC1123Label(escalatedGroup), groupLabel)
	require.Empty(t, validation.IsValidLabelValue(groupLabel), "group label must be a valid label value")
	require.Len(t, groupLabel, 63, "the 64-character group must be truncated to the label limit")

	if helpers.IsMailHogTestEnabled() {
		recipients := map[string]bool{}
		err := helpers.WaitForCondition(ctx, func() (bool, error) {
			for _, msg := range getMailHogMessages(t) {
				body, err := decodeMailHogBody(msg)
				if err != nil || !strings.Contains(body, escalatedGroup) {
					continue
				}
				for _, to := range msg.To {
					recipients[to.Mailbox+"@"+to.Domain] = true
				}
			}
			return recipients[approver.Email], nil
		}, helpers.WaitForStateTimeout, time.Second)
		require.NoError(t, err, "the exact ZAM approver group member must be notified")
		require.False(t, recipients[variant.Email], "the case-variant group member must not be notified")
	}

	require.Error(t, tc.ClientForUser(variant).ApproveSessionViaAPI(ctx, t, session.Name, namespace),
		"a group that differs only in case must not authorize approval")

	require.NoError(t, tc.ClientForUser(approver).ApproveSessionViaAPI(ctx, t, session.Name, namespace),
		"the mixed-case ZAM approver group must authorize approval")
	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace, breakglassv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)

	var approved breakglassv1alpha1.BreakglassSession
	require.NoError(t, cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &approved))
	require.Equal(t, approver.Email, approved.Status.Approver)

	err = helpers.WaitForCondition(ctx, func() (bool, error) {
		resp, code, err := helpers.SendSARToWebhook(t, ctx, sar, clusterName)
		if err != nil {
			return false, err
		}
		return code == http.StatusOK && resp.Status.Allowed, nil
	}, helpers.WaitForStateTimeout, time.Second)
	require.NoError(t, err, "the approved ZAM session must authorize the SubjectAccessReview")
}
