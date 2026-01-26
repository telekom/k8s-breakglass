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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	authorizationv1 "k8s.io/api/authorization/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestCrossClusterSessionIsolation verifies that a session approved for cluster-A
// cannot be used to authorize access to cluster-B.
//
// Test ID: SEC-001 (Critical)
// Security Concern: Sessions must be strictly bound to their target cluster
func TestCrossClusterSessionIsolation(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())
	if !helpers.IsWebhookTestEnabled() {
		t.Skip("Webhook tests disabled via E2E_SKIP_WEBHOOK_TESTS=true")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterA := helpers.GetTestClusterName()
	clusterB := "cluster-b-isolation-test"

	t.Log("=== Test: Cross-Cluster Session Isolation (SEC-001) ===")

	escalation := helpers.NewEscalationBuilder("e2e-isolation-escalation", namespace).
		WithEscalatedGroup("breakglass-isolation-test-group").
		WithMaxValidFor("4h").
		WithApprovalTimeout("2h").
		WithAllowedClusters(clusterA, clusterB).
		Build()
	cleanup.Add(escalation)
	err := cli.Create(ctx, escalation)
	require.NoError(t, err)

	tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)
	apiClient := tc.RequesterClient()
	approverClient := tc.ApproverClient()

	sessionUser := "isolation-test-user@example.com"
	session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterA,
		User:    sessionUser,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "SEC-001: Cross-cluster isolation test",
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err)
	cleanup.Add(session)

	err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
	require.NoError(t, err)
	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace,
		telekomv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)

	t.Run("VerifySessionWorksForClusterA", func(t *testing.T) {
		sar := createSecuritySAR(sessionUser, escalation.Spec.EscalatedGroup)
		sarResp, statusCode, err := helpers.SendSARToWebhook(t, ctx, sar, clusterA)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, statusCode)
		t.Logf("Cluster-A SAR: allowed=%v, reason=%s", sarResp.Status.Allowed, sarResp.Status.Reason)
	})

	t.Run("VerifySessionDeniedForClusterB", func(t *testing.T) {
		sar := createSecuritySAR(sessionUser, escalation.Spec.EscalatedGroup)
		sarResp, statusCode, err := helpers.SendSARToWebhook(t, ctx, sar, clusterB)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, statusCode)
		t.Logf("Cluster-B SAR: allowed=%v, denied=%v", sarResp.Status.Allowed, sarResp.Status.Denied)
		assert.False(t, sarResp.Status.Allowed, "SECURITY: Session for cluster-A should NOT work for cluster-B")
	})

	t.Log("=== SEC-001: Cross-Cluster Session Isolation Test Complete ===")
}

// TestExpiredSessionRaceCondition tests race conditions with expired sessions.
// Test ID: SEC-002 (Critical)
func TestExpiredSessionRaceCondition(t *testing.T) {
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

	t.Log("=== Test: Expired Session Race Condition (SEC-002) ===")

	escalation := helpers.NewEscalationBuilder("e2e-race-condition-escalation", namespace).
		WithEscalatedGroup("breakglass-race-test-group").
		WithMaxValidFor("10m").
		WithApprovalTimeout("5m").
		WithAllowedClusters(clusterName).
		Build()
	cleanup.Add(escalation)
	err := cli.Create(ctx, escalation)
	require.NoError(t, err)

	tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)
	apiClient := tc.RequesterClient()
	approverClient := tc.ApproverClient()

	sessionUser := "race-condition-test-user@example.com"
	session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    sessionUser,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "SEC-002: Expired session race condition test",
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err)
	cleanup.Add(session)

	err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
	require.NoError(t, err)
	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace,
		telekomv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)

	var toExpire telekomv1alpha1.BreakglassSession
	err = cli.Get(ctx, types.NamespacedName{Name: session.Name, Namespace: namespace}, &toExpire)
	require.NoError(t, err)
	toExpire.Status.State = telekomv1alpha1.SessionStateExpired
	toExpire.Status.ExpiresAt = metav1.NewTime(time.Now().Add(-1 * time.Second))
	err = helpers.ApplySessionStatus(ctx, cli, &toExpire)
	require.NoError(t, err)

	t.Run("RapidSARAfterExpiry", func(t *testing.T) {
		for i := 0; i < 5; i++ {
			sar := createSecuritySAR(sessionUser, escalation.Spec.EscalatedGroup)
			sarResp, statusCode, err := helpers.SendSARToWebhook(t, ctx, sar, clusterName)
			require.NoError(t, err)
			assert.Equal(t, http.StatusOK, statusCode)
			t.Logf("SAR #%d: allowed=%v", i+1, sarResp.Status.Allowed)
			assert.False(t, sarResp.Status.Allowed, "SECURITY: Expired session should be denied")
			time.Sleep(10 * time.Millisecond)
		}
	})

	t.Log("=== SEC-002: Expired Session Race Condition Test Complete ===")
}

// TestDifferentUserSameGroup verifies user isolation.
// Test ID: SEC-003 (Critical)
func TestDifferentUserSameGroup(t *testing.T) {
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

	escalation := helpers.NewEscalationBuilder("e2e-user-isolation-escalation", namespace).
		WithEscalatedGroup("breakglass-user-isolation-group").
		WithMaxValidFor("4h").
		WithAllowedClusters(clusterName).
		Build()
	cleanup.Add(escalation)
	err := cli.Create(ctx, escalation)
	require.NoError(t, err)

	tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)
	apiClient := tc.RequesterClient()
	approverClient := tc.ApproverClient()

	userA := "user-a-isolation@example.com"
	userB := "user-b-isolation@example.com"

	session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    userA,
		Group:   escalation.Spec.EscalatedGroup,
		Reason:  "SEC-003: User isolation test",
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err)
	cleanup.Add(session)

	err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
	require.NoError(t, err)
	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace,
		telekomv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)

	t.Run("VerifyUserBDeniedSameGroup", func(t *testing.T) {
		sar := createSecuritySAR(userB, escalation.Spec.EscalatedGroup)
		sarResp, statusCode, err := helpers.SendSARToWebhook(t, ctx, sar, clusterName)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, statusCode)
		assert.False(t, sarResp.Status.Allowed, "SECURITY: User-B should NOT use user-A's session")
	})
}

// TestSameUserDifferentGroup verifies group isolation.
// Test ID: SEC-004 (Critical)
func TestSameUserDifferentGroup(t *testing.T) {
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

	escalationGroupX := helpers.NewEscalationBuilder("e2e-group-x-escalation", namespace).
		WithEscalatedGroup("breakglass-group-x").
		WithMaxValidFor("4h").
		WithAllowedClusters(clusterName).
		Build()
	cleanup.Add(escalationGroupX)
	err := cli.Create(ctx, escalationGroupX)
	require.NoError(t, err)

	escalationGroupY := helpers.NewEscalationBuilder("e2e-group-y-escalation", namespace).
		WithEscalatedGroup("breakglass-group-y").
		WithMaxValidFor("4h").
		WithAllowedClusters(clusterName).
		Build()
	cleanup.Add(escalationGroupY)
	err = cli.Create(ctx, escalationGroupY)
	require.NoError(t, err)

	tc := helpers.NewTestContext(t, ctx).WithClient(cli, namespace)
	apiClient := tc.RequesterClient()
	approverClient := tc.ApproverClient()

	user := "group-isolation-user@example.com"

	session, err := apiClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
		Cluster: clusterName,
		User:    user,
		Group:   escalationGroupX.Spec.EscalatedGroup,
		Reason:  "SEC-004: Group isolation test",
	}, helpers.WaitForStateTimeout)
	require.NoError(t, err)
	cleanup.Add(session)

	err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
	require.NoError(t, err)
	helpers.WaitForSessionState(t, ctx, cli, session.Name, namespace,
		telekomv1alpha1.SessionStateApproved, helpers.WaitForStateTimeout)

	t.Run("VerifyUserDeniedGroupY", func(t *testing.T) {
		sar := createSecuritySAR(user, escalationGroupY.Spec.EscalatedGroup)
		sarResp, statusCode, err := helpers.SendSARToWebhook(t, ctx, sar, clusterName)
		require.NoError(t, err)
		assert.Equal(t, http.StatusOK, statusCode)
		assert.False(t, sarResp.Status.Allowed, "SECURITY: Group-X session should NOT work for group-Y")
	})
}

func createSecuritySAR(user, group string) *authorizationv1.SubjectAccessReview {
	return &authorizationv1.SubjectAccessReview{
		TypeMeta: metav1.TypeMeta{
			APIVersion: "authorization.k8s.io/v1",
			Kind:       "SubjectAccessReview",
		},
		Spec: authorizationv1.SubjectAccessReviewSpec{
			User:   user,
			Groups: []string{group},
			ResourceAttributes: &authorizationv1.ResourceAttributes{
				Namespace: "default",
				Verb:      "get",
				Resource:  "pods",
			},
		},
	}
}
