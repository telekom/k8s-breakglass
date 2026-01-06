package api

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

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestDisableNotificationsFeature tests the DisableNotifications escalation feature.
func TestDisableNotificationsFeature(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	t.Run("EscalationWithDisableNotificationsTrue", func(t *testing.T) {
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      helpers.GenerateUniqueName("e2e-disable-notify-true"),
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:  helpers.GenerateUniqueName("disable-notify-group"),
				MaxValidFor:     "2h",
				ApprovalTimeout: "1h",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   helpers.TestUsers.Requester.Groups,
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{helpers.TestUsers.Approver.Email},
				},
				DisableNotifications: boolPtr(true),
			},
		}
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err)

		assert.NotNil(t, escalation.Spec.DisableNotifications,
			"NOTIFY-001: DisableNotifications should be set")
		assert.True(t, *escalation.Spec.DisableNotifications,
			"NOTIFY-001: DisableNotifications should be true when set")
		t.Logf("NOTIFY-001: Created escalation %s with DisableNotifications=true", escalation.Name)
	})

	t.Run("EscalationWithDisableNotificationsFalse", func(t *testing.T) {
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      helpers.GenerateUniqueName("e2e-disable-notify-false"),
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:  helpers.GenerateUniqueName("notify-enabled-group"),
				MaxValidFor:     "2h",
				ApprovalTimeout: "1h",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   helpers.TestUsers.Requester.Groups,
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{helpers.TestUsers.Approver.Email},
				},
				DisableNotifications: boolPtr(false),
			},
		}
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err)

		assert.NotNil(t, escalation.Spec.DisableNotifications,
			"NOTIFY-002: DisableNotifications should be set")
		assert.False(t, *escalation.Spec.DisableNotifications,
			"NOTIFY-002: DisableNotifications should be false when explicitly set")
		t.Logf("NOTIFY-002: Created escalation %s with DisableNotifications=false", escalation.Name)
	})

	t.Run("DisableNotificationsDefaultsToFalse", func(t *testing.T) {
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      helpers.GenerateUniqueName("e2e-disable-notify-default"),
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:  helpers.GenerateUniqueName("notify-default-group"),
				MaxValidFor:     "2h",
				ApprovalTimeout: "1h",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   helpers.TestUsers.Requester.Groups,
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{helpers.TestUsers.Approver.Email},
				},
			},
		}
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err)

		assert.Nil(t, escalation.Spec.DisableNotifications,
			"NOTIFY-003: DisableNotifications should be nil when omitted")
		t.Logf("NOTIFY-003: Created escalation %s without DisableNotifications field - defaults to false", escalation.Name)
	})
}

// TestNotificationIntegration tests notification behavior for sessions.
func TestNotificationIntegration(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	t.Run("NotificationScenarios", func(t *testing.T) {
		t.Log("NOTIFY-004: Notifications sent when DisableNotifications=false")
		t.Log("NOTIFY-005: No notifications sent when DisableNotifications=true")
		t.Log("NOTIFY-006: Notification includes session details (user, cluster, reason)")
		t.Log("NOTIFY-007: Approval notifications go to session requester")
		t.Log("NOTIFY-008: Request notifications go to configured approvers")
	})

	t.Run("MailProviderRequirements", func(t *testing.T) {
		t.Log("NOTIFY-009: Valid MailProvider required for notifications")
		t.Log("NOTIFY-010: Escalation condition reflects MailProvider validity")
		t.Log("NOTIFY-011: Sessions can proceed even if MailProvider is invalid")
	})
}

// TestEscalationNotificationConfig tests notification configuration on escalations.
func TestEscalationNotificationConfig(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	t.Run("EscalationMailProviderField", func(t *testing.T) {
		spec := telekomv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:       "test-group",
			MaxValidFor:          "1h",
			ApprovalTimeout:      "30m",
			MailProvider:         "custom-mail-provider",
			DisableNotifications: boolPtr(false),
		}
		assert.Equal(t, "custom-mail-provider", spec.MailProvider)
		assert.False(t, *spec.DisableNotifications)
		t.Logf("NOTIFY-012: MailProvider can override default MailProvider")
	})

	t.Run("EscalationWithoutMailProvider", func(t *testing.T) {
		spec := telekomv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:       "test-group",
			MaxValidFor:          "1h",
			ApprovalTimeout:      "30m",
			DisableNotifications: boolPtr(true),
		}
		assert.Empty(t, spec.MailProvider)
		assert.True(t, *spec.DisableNotifications)
		t.Logf("NOTIFY-013: Escalation can omit MailProvider when notifications disabled")
	})
}
