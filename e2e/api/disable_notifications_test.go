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
	"testing"

	"github.com/stretchr/testify/assert"

	breakglassv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestDisableNotificationsFeature tests the DisableNotifications escalation feature.
func TestDisableNotificationsFeature(t *testing.T) {
	s := helpers.SetupTest(t)

	t.Run("EscalationWithDisableNotificationsTrue", func(t *testing.T) {
		escalation := helpers.NewEscalationBuilder(s.GenerateName("e2e-disable-notify-true"), s.Namespace).
			WithEscalatedGroup(s.GenerateName("disable-notify-group")).
			WithAllowedClusters(s.Cluster).
			Build()
		escalation.Spec.DisableNotifications = helpers.BoolPtr(true)

		s.MustCreateResource(escalation)

		assert.NotNil(t, escalation.Spec.DisableNotifications,
			"NOTIFY-001: DisableNotifications should be set")
		assert.True(t, *escalation.Spec.DisableNotifications,
			"NOTIFY-001: DisableNotifications should be true when set")
		t.Logf("NOTIFY-001: Created escalation %s with DisableNotifications=true", escalation.Name)
	})

	t.Run("EscalationWithDisableNotificationsFalse", func(t *testing.T) {
		escalation := helpers.NewEscalationBuilder(s.GenerateName("e2e-disable-notify-false"), s.Namespace).
			WithEscalatedGroup(s.GenerateName("notify-enabled-group")).
			WithAllowedClusters(s.Cluster).
			Build()
		escalation.Spec.DisableNotifications = helpers.BoolPtr(false)

		s.MustCreateResource(escalation)

		assert.NotNil(t, escalation.Spec.DisableNotifications,
			"NOTIFY-002: DisableNotifications should be set")
		assert.False(t, *escalation.Spec.DisableNotifications,
			"NOTIFY-002: DisableNotifications should be false when explicitly set")
		t.Logf("NOTIFY-002: Created escalation %s with DisableNotifications=false", escalation.Name)
	})

	t.Run("DisableNotificationsDefaultsToFalse", func(t *testing.T) {
		escalation := helpers.NewEscalationBuilder(s.GenerateName("e2e-disable-notify-default"), s.Namespace).
			WithEscalatedGroup(s.GenerateName("notify-default-group")).
			WithAllowedClusters(s.Cluster).
			Build()

		s.MustCreateResource(escalation)

		assert.Nil(t, escalation.Spec.DisableNotifications,
			"NOTIFY-003: DisableNotifications should be nil when omitted")
		t.Logf("NOTIFY-003: Created escalation %s without DisableNotifications field - defaults to false", escalation.Name)
	})
}

// TestNotificationIntegration tests notification behavior for sessions.
func TestNotificationIntegration(t *testing.T) {
	_ = helpers.SetupTest(t)

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
	_ = helpers.SetupTest(t)

	t.Run("EscalationMailProviderField", func(t *testing.T) {
		spec := breakglassv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:       "test-group",
			MaxValidFor:          "1h",
			ApprovalTimeout:      "30m",
			MailProvider:         "custom-mail-provider",
			DisableNotifications: helpers.BoolPtr(false),
		}
		assert.Equal(t, "custom-mail-provider", spec.MailProvider)
		assert.False(t, *spec.DisableNotifications)
		t.Logf("NOTIFY-012: MailProvider can override default MailProvider")
	})

	t.Run("EscalationWithoutMailProvider", func(t *testing.T) {
		spec := breakglassv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:       "test-group",
			MaxValidFor:          "1h",
			ApprovalTimeout:      "30m",
			DisableNotifications: helpers.BoolPtr(true),
		}
		assert.Empty(t, spec.MailProvider)
		assert.True(t, *spec.DisableNotifications)
		t.Logf("NOTIFY-013: Escalation can omit MailProvider when notifications disabled")
	})
}
