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
	"github.com/stretchr/testify/require"
	"k8s.io/utils/ptr"
	"sigs.k8s.io/controller-runtime/pkg/client"

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
		escalation.Spec.DisableNotifications = ptr.To(true)

		s.MustCreateResource(escalation)
		require.NoError(t, s.Client.Get(s.Ctx, client.ObjectKeyFromObject(escalation), escalation))

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
		escalation.Spec.DisableNotifications = ptr.To(false)

		s.MustCreateResource(escalation)
		require.NoError(t, s.Client.Get(s.Ctx, client.ObjectKeyFromObject(escalation), escalation))

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
		require.NoError(t, s.Client.Get(s.Ctx, client.ObjectKeyFromObject(escalation), escalation))

		assert.Nil(t, escalation.Spec.DisableNotifications,
			"NOTIFY-003: DisableNotifications should be nil when omitted")
		t.Logf("NOTIFY-003: Created escalation %s without DisableNotifications field - defaults to false", escalation.Name)
	})
}
