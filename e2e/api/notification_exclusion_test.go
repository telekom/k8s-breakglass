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
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/types"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestMailProviderCRUD tests MailProvider create/read/update/delete operations.
func TestMailProviderCRUD(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("CreateMailProvider", func(t *testing.T) {
		provider := &telekomv1alpha1.MailProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:   helpers.GenerateUniqueName("e2e-mail-provider"),
				Labels: map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.MailProviderSpec{
				DisplayName: "E2E Test Mail Provider",
				SMTP: telekomv1alpha1.SMTPConfig{
					Host: "smtp.example.com",
					Port: 587,
				},
				Sender: telekomv1alpha1.SenderConfig{
					Address: "noreply@example.com",
					Name:    "Breakglass System",
				},
			},
		}
		cleanup.Add(provider)
		err := cli.Create(ctx, provider)
		require.NoError(t, err, "Failed to create MailProvider")

		var fetched telekomv1alpha1.MailProvider
		err = cli.Get(ctx, types.NamespacedName{Name: provider.Name}, &fetched)
		require.NoError(t, err)
		assert.Equal(t, "smtp.example.com", fetched.Spec.SMTP.Host)
		assert.Equal(t, 587, fetched.Spec.SMTP.Port)
		assert.Equal(t, "noreply@example.com", fetched.Spec.Sender.Address)

		t.Logf("MailProvider created: %s", fetched.Name)
	})

	t.Run("CreateDefaultMailProvider", func(t *testing.T) {
		// Check if a default MailProvider already exists
		var existingProviders telekomv1alpha1.MailProviderList
		err := cli.List(ctx, &existingProviders)
		require.NoError(t, err)

		for _, p := range existingProviders.Items {
			if p.Spec.Default {
				t.Skipf("Default MailProvider already exists: %s", p.Name)
			}
		}

		provider := &telekomv1alpha1.MailProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:   helpers.GenerateUniqueName("e2e-mail-default"),
				Labels: map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.MailProviderSpec{
				DisplayName: "Default Mail Provider",
				Default:     true,
				SMTP: telekomv1alpha1.SMTPConfig{
					Host: "smtp.default.example.com",
					Port: 465,
				},
				Sender: telekomv1alpha1.SenderConfig{
					Address: "breakglass@example.com",
					Name:    "Default Sender",
				},
			},
		}
		cleanup.Add(provider)
		err = cli.Create(ctx, provider)
		require.NoError(t, err)

		var fetched telekomv1alpha1.MailProvider
		err = cli.Get(ctx, types.NamespacedName{Name: provider.Name}, &fetched)
		require.NoError(t, err)
		assert.True(t, fetched.Spec.Default)

		t.Logf("Default MailProvider created: %s", fetched.Name)
	})
}

// TestNotificationExclusions tests NotificationExclusions field in BreakglassEscalation.
func TestNotificationExclusions(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	t.Run("EscalationWithUserNotificationExclusion", func(t *testing.T) {
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      helpers.GenerateUniqueName("e2e-esc-exclude-user"),
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup: "notification-test-group",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   helpers.TestUsers.NotificationTestRequester.Groups,
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{helpers.TestUsers.NotificationTestApprover.Email},
				},
				NotificationExclusions: &telekomv1alpha1.NotificationExclusions{
					Users: []string{"excluded@example.com", "silent-admin@example.com"},
				},
			},
		}
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err, "Failed to create escalation with notification exclusions")

		var fetched telekomv1alpha1.BreakglassEscalation
		err = cli.Get(ctx, types.NamespacedName{Name: escalation.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.NotificationExclusions)
		assert.Len(t, fetched.Spec.NotificationExclusions.Users, 2)

		t.Logf("Escalation with user notification exclusions created")
	})

	t.Run("EscalationWithGroupNotificationExclusion", func(t *testing.T) {
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      helpers.GenerateUniqueName("e2e-esc-exclude-group"),
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup: "notification-group-test",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   helpers.TestUsers.NotificationTestRequester.Groups,
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{helpers.TestUsers.NotificationTestApprover.Email},
				},
				NotificationExclusions: &telekomv1alpha1.NotificationExclusions{
					Groups: []string{"silent-team", "no-notifications"},
				},
			},
		}
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err, "Failed to create escalation with group notification exclusions")

		var fetched telekomv1alpha1.BreakglassEscalation
		err = cli.Get(ctx, types.NamespacedName{Name: escalation.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.NotificationExclusions)
		assert.Len(t, fetched.Spec.NotificationExclusions.Groups, 2)

		t.Logf("Escalation with group notification exclusions created")
	})
}

// TestApproversHiddenFromUI tests the HiddenFromUI field in Approvers.
func TestApproversHiddenFromUI(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	t.Run("EscalationWithHiddenApprovers", func(t *testing.T) {
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      helpers.GenerateUniqueName("e2e-esc-hidden-approvers"),
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup: "hidden-approvers-group",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   helpers.TestUsers.NotificationTestRequester.Groups,
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users:        []string{helpers.TestUsers.NotificationTestApprover.Email},
					HiddenFromUI: []string{"hidden-admin@example.com", "silent-approver@example.com"},
				},
			},
		}
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err, "Failed to create escalation with hidden approvers")

		var fetched telekomv1alpha1.BreakglassEscalation
		err = cli.Get(ctx, types.NamespacedName{Name: escalation.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		assert.Len(t, fetched.Spec.Approvers.HiddenFromUI, 2)

		t.Logf("Escalation with hidden approvers created")
	})
}

// TestApproverGroups tests the Groups field in Approvers.
func TestApproverGroups(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	t.Run("EscalationWithApproverGroups", func(t *testing.T) {
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      helpers.GenerateUniqueName("e2e-esc-approver-groups"),
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup: "approver-groups-test",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   helpers.TestUsers.NotificationTestRequester.Groups,
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users:  []string{helpers.TestUsers.NotificationTestApprover.Email},
					Groups: []string{"sre-team", "platform-team", "security-team"},
				},
			},
		}
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err, "Failed to create escalation with approver groups")

		var fetched telekomv1alpha1.BreakglassEscalation
		err = cli.Get(ctx, types.NamespacedName{Name: escalation.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		assert.Len(t, fetched.Spec.Approvers.Groups, 3)

		t.Logf("Escalation with approver groups created")
	})
}

// TestRequestReasonConfiguration tests RequestReason field in BreakglassEscalation.
func TestRequestReasonConfiguration(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	t.Run("EscalationWithMandatoryReason", func(t *testing.T) {
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      helpers.GenerateUniqueName("e2e-esc-mandatory-reason"),
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup: "mandatory-reason-group",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{clusterName},
					Groups:   helpers.TestUsers.NotificationTestRequester.Groups,
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{helpers.TestUsers.NotificationTestApprover.Email},
				},
				RequestReason: &telekomv1alpha1.ReasonConfig{
					Mandatory:   true,
					Description: "Please provide a ticket number and justification",
				},
			},
		}
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err, "Failed to create escalation with mandatory reason")

		var fetched telekomv1alpha1.BreakglassEscalation
		err = cli.Get(ctx, types.NamespacedName{Name: escalation.Name, Namespace: namespace}, &fetched)
		require.NoError(t, err)
		require.NotNil(t, fetched.Spec.RequestReason)
		assert.True(t, fetched.Spec.RequestReason.Mandatory)
		assert.Equal(t, "Please provide a ticket number and justification", fetched.Spec.RequestReason.Description)

		t.Logf("Escalation with mandatory request reason created")
	})
}
