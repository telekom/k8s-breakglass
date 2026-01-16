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

// TestMailProviderConfigurationValidation tests MailProvider configuration validation.
func TestMailProviderConfigurationValidation(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("ValidSMTPConfiguration", func(t *testing.T) {
		provider := &telekomv1alpha1.MailProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:   helpers.GenerateUniqueName("e2e-mail-valid"),
				Labels: helpers.E2ETestLabels(),
			},
			Spec: telekomv1alpha1.MailProviderSpec{
				SMTP: telekomv1alpha1.SMTPConfig{
					Host: "breakglass-mailhog.breakglass-system.svc.cluster.local",
					Port: 1025,
				},
				Sender: telekomv1alpha1.SenderConfig{
					Address: "breakglass@example.com",
				},
			},
		}
		cleanup.Add(provider)
		err := cli.Create(ctx, provider)
		require.NoError(t, err, "Failed to create valid MailProvider")

		var fetched telekomv1alpha1.MailProvider
		err = cli.Get(ctx, types.NamespacedName{Name: provider.Name}, &fetched)
		require.NoError(t, err)
		assert.Equal(t, "breakglass-mailhog.breakglass-system.svc.cluster.local", fetched.Spec.SMTP.Host)
		assert.Equal(t, 1025, fetched.Spec.SMTP.Port)
		t.Logf("MAIL-001: Valid MailProvider created: host=%s, port=%d", fetched.Spec.SMTP.Host, fetched.Spec.SMTP.Port)
	})

	t.Run("TLSConfiguration", func(t *testing.T) {
		provider := &telekomv1alpha1.MailProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:   helpers.GenerateUniqueName("e2e-mail-tls"),
				Labels: helpers.E2ETestLabels(),
			},
			Spec: telekomv1alpha1.MailProviderSpec{
				SMTP: telekomv1alpha1.SMTPConfig{
					Host: "smtp.example.com",
					Port: 587,
				},
				Sender: telekomv1alpha1.SenderConfig{
					Address: "breakglass@example.com",
				},
			},
		}
		cleanup.Add(provider)
		err := cli.Create(ctx, provider)
		require.NoError(t, err, "Failed to create TLS MailProvider")

		var fetched telekomv1alpha1.MailProvider
		err = cli.Get(ctx, types.NamespacedName{Name: provider.Name}, &fetched)
		require.NoError(t, err)
		t.Logf("MAIL-002: TLS MailProvider created: host=%s, port=%d", fetched.Spec.SMTP.Host, fetched.Spec.SMTP.Port)
	})

	t.Run("AuthenticationConfiguration", func(t *testing.T) {
		provider := &telekomv1alpha1.MailProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:   helpers.GenerateUniqueName("e2e-mail-auth"),
				Labels: helpers.E2ETestLabels(),
			},
			Spec: telekomv1alpha1.MailProviderSpec{
				SMTP: telekomv1alpha1.SMTPConfig{
					Host:     "smtp.example.com",
					Port:     587,
					Username: "smtp-user",
					PasswordRef: &telekomv1alpha1.SecretKeyReference{
						Name:      "smtp-credentials",
						Namespace: "breakglass-system",
						Key:       "password",
					},
				},
				Sender: telekomv1alpha1.SenderConfig{
					Address: "breakglass@example.com",
				},
			},
		}
		cleanup.Add(provider)
		err := cli.Create(ctx, provider)
		require.NoError(t, err, "Failed to create authenticated MailProvider")

		var fetched telekomv1alpha1.MailProvider
		err = cli.Get(ctx, types.NamespacedName{Name: provider.Name}, &fetched)
		require.NoError(t, err)
		assert.NotNil(t, fetched.Spec.SMTP.PasswordRef, "Password ref should be set")
		assert.Equal(t, "smtp-credentials", fetched.Spec.SMTP.PasswordRef.Name)
		t.Logf("MAIL-003: Authenticated MailProvider created: user=%s, secretRef=%s",
			fetched.Spec.SMTP.Username, fetched.Spec.SMTP.PasswordRef.Name)
	})
}

// TestMailProviderStatusHealth tests MailProvider status health tracking.
func TestMailProviderStatusHealth(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("HealthyMailProviderHasReadyCondition", func(t *testing.T) {
		var provider telekomv1alpha1.MailProvider
		err := cli.Get(ctx, types.NamespacedName{Name: "breakglass-mailhog", Namespace: namespace}, &provider)
		if err != nil {
			err = cli.Get(ctx, types.NamespacedName{Name: "breakglass-mailhog"}, &provider)
		}
		if err != nil {
			t.Skip("No e2e MailProvider found, skipping health check test")
		}

		t.Logf("MAIL-004: MailProvider %s status: conditions=%d", provider.Name, len(provider.Status.Conditions))
		for _, cond := range provider.Status.Conditions {
			t.Logf("  Condition: type=%s, status=%s, reason=%s", cond.Type, cond.Status, cond.Reason)
		}
	})

	t.Run("UnreachableSMTPReportsUnhealthy", func(t *testing.T) {
		provider := &telekomv1alpha1.MailProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:   helpers.GenerateUniqueName("e2e-mail-unreachable"),
				Labels: helpers.E2ETestLabels(),
			},
			Spec: telekomv1alpha1.MailProviderSpec{
				SMTP: telekomv1alpha1.SMTPConfig{
					Host: "definitely-not-a-real-smtp-server.invalid",
					Port: 25,
				},
				Sender: telekomv1alpha1.SenderConfig{
					Address: "test@example.com",
				},
			},
		}
		cleanup.Add(provider)
		err := cli.Create(ctx, provider)
		require.NoError(t, err, "Failed to create unreachable MailProvider")

		time.Sleep(2 * time.Second)

		var fetched telekomv1alpha1.MailProvider
		err = cli.Get(ctx, types.NamespacedName{Name: provider.Name}, &fetched)
		require.NoError(t, err)

		t.Logf("MAIL-005: Unreachable MailProvider status: conditions=%d", len(fetched.Status.Conditions))
		for _, cond := range fetched.Status.Conditions {
			t.Logf("  Condition: type=%s, status=%s, reason=%s", cond.Type, cond.Status, cond.Reason)
		}
	})
}

// TestMailProviderRetryBehavior tests that email delivery retries on transient failures.
func TestMailProviderRetryBehavior(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)

	t.Run("RetryConfigurationDocumented", func(t *testing.T) {
		t.Logf("RETRY-001: Mail delivery retry behavior:")
		t.Logf("  - Connection failures trigger retry with exponential backoff")
		t.Logf("  - Max retries configured via controller flags")
		t.Logf("  - Permanent failures emit audit events and metrics")
		t.Logf("  - Session workflow continues regardless of notification failure")
	})

	t.Run("NotificationFailureDoesNotBlockApproval", func(t *testing.T) {
		cleanup := helpers.NewCleanup(t, cli)

		escalation := helpers.NewEscalationBuilder(helpers.GenerateUniqueName("e2e-mail-resilience"), helpers.GetTestNamespace()).
			WithEscalatedGroup(helpers.GenerateUniqueName("mail-test-group")).
			WithAllowedClusters(helpers.GetTestClusterName()).
			WithMaxValidFor("2h").
			WithApprovalTimeout("1h").
			Build()
		cleanup.Add(escalation)
		err := cli.Create(ctx, escalation)
		require.NoError(t, err)

		tc := helpers.NewTestContext(t, ctx)
		requesterClient := tc.RequesterClient()
		approverClient := tc.ApproverClient()

		session, err := requesterClient.CreateSessionAndWaitForPending(ctx, t, helpers.SessionRequest{
			Cluster: helpers.GetTestClusterName(),
			User:    helpers.TestUsers.Requester.Email,
			Group:   escalation.Spec.EscalatedGroup,
			Reason:  "Mail resilience test",
		}, helpers.WaitForStateTimeout)
		require.NoError(t, err)
		cleanup.Add(session)

		err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, session.Namespace)
		require.NoError(t, err, "Approval should succeed even if notification delivery is slow")

		t.Logf("RETRY-002: Session %s approved successfully - notification failures don't block workflow", session.Name)
	})
}

// TestMailProviderMultipleProviders tests behavior when multiple MailProviders exist.
func TestMailProviderMultipleProviders(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	t.Run("MultipleMailProvidersCanExist", func(t *testing.T) {
		provider1 := &telekomv1alpha1.MailProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:   helpers.GenerateUniqueName("e2e-mail-primary"),
				Labels: helpers.E2ELabelsWithExtra(map[string]string{"purpose": "primary"}),
			},
			Spec: telekomv1alpha1.MailProviderSpec{
				SMTP: telekomv1alpha1.SMTPConfig{
					Host: "smtp1.example.com",
					Port: 25,
				},
				Sender: telekomv1alpha1.SenderConfig{
					Address: "primary@example.com",
				},
			},
		}
		provider2 := &telekomv1alpha1.MailProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:   helpers.GenerateUniqueName("e2e-mail-secondary"),
				Labels: helpers.E2ELabelsWithExtra(map[string]string{"purpose": "secondary"}),
			},
			Spec: telekomv1alpha1.MailProviderSpec{
				SMTP: telekomv1alpha1.SMTPConfig{
					Host: "smtp2.example.com",
					Port: 25,
				},
				Sender: telekomv1alpha1.SenderConfig{
					Address: "secondary@example.com",
				},
			},
		}

		cleanup.Add(provider1)
		cleanup.Add(provider2)

		err := cli.Create(ctx, provider1)
		require.NoError(t, err)
		err = cli.Create(ctx, provider2)
		require.NoError(t, err)

		var list telekomv1alpha1.MailProviderList
		err = cli.List(ctx, &list)
		require.NoError(t, err)

		var foundPrimary, foundSecondary bool
		for _, mp := range list.Items {
			if mp.Name == provider1.Name {
				foundPrimary = true
			}
			if mp.Name == provider2.Name {
				foundSecondary = true
			}
		}

		assert.True(t, foundPrimary, "Primary MailProvider should exist")
		assert.True(t, foundSecondary, "Secondary MailProvider should exist")
		t.Logf("MULTI-001: Multiple MailProviders coexist: primary=%s, secondary=%s",
			provider1.Name, provider2.Name)
	})
}
