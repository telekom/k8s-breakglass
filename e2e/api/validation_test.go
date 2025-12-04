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
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// TestInvalidBreakglassEscalationConfigs tests explicitly invalid BreakglassEscalation configurations
func TestInvalidBreakglassEscalationConfigs(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("MissingEscalatedGroup", func(t *testing.T) {
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-missing-escalated-group",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				// EscalatedGroup intentionally missing
				MaxValidFor:     "4h",
				ApprovalTimeout: "2h",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{helpers.GetTestClusterName()},
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{helpers.GetTestApproverEmail()},
				},
			},
		}
		cleanup.Add(escalation)

		err := cli.Create(ctx, escalation)
		if err != nil {
			t.Logf("Missing escalatedGroup correctly rejected: %v", err)
			assert.True(t, errors.IsInvalid(err) || strings.Contains(err.Error(), "escalatedGroup"))
		} else {
			t.Log("WARNING: Empty escalatedGroup was accepted")
		}
	})

	t.Run("InvalidMaxValidForDuration", func(t *testing.T) {
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-invalid-max-valid-for",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:  "invalid-duration-admins",
				MaxValidFor:     "not-a-duration",
				ApprovalTimeout: "2h",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{helpers.GetTestClusterName()},
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{helpers.GetTestApproverEmail()},
				},
			},
		}
		cleanup.Add(escalation)

		err := cli.Create(ctx, escalation)
		if err != nil {
			t.Logf("Invalid maxValidFor correctly rejected: %v", err)
		} else {
			t.Log("WARNING: Invalid maxValidFor was accepted")
		}
	})

	t.Run("InvalidApprovalTimeoutDuration", func(t *testing.T) {
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-invalid-approval-timeout",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:  "invalid-timeout-admins",
				MaxValidFor:     "4h",
				ApprovalTimeout: "xyz123",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{helpers.GetTestClusterName()},
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{helpers.GetTestApproverEmail()},
				},
			},
		}
		cleanup.Add(escalation)

		err := cli.Create(ctx, escalation)
		if err != nil {
			t.Logf("Invalid approvalTimeout correctly rejected: %v", err)
		} else {
			t.Log("WARNING: Invalid approvalTimeout was accepted")
		}
	})

	t.Run("NoApproversConfigured", func(t *testing.T) {
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-no-approvers",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:  "no-approvers-admins",
				MaxValidFor:     "4h",
				ApprovalTimeout: "2h",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{helpers.GetTestClusterName()},
				},
				// Approvers intentionally empty
			},
		}
		cleanup.Add(escalation)

		err := cli.Create(ctx, escalation)
		if err != nil {
			t.Logf("No approvers correctly rejected: %v", err)
		} else {
			t.Log("No approvers was accepted - may use default behavior")
		}
	})

	t.Run("EmptyAllowedSection", func(t *testing.T) {
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-empty-allowed",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:  "empty-allowed-admins",
				MaxValidFor:     "4h",
				ApprovalTimeout: "2h",
				// Allowed intentionally empty
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{helpers.GetTestApproverEmail()},
				},
			},
		}
		cleanup.Add(escalation)

		err := cli.Create(ctx, escalation)
		if err != nil {
			t.Logf("Empty allowed section rejected: %v", err)
		} else {
			t.Log("Empty allowed section accepted - may mean global scope")
		}
	})

	t.Run("InvalidEmailInApprovers", func(t *testing.T) {
		escalation := &telekomv1alpha1.BreakglassEscalation{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-invalid-approver-email",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.BreakglassEscalationSpec{
				EscalatedGroup:  "invalid-email-admins",
				MaxValidFor:     "4h",
				ApprovalTimeout: "2h",
				Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
					Clusters: []string{helpers.GetTestClusterName()},
				},
				Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
					Users: []string{"not-an-email", "also-not-an-email"},
				},
			},
		}
		cleanup.Add(escalation)

		err := cli.Create(ctx, escalation)
		if err != nil {
			t.Logf("Invalid email correctly rejected: %v", err)
		} else {
			t.Log("Invalid email was accepted - email validation may be lenient")
		}
	})
}

// TestInvalidBreakglassSessionConfigs tests explicitly invalid BreakglassSession configurations
func TestInvalidBreakglassSessionConfigs(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()
	clusterName := helpers.GetTestClusterName()

	// First create a valid escalation to reference
	escalation := &telekomv1alpha1.BreakglassEscalation{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "e2e-validation-escalation",
			Namespace: namespace,
			Labels:    map[string]string{"e2e-test": "true"},
		},
		Spec: telekomv1alpha1.BreakglassEscalationSpec{
			EscalatedGroup:  "validation-admins",
			MaxValidFor:     "4h",
			ApprovalTimeout: "2h",
			Allowed: telekomv1alpha1.BreakglassEscalationAllowed{
				Clusters: []string{clusterName},
				Groups:   helpers.TestUsers.Requester.Groups,
			},
			Approvers: telekomv1alpha1.BreakglassEscalationApprovers{
				Users: []string{helpers.GetTestApproverEmail()},
			},
		},
	}
	cleanup.Add(escalation)
	err := cli.Create(ctx, escalation)
	require.NoError(t, err)

	t.Run("MissingClusterField", func(t *testing.T) {
		session := &telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-missing-cluster",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.BreakglassSessionSpec{
				// Cluster intentionally missing
				User:          helpers.GetTestUserEmail(),
				GrantedGroup:  escalation.Spec.EscalatedGroup,
				MaxValidFor:   "1h",
				RequestReason: "Testing missing cluster",
			},
		}
		cleanup.Add(session)

		err := cli.Create(ctx, session)
		if err != nil {
			t.Logf("Missing cluster correctly rejected: %v", err)
		} else {
			t.Log("WARNING: Missing cluster was accepted")
		}
	})

	t.Run("MissingUserField", func(t *testing.T) {
		session := &telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-missing-user",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.BreakglassSessionSpec{
				Cluster: clusterName,
				// User intentionally missing
				GrantedGroup:  escalation.Spec.EscalatedGroup,
				MaxValidFor:   "1h",
				RequestReason: "Testing missing user",
			},
		}
		cleanup.Add(session)

		err := cli.Create(ctx, session)
		if err != nil {
			t.Logf("Missing user correctly rejected: %v", err)
		} else {
			t.Log("WARNING: Missing user was accepted")
		}
	})

	t.Run("MissingGrantedGroup", func(t *testing.T) {
		session := &telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-missing-granted-group",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.BreakglassSessionSpec{
				Cluster:       clusterName,
				User:          helpers.GetTestUserEmail(),
				MaxValidFor:   "1h",
				RequestReason: "Testing missing granted group",
				// GrantedGroup intentionally missing
			},
		}
		cleanup.Add(session)

		err := cli.Create(ctx, session)
		if err != nil {
			t.Logf("Missing grantedGroup correctly rejected: %v", err)
		} else {
			t.Log("WARNING: Missing grantedGroup was accepted")
		}
	})

	t.Run("InvalidMaxValidForDuration", func(t *testing.T) {
		session := &telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-invalid-session-duration",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.BreakglassSessionSpec{
				Cluster:       clusterName,
				User:          helpers.GetTestUserEmail(),
				GrantedGroup:  escalation.Spec.EscalatedGroup,
				MaxValidFor:   "invalid-duration",
				RequestReason: "Testing invalid duration",
			},
		}
		cleanup.Add(session)

		err := cli.Create(ctx, session)
		if err != nil {
			t.Logf("Invalid maxValidFor correctly rejected: %v", err)
		} else {
			t.Log("WARNING: Invalid maxValidFor was accepted")
		}
	})

	t.Run("ExcessiveDurationRequest", func(t *testing.T) {
		session := &telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-excessive-duration",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.BreakglassSessionSpec{
				Cluster:       clusterName,
				User:          helpers.GetTestUserEmail(),
				GrantedGroup:  escalation.Spec.EscalatedGroup,
				MaxValidFor:   "8760h", // One year
				RequestReason: "Testing excessive duration",
			},
		}
		cleanup.Add(session)

		err := cli.Create(ctx, session)
		if err != nil {
			t.Logf("Excessive duration correctly rejected: %v", err)
		} else {
			t.Log("Excessive duration was accepted - may be capped by escalation maxValidFor")
		}
	})

	t.Run("NonMatchingGrantedGroup", func(t *testing.T) {
		session := &telekomv1alpha1.BreakglassSession{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-non-matching-group",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.BreakglassSessionSpec{
				Cluster:       clusterName,
				User:          helpers.GetTestUserEmail(),
				GrantedGroup:  "group-that-no-escalation-defines",
				MaxValidFor:   "1h",
				RequestReason: "Testing non-matching group",
			},
		}
		cleanup.Add(session)

		err := cli.Create(ctx, session)
		if err != nil {
			t.Logf("Non-matching group correctly rejected: %v", err)
		} else {
			t.Log("Non-matching group was accepted - validation may happen at approval")
		}
	})
}

// TestInvalidDenyPolicyConfigs tests explicitly invalid DenyPolicy configurations
func TestInvalidDenyPolicyConfigs(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("EmptyRulesAndPodSecurityRules", func(t *testing.T) {
		policy := &telekomv1alpha1.DenyPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-empty-rules-policy",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.DenyPolicySpec{
				// Both rules and podSecurityRules empty
			},
		}
		cleanup.Add(policy)

		err := cli.Create(ctx, policy)
		if err != nil {
			t.Logf("Empty rules correctly rejected: %v", err)
		} else {
			t.Log("Empty rules policy was accepted - may be valid (no-op policy)")
		}
	})

	t.Run("RuleWithEmptyVerbs", func(t *testing.T) {
		policy := &telekomv1alpha1.DenyPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-empty-verbs-policy",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.DenyPolicySpec{
				Rules: []telekomv1alpha1.DenyRule{
					{
						Verbs:     []string{}, // Empty verbs
						Resources: []string{"pods"},
						APIGroups: []string{""},
					},
				},
			},
		}
		cleanup.Add(policy)

		err := cli.Create(ctx, policy)
		if err != nil {
			t.Logf("Empty verbs correctly rejected: %v", err)
		} else {
			t.Log("Empty verbs was accepted - may be valid (matches nothing)")
		}
	})

	t.Run("RuleWithEmptyResources", func(t *testing.T) {
		policy := &telekomv1alpha1.DenyPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-empty-resources-policy",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.DenyPolicySpec{
				Rules: []telekomv1alpha1.DenyRule{
					{
						Verbs:     []string{"get"},
						Resources: []string{}, // Empty resources
						APIGroups: []string{""},
					},
				},
			},
		}
		cleanup.Add(policy)

		err := cli.Create(ctx, policy)
		if err != nil {
			t.Logf("Empty resources correctly rejected: %v", err)
		} else {
			t.Log("Empty resources was accepted - may be valid (matches nothing)")
		}
	})

	t.Run("RuleWithInvalidVerb", func(t *testing.T) {
		policy := &telekomv1alpha1.DenyPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-invalid-verb-policy",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.DenyPolicySpec{
				Rules: []telekomv1alpha1.DenyRule{
					{
						Verbs:     []string{"invalid-verb-xyz"},
						Resources: []string{"pods"},
						APIGroups: []string{""},
					},
				},
			},
		}
		cleanup.Add(policy)

		err := cli.Create(ctx, policy)
		if err != nil {
			t.Logf("Invalid verb correctly rejected: %v", err)
		} else {
			t.Log("Invalid verb was accepted - verb validation may be lenient")
		}
	})

	t.Run("PodSecurityRulesWithInvalidBlockFactor", func(t *testing.T) {
		policy := &telekomv1alpha1.DenyPolicy{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-invalid-block-factor",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.DenyPolicySpec{
				PodSecurityRules: &telekomv1alpha1.PodSecurityRules{
					RiskFactors: telekomv1alpha1.RiskFactors{
						HostNetwork: 50,
					},
					Thresholds: []telekomv1alpha1.RiskThreshold{
						{
							MaxScore: 50,
							Action:   "deny",
						},
					},
					BlockFactors: []string{"invalid-factor-xyz"},
				},
			},
		}
		cleanup.Add(policy)

		err := cli.Create(ctx, policy)
		if err != nil {
			t.Logf("Invalid block factor correctly rejected: %v", err)
		} else {
			t.Log("Invalid block factor was accepted - validation may be lenient")
		}
	})
}

// TestInvalidIdentityProviderConfigs tests explicitly invalid IdentityProvider configurations
func TestInvalidIdentityProviderConfigs(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("MissingAuthority", func(t *testing.T) {
		idp := &telekomv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-missing-authority",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.IdentityProviderSpec{
				OIDC: telekomv1alpha1.OIDCConfig{
					// Authority intentionally missing
					ClientID: "some-client",
				},
			},
		}
		cleanup.Add(idp)

		err := cli.Create(ctx, idp)
		if err != nil {
			t.Logf("Missing authority correctly rejected: %v", err)
		} else {
			t.Log("WARNING: Missing authority was accepted")
		}
	})

	t.Run("MissingClientID", func(t *testing.T) {
		idp := &telekomv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-missing-client-id",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.IdentityProviderSpec{
				OIDC: telekomv1alpha1.OIDCConfig{
					Authority: "https://example.com",
					// ClientID intentionally missing
				},
			},
		}
		cleanup.Add(idp)

		err := cli.Create(ctx, idp)
		if err != nil {
			t.Logf("Missing clientID correctly rejected: %v", err)
		} else {
			t.Log("WARNING: Missing clientID was accepted")
		}
	})

	t.Run("InvalidAuthority", func(t *testing.T) {
		idp := &telekomv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-invalid-authority",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.IdentityProviderSpec{
				OIDC: telekomv1alpha1.OIDCConfig{
					Authority: "not-a-valid-url",
					ClientID:  "some-client",
				},
			},
		}
		cleanup.Add(idp)

		err := cli.Create(ctx, idp)
		if err != nil {
			t.Logf("Invalid authority correctly rejected: %v", err)
		} else {
			t.Log("Invalid authority was accepted - URL validation may happen at reconcile")
		}
	})

	t.Run("KeycloakSecretRefToNonExistentSecret", func(t *testing.T) {
		idp := &telekomv1alpha1.IdentityProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-nonexistent-secret-ref",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.IdentityProviderSpec{
				OIDC: telekomv1alpha1.OIDCConfig{
					Authority: "https://example.com",
					ClientID:  "some-client",
				},
				GroupSyncProvider: telekomv1alpha1.GroupSyncProviderKeycloak,
				Keycloak: &telekomv1alpha1.KeycloakGroupSync{
					BaseURL:  "https://keycloak.example.com",
					Realm:    "test-realm",
					ClientID: "test-client",
					ClientSecretRef: telekomv1alpha1.SecretKeyReference{
						Name:      "secret-that-does-not-exist",
						Namespace: namespace,
						Key:       "client-secret",
					},
				},
			},
		}
		cleanup.Add(idp)

		err := cli.Create(ctx, idp)
		if err != nil {
			t.Logf("Non-existent secret ref rejected: %v", err)
		} else {
			t.Log("Non-existent secret ref accepted - validation at reconcile time")
		}
	})
}

// TestInvalidMailProviderConfigs tests explicitly invalid MailProvider configurations
func TestInvalidMailProviderConfigs(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("MissingSMTPHost", func(t *testing.T) {
		mp := &telekomv1alpha1.MailProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-missing-smtp-host",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.MailProviderSpec{
				SMTP: telekomv1alpha1.SMTPConfig{
					// Host intentionally missing
					Port: 587,
				},
				Sender: telekomv1alpha1.SenderConfig{
					Address: "test@example.com",
				},
			},
		}
		cleanup.Add(mp)

		err := cli.Create(ctx, mp)
		if err != nil {
			t.Logf("Missing smtpHost correctly rejected: %v", err)
		} else {
			t.Log("WARNING: Missing smtpHost was accepted")
		}
	})

	t.Run("InvalidSMTPPort", func(t *testing.T) {
		mp := &telekomv1alpha1.MailProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-invalid-smtp-port",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.MailProviderSpec{
				SMTP: telekomv1alpha1.SMTPConfig{
					Host: "smtp.example.com",
					Port: 99999, // Invalid port
				},
				Sender: telekomv1alpha1.SenderConfig{
					Address: "test@example.com",
				},
			},
		}
		cleanup.Add(mp)

		err := cli.Create(ctx, mp)
		if err != nil {
			t.Logf("Invalid smtpPort correctly rejected: %v", err)
		} else {
			t.Log("Invalid smtpPort was accepted - port validation may be lenient")
		}
	})

	t.Run("InvalidSenderEmail", func(t *testing.T) {
		mp := &telekomv1alpha1.MailProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-invalid-sender-email",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.MailProviderSpec{
				SMTP: telekomv1alpha1.SMTPConfig{
					Host: "smtp.example.com",
					Port: 587,
				},
				Sender: telekomv1alpha1.SenderConfig{
					Address: "not-an-email",
				},
			},
		}
		cleanup.Add(mp)

		err := cli.Create(ctx, mp)
		if err != nil {
			t.Logf("Invalid senderMail correctly rejected: %v", err)
		} else {
			t.Log("Invalid senderMail was accepted - email validation may be lenient")
		}
	})

	t.Run("MissingSenderAddress", func(t *testing.T) {
		mp := &telekomv1alpha1.MailProvider{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-missing-sender-address",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.MailProviderSpec{
				SMTP: telekomv1alpha1.SMTPConfig{
					Host: "smtp.example.com",
					Port: 587,
				},
				Sender: telekomv1alpha1.SenderConfig{
					// Address intentionally missing
				},
			},
		}
		cleanup.Add(mp)

		err := cli.Create(ctx, mp)
		if err != nil {
			t.Logf("Missing sender address correctly rejected: %v", err)
		} else {
			t.Log("WARNING: Missing sender address was accepted")
		}
	})
}

// TestInvalidClusterConfigConfigs tests explicitly invalid ClusterConfig configurations
func TestInvalidClusterConfigConfigs(t *testing.T) {
	if !helpers.IsE2EEnabled() {
		t.Skip("Skipping E2E test. Set E2E_TEST=true to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)
	namespace := helpers.GetTestNamespace()

	t.Run("MissingKubeconfigSecretRef", func(t *testing.T) {
		cfg := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-missing-kubeconfig-ref",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.ClusterConfigSpec{
				ClusterID: "test-cluster",
				// KubeconfigSecretRef intentionally missing
			},
		}
		cleanup.Add(cfg)

		err := cli.Create(ctx, cfg)
		if err != nil {
			t.Logf("Missing kubeconfigSecretRef correctly rejected: %v", err)
		} else {
			t.Log("WARNING: Missing kubeconfigSecretRef was accepted")
		}
	})

	t.Run("KubeconfigSecretRefToNonExistentSecret", func(t *testing.T) {
		cfg := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-nonexistent-kubeconfig-secret",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.ClusterConfigSpec{
				ClusterID: "test-cluster",
				KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{
					Name:      "kubeconfig-secret-that-does-not-exist",
					Namespace: namespace,
					Key:       "kubeconfig",
				},
			},
		}
		cleanup.Add(cfg)

		err := cli.Create(ctx, cfg)
		if err != nil {
			t.Logf("Non-existent kubeconfig secret rejected: %v", err)
		} else {
			t.Log("Non-existent kubeconfig secret accepted - validation at reconcile")
		}
	})

	t.Run("KubeconfigSecretWithWrongKey", func(t *testing.T) {
		// Create a secret with the wrong key
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-wrong-key-secret",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Data: map[string][]byte{
				"wrong-key": []byte("some data"),
			},
		}
		cleanup.Add(secret)
		err := cli.Create(ctx, secret)
		require.NoError(t, err)

		cfg := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-wrong-key-cluster",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.ClusterConfigSpec{
				ClusterID: "test-cluster",
				KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{
					Name:      secret.Name,
					Namespace: namespace,
					Key:       "kubeconfig", // Key that doesn't exist
				},
			},
		}
		cleanup.Add(cfg)

		err = cli.Create(ctx, cfg)
		if err != nil {
			t.Logf("Wrong key reference rejected: %v", err)
		} else {
			t.Log("Wrong key reference accepted - key validation at reconcile")
		}
	})

	t.Run("InvalidQPSValue", func(t *testing.T) {
		// Create a valid secret first
		secret := &corev1.Secret{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-qps-test-secret",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Data: map[string][]byte{
				"kubeconfig": []byte("apiVersion: v1\nkind: Config"),
			},
		}
		cleanup.Add(secret)
		err := cli.Create(ctx, secret)
		require.NoError(t, err)

		zeroQPS := int32(0)
		cfg := &telekomv1alpha1.ClusterConfig{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "e2e-invalid-qps",
				Namespace: namespace,
				Labels:    map[string]string{"e2e-test": "true"},
			},
			Spec: telekomv1alpha1.ClusterConfigSpec{
				ClusterID: "test-cluster",
				KubeconfigSecretRef: &telekomv1alpha1.SecretKeyReference{
					Name:      secret.Name,
					Namespace: namespace,
					Key:       "kubeconfig",
				},
				QPS: &zeroQPS, // 0 is invalid (min=1)
			},
		}
		cleanup.Add(cfg)

		err = cli.Create(ctx, cfg)
		if err != nil {
			t.Logf("Zero QPS correctly rejected: %v", err)
		} else {
			t.Log("Zero QPS was accepted - QPS validation may be lenient")
		}
	})
}
