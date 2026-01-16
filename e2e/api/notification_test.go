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
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	telekomv1alpha1 "github.com/telekom/k8s-breakglass/api/v1alpha1"
	"github.com/telekom/k8s-breakglass/e2e/helpers"
)

// MailHogMessage represents a message from MailHog API
type MailHogMessage struct {
	ID   string `json:"ID"`
	From struct {
		Mailbox string `json:"Mailbox"`
		Domain  string `json:"Domain"`
	} `json:"From"`
	To []struct {
		Mailbox string `json:"Mailbox"`
		Domain  string `json:"Domain"`
	} `json:"To"`
	Content struct {
		Headers struct {
			Subject []string `json:"Subject"`
			From    []string `json:"From"`
			To      []string `json:"To"`
		} `json:"Headers"`
		Body string `json:"Body"`
	} `json:"Content"`
	Created time.Time `json:"Created"`
}

// MailHogResponse represents the response from MailHog messages API
type MailHogResponse struct {
	Total    int              `json:"total"`
	Count    int              `json:"count"`
	Start    int              `json:"start"`
	Items    []MailHogMessage `json:"items"`
	Messages []MailHogMessage `json:"messages"` // v1 API uses "messages" key
}

// getMailHogMessages retrieves messages from MailHog API
func getMailHogMessages(t *testing.T) []MailHogMessage {
	t.Helper()
	mailhogURL := helpers.GetMailHogAPIURL()
	resp, err := http.Get(mailhogURL + "/api/v2/messages")
	if err != nil {
		t.Logf("Failed to connect to MailHog at %s: %v", mailhogURL, err)
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		t.Logf("MailHog returned status %d", resp.StatusCode)
		return nil
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Logf("Failed to read MailHog response: %v", err)
		return nil
	}

	var mailhogResp MailHogResponse
	if err := json.Unmarshal(body, &mailhogResp); err != nil {
		t.Logf("Failed to parse MailHog response: %v", err)
		return nil
	}

	return mailhogResp.Items
}

// clearMailHogMessages clears all messages in MailHog
func clearMailHogMessages(t *testing.T) {
	t.Helper()
	mailhogURL := helpers.GetMailHogAPIURL()
	req, err := http.NewRequest(http.MethodDelete, mailhogURL+"/api/v1/messages", nil)
	if err != nil {
		t.Logf("Failed to create delete request: %v", err)
		return
	}
	client := helpers.ShortTimeoutHTTPClient()
	resp, err := client.Do(req)
	if err != nil {
		t.Logf("Failed to clear MailHog messages: %v", err)
		return
	}
	defer func() { _ = resp.Body.Close() }()
}

// waitForMailHogMessage waits for a message matching the given subject substring
func waitForMailHogMessage(t *testing.T, subjectContains string, timeout time.Duration) *MailHogMessage {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		messages := getMailHogMessages(t)
		for i := range messages {
			for _, subject := range messages[i].Content.Headers.Subject {
				if strings.Contains(strings.ToLower(subject), strings.ToLower(subjectContains)) {
					return &messages[i]
				}
			}
		}
		time.Sleep(1 * time.Second)
	}
	return nil
}

// TestNotificationOnSessionCreation [M-001] tests that the controller sends notification
// emails when sessions are created and MailHog receives them.
func TestNotificationOnSessionCreation(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())
	if !helpers.IsMailHogTestEnabled() {
		t.Skip("MailHog tests are disabled. Unset E2E_SKIP_MAILHOG_TESTS to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	tc := helpers.NewTestContext(t, ctx)
	requesterClient := tc.ClientForUser(helpers.TestUsers.NotificationTestRequester)
	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	clusterName := helpers.GetTestClusterName()
	namespace := helpers.GetTestNamespace()
	uniqueID := fmt.Sprintf("notif-%d", time.Now().UnixNano()%10000)

	// Clear existing messages
	clearMailHogMessages(t)

	// Create escalation using Kubernetes client (direct CR creation)
	escalationName := fmt.Sprintf("e2e-notif-esc-%s", uniqueID)
	escalation := helpers.NewEscalationBuilder(escalationName, namespace).
		WithEscalatedGroup(fmt.Sprintf("escalated-notif-group-%s", uniqueID)).
		WithAllowedClusters(clusterName).
		WithAllowedGroups(helpers.TestUsers.NotificationTestRequester.Groups[0]).
		WithApproverUsers(helpers.TestUsers.NotificationTestApprover.Email).
		Build()

	err := cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create escalation")
	cleanup.Add(escalation)

	// Create session via REST API - this should trigger a notification email
	sessionReq := helpers.SessionRequest{
		Cluster:  clusterName,
		User:     helpers.TestUsers.NotificationTestRequester.Email,
		Group:    escalation.Spec.EscalatedGroup,
		Reason:   "E2E notification test - testing email delivery",
		Duration: 1800, // 30 minutes in seconds
	}

	session, err := requesterClient.CreateSession(ctx, t, sessionReq)
	require.NoError(t, err, "Failed to create session")
	t.Logf("Created session: %s/%s", session.Namespace, session.Name)

	// Wait for notification email
	t.Run("SessionCreationEmailSent", func(t *testing.T) {
		// Wait for email with the session name or group name
		msg := waitForMailHogMessage(t, escalation.Spec.EscalatedGroup, helpers.WaitForStateTimeout)
		if msg == nil {
			// Try waiting for "pending" which is common in notification subjects
			msg = waitForMailHogMessage(t, "pending", 15*time.Second)
		}
		require.NotNil(t, msg, "Session creation should trigger a notification email - check MailProvider and controller configuration")

		// Verify email content
		assert.NotEmpty(t, msg.Content.Headers.Subject, "Email should have a subject")
		for _, subject := range msg.Content.Headers.Subject {
			t.Logf("Email subject: %s", subject)
		}
	})
}

// TestNotificationWithGroupApprovers [M-001b] tests that notifications work correctly
// when approvers are specified as groups rather than individual users.
// This requires Keycloak group sync to resolve group members' email addresses.
func TestNotificationWithGroupApprovers(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())
	if !helpers.IsMailHogTestEnabled() {
		t.Skip("MailHog tests are disabled. Unset E2E_SKIP_MAILHOG_TESTS to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	tc := helpers.NewTestContext(t, ctx)
	requesterClient := tc.ClientForUser(helpers.TestUsers.NotificationTestRequester)
	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	clusterName := helpers.GetTestClusterName()
	namespace := helpers.GetTestNamespace()
	uniqueID := fmt.Sprintf("grp-notif-%d", time.Now().UnixNano()%10000)

	// Clear existing messages
	clearMailHogMessages(t)

	// Create escalation with approver GROUPS (not individual users)
	// This tests the Keycloak group sync functionality that resolves group members
	escalationName := fmt.Sprintf("e2e-grp-notif-esc-%s", uniqueID)
	approverGroup := helpers.TestUsers.NotificationTestApprover.Groups[1] // "notification-test-approver"
	escalation := helpers.NewEscalationBuilder(escalationName, namespace).
		WithEscalatedGroup(fmt.Sprintf("escalated-grp-notif-%s", uniqueID)).
		WithAllowedClusters(clusterName).
		WithAllowedGroups(helpers.TestUsers.NotificationTestRequester.Groups[0]).
		WithApproverGroups(approverGroup). // Use group instead of individual user
		Build()

	err := cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create escalation with group-based approvers")
	cleanup.Add(escalation)

	t.Logf("Created escalation with approver group: %s", approverGroup)

	// Create session via REST API - this should trigger a notification email
	// The controller must use Keycloak group sync to resolve the group members
	sessionReq := helpers.SessionRequest{
		Cluster:  clusterName,
		User:     helpers.TestUsers.NotificationTestRequester.Email,
		Group:    escalation.Spec.EscalatedGroup,
		Reason:   "E2E group sync notification test - testing group-based approver resolution",
		Duration: 1800, // 30 minutes in seconds
	}

	session, err := requesterClient.CreateSession(ctx, t, sessionReq)
	require.NoError(t, err, "Failed to create session")
	t.Logf("Created session: %s/%s (requires group sync to send notification)", session.Namespace, session.Name)

	// Wait for notification email - this will only arrive if group sync works correctly
	t.Run("GroupApproverNotificationSent", func(t *testing.T) {
		// The email should be sent to the group members resolved via Keycloak
		msg := waitForMailHogMessage(t, escalation.Spec.EscalatedGroup, helpers.WaitForStateTimeout)
		if msg == nil {
			// Try waiting for "pending" as a fallback
			msg = waitForMailHogMessage(t, "pending", 15*time.Second)
		}

		if msg == nil {
			// Provide detailed error message for debugging group sync issues
			t.Fatalf("No notification email received for group-based approvers. "+
				"This typically means Keycloak group sync is not working correctly. "+
				"Check that:\n"+
				"  1. The breakglass-group-sync client has realm-management roles (view-users, query-groups)\n"+
				"  2. The IdentityProvider has groupSyncProvider=Keycloak configured\n"+
				"  3. The group '%s' exists in Keycloak and has members\n"+
				"  4. Controller logs for 'Failed to resolve approver group members' errors",
				approverGroup)
		}

		// Verify the email was sent to the approver
		t.Logf("Received notification email - group sync is working correctly")
		assert.NotEmpty(t, msg.Content.Headers.Subject, "Email should have a subject")
		for _, subject := range msg.Content.Headers.Subject {
			t.Logf("Email subject: %s", subject)
		}

		// Verify that the email was sent to the correct recipient (group member)
		recipientFound := false
		for _, to := range msg.To {
			fullEmail := to.Mailbox + "@" + to.Domain
			t.Logf("Email recipient: %s", fullEmail)
			if strings.Contains(fullEmail, "notification-approver") {
				recipientFound = true
			}
		}
		assert.True(t, recipientFound, "Email should be sent to a member of the approver group")
	})
}

// TestNotificationOnSessionApproval tests that notification is sent when a session is approved
func TestNotificationOnSessionApproval(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())
	if !helpers.IsMailHogTestEnabled() {
		t.Skip("MailHog tests are disabled. Unset E2E_SKIP_MAILHOG_TESTS to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	tc := helpers.NewTestContext(t, ctx)
	requesterClient := tc.ClientForUser(helpers.TestUsers.NotificationTestRequester)
	approverClient := tc.ClientForUser(helpers.TestUsers.NotificationTestApprover)
	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	clusterName := helpers.GetTestClusterName()
	namespace := helpers.GetTestNamespace()
	uniqueID := fmt.Sprintf("notif-appr-%d", time.Now().UnixNano()%10000)

	// Create escalation using Kubernetes client
	escalationName := fmt.Sprintf("e2e-notif-appr-esc-%s", uniqueID)
	escalation := helpers.NewEscalationBuilder(escalationName, namespace).
		WithEscalatedGroup(fmt.Sprintf("escalated-notif-approval-group-%s", uniqueID)).
		WithAllowedClusters(clusterName).
		WithAllowedGroups(helpers.TestUsers.NotificationTestRequester.Groups[0]).
		WithApproverUsers(helpers.TestUsers.NotificationTestApprover.Email).
		Build()

	err := cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create escalation")
	cleanup.Add(escalation)

	// Create session via REST API
	sessionReq := helpers.SessionRequest{
		Cluster:  clusterName,
		User:     helpers.TestUsers.NotificationTestRequester.Email,
		Group:    escalation.Spec.EscalatedGroup,
		Reason:   "E2E notification approval test",
		Duration: 1800, // 30 minutes
	}

	session, err := requesterClient.CreateSession(ctx, t, sessionReq)
	require.NoError(t, err, "Failed to create session")
	t.Logf("Created session: %s/%s", session.Namespace, session.Name)

	// Wait for session to be pending
	_, err = requesterClient.WaitForSessionViaAPI(ctx, t, session.Name, namespace, telekomv1alpha1.SessionStatePending, helpers.WaitForStateTimeout)
	require.NoError(t, err, "Session did not reach Pending state")

	// Clear messages before approval
	clearMailHogMessages(t)

	// Approve session using approver client
	err = approverClient.ApproveSessionViaAPI(ctx, t, session.Name, namespace)
	require.NoError(t, err, "Failed to approve session")

	// Wait for approval notification email
	t.Run("ApprovalEmailSent", func(t *testing.T) {
		msg := waitForMailHogMessage(t, "approved", helpers.WaitForStateTimeout)
		if msg == nil {
			// Also try looking for "active" since approved sessions become active
			msg = waitForMailHogMessage(t, "active", 15*time.Second)
		}
		require.NotNil(t, msg, "Session approval should trigger a notification email - check MailProvider and controller configuration")

		t.Logf("Received approval notification email")
		assert.NotEmpty(t, msg.Content.Headers.Subject)
	})
}

// TestNotificationOnSessionRejection tests that notification is sent when a session is rejected
func TestNotificationOnSessionRejection(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())
	if !helpers.IsMailHogTestEnabled() {
		t.Skip("MailHog tests are disabled. Unset E2E_SKIP_MAILHOG_TESTS to run.")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()

	tc := helpers.NewTestContext(t, ctx)
	requesterClient := tc.ClientForUser(helpers.TestUsers.NotificationTestRequester)
	approverClient := tc.ClientForUser(helpers.TestUsers.NotificationTestApprover)
	cli := helpers.GetClient(t)
	cleanup := helpers.NewCleanup(t, cli)

	clusterName := helpers.GetTestClusterName()
	namespace := helpers.GetTestNamespace()
	uniqueID := fmt.Sprintf("notif-rej-%d", time.Now().UnixNano()%10000)

	// Create escalation using Kubernetes client
	escalationName := fmt.Sprintf("e2e-notif-rej-esc-%s", uniqueID)
	escalation := helpers.NewEscalationBuilder(escalationName, namespace).
		WithEscalatedGroup(fmt.Sprintf("escalated-notif-rejection-group-%s", uniqueID)).
		WithAllowedClusters(clusterName).
		WithAllowedGroups(helpers.TestUsers.NotificationTestRequester.Groups[0]).
		WithApproverUsers(helpers.TestUsers.NotificationTestApprover.Email).
		Build()

	err := cli.Create(ctx, escalation)
	require.NoError(t, err, "Failed to create escalation")
	cleanup.Add(escalation)

	// Create session via REST API
	sessionReq := helpers.SessionRequest{
		Cluster:  clusterName,
		User:     helpers.TestUsers.NotificationTestRequester.Email,
		Group:    escalation.Spec.EscalatedGroup,
		Reason:   "E2E notification rejection test",
		Duration: 1800, // 30 minutes
	}

	session, err := requesterClient.CreateSession(ctx, t, sessionReq)
	require.NoError(t, err, "Failed to create session")
	t.Logf("Created session: %s/%s", session.Namespace, session.Name)

	// Wait for session to be pending
	_, err = requesterClient.WaitForSessionViaAPI(ctx, t, session.Name, namespace, telekomv1alpha1.SessionStatePending, helpers.WaitForStateTimeout)
	require.NoError(t, err, "Session did not reach Pending state")

	// Clear messages before rejection
	clearMailHogMessages(t)

	// Reject session using approver client
	err = approverClient.RejectSessionViaAPI(ctx, t, session.Name, namespace, "Rejected for testing purposes")
	require.NoError(t, err, "Failed to reject session")

	// Wait for rejection notification email
	t.Run("RejectionEmailSent", func(t *testing.T) {
		msg := waitForMailHogMessage(t, "rejected", helpers.WaitForStateTimeout)
		require.NotNil(t, msg, "Session rejection should trigger a notification email - check MailProvider and controller configuration")

		t.Logf("Received rejection notification email")
		assert.NotEmpty(t, msg.Content.Headers.Subject)
	})
}

// TestMailProviderConfiguration tests that the MailProvider CR is correctly configured
func TestMailProviderConfiguration(t *testing.T) {
	_ = helpers.SetupTest(t, helpers.WithShortTimeout())

	ctx, cancel := context.WithTimeout(context.Background(), helpers.WaitForStateTimeout)
	defer cancel()

	cli := helpers.GetClient(t)

	t.Run("MailProviderExists", func(t *testing.T) {
		var providers telekomv1alpha1.MailProviderList
		err := cli.List(ctx, &providers)
		require.NoError(t, err, "Failed to list mail providers - check RBAC permissions")

		require.NotEmpty(t, providers.Items, "At least one MailProvider must be configured for email notifications to work")

		for _, provider := range providers.Items {
			t.Logf("Found MailProvider: %s (namespace: %s)", provider.Name, provider.Namespace)
			assert.NotEmpty(t, provider.Spec.SMTP.Host, "MailProvider should have SMTP host")
		}
	})
}
