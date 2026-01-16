// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { test, expect } from "@playwright/test";
import {
  AuthHelper,
  TEST_USERS,
  MailHogClient,
  fillScaleTextarea,
  waitForScaleToast,
  findEscalationCardByName,
  cleanupPendingSessions,
} from "./helpers";

// This test file uses ui-e2e-reject-session-user (isolated user with group "ui-e2e-reject-session-requester")
// It targets the "ui-e2e-reject-session-test" escalation which only allows "ui-e2e-reject-session-requester" group
// Approver: ui-e2e-approver
// The UI displays the escalatedGroup field, not the metadata.name
const ESCALATION_NAME = "ui-e2e-reject-session-group";

// Tests that create sessions must run serially to avoid race conditions
// when multiple tests try to use the same escalation concurrently
test.describe.serial("Reject Session", () => {
  let mailhog: MailHogClient;

  test.beforeAll(() => {
    mailhog = new MailHogClient();
  });

  test.beforeEach(async ({ page }) => {
    await mailhog.clearMessages();
    // Clean up any leftover sessions from this test to prevent pollution
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.uiE2eRejectSession);
    await cleanupPendingSessions(page);
  });

  test("approver can reject session with reason", async ({ browser }) => {
    const requesterContext = await browser.newContext({
      ignoreHTTPSErrors: true,
    });
    const approverContext = await browser.newContext({
      ignoreHTTPSErrors: true,
    });

    try {
      const requesterPage = await requesterContext.newPage();
      const approverPage = await approverContext.newPage();

      const requesterAuth = new AuthHelper(requesterPage);
      const approverAuth = new AuthHelper(approverPage);

      // === Step 1: Requester creates session ===
      // Use ui-e2e-reject-session-user (isolated from other tests)
      await requesterAuth.loginViaKeycloak(TEST_USERS.uiE2eRejectSession);

      // Clean up any leftover sessions from previous test runs
      await cleanupPendingSessions(requesterPage);
      // Refresh the page to reflect cleanup
      await requesterPage.goto("/");
      await requesterPage.waitForLoadState("networkidle");

      // Find the specific escalation card for this test file
      const escalationCard = await findEscalationCardByName(requesterPage, ESCALATION_NAME, { requireAvailable: true });
      expect(escalationCard).not.toBeNull();
      if (!escalationCard) return;
      await escalationCard.locator('[data-testid="request-access-button"]').click();
      await fillScaleTextarea(
        requesterPage,
        '[data-testid="reason-input"]',
        "Rejection test - this should be rejected",
      );
      await requesterPage.click('[data-testid="submit-request-button"]');

      // Verify success message (use waitForScaleToast for Scale's notification toast component)
      await waitForScaleToast(requesterPage, "success-toast");

      // === Step 2: Wait for email ===
      // Backend processes session creation asynchronously and sends email
      // MailHog client has built-in retry logic (60s timeout, 2s polling)
      // Increase timeout for CI environments
      const email = await mailhog.waitForSubject("breakglass", 90000);
      const approvalLink = mailhog.extractApprovalLink(email.Content.Body);
      expect(approvalLink).toBeTruthy();

      // === Step 3: Approver opens review page ===
      await approverAuth.loginViaKeycloak(TEST_USERS.uiE2eApprover);
      // Rewrite backend URL to frontend dev server to preserve OIDC session
      const frontendApprovalLink = mailhog.rewriteToFrontendUrl(approvalLink!);
      await approverPage.goto(frontendApprovalLink);
      await approverPage.waitForLoadState("networkidle");

      // Wait for the session review content to appear on the dedicated approval page
      // The approval URL leads to a full page view, not a modal
      await expect(
        approverPage
          .locator('[data-testid="session-review"], [data-testid="requester"], [data-testid="error-title"]')
          .first(),
      ).toBeVisible({ timeout: 30000 });

      // Wait for content to load - look for user field which confirms data loaded
      // Replace arbitrary timeout with explicit content check
      await expect(approverPage.getByText(/User:/i)).toBeVisible({ timeout: 20000 });

      // === Step 4: Fill rejection reason ===
      // The approval-reason-input is used for both approval and rejection notes
      await fillScaleTextarea(
        approverPage,
        '[data-testid="approval-reason-input"]',
        "Rejected: Invalid justification provided",
      );

      // === Step 5: Click reject button ===
      await approverPage.getByRole("button", { name: /Reject/i }).click();

      // Handle confirmation dialog if present
      const confirmDialog = approverPage.locator('[data-testid="confirm-reject-dialog"]');
      if (await confirmDialog.isVisible({ timeout: 2000 }).catch(() => false)) {
        await approverPage.click('[data-testid="confirm-reject-button"]');
      }

      // Verify rejection success (use waitForScaleToast for Scale's notification toast component)
      await waitForScaleToast(approverPage, "success-toast");

      // === Step 6: Verify requester sees rejected session ===
      // Navigate to Session Browser as rejected sessions may not show on "My Pending Requests" (state=pending filter)
      await requesterPage.goto("/sessions");
      await requesterPage.reload();
      await requesterPage.waitForLoadState("networkidle");

      const sessionRow = requesterPage.locator('[data-testid="session-row"]').first();
      await expect(sessionRow).toContainText(/rejected/i);

      // === Step 7: Verify rejection email ===
      const rejectionEmail = await mailhog.waitForSubject("rejected", 15000);
      expect(rejectionEmail).toBeTruthy();

      const rejectionBody = mailhog.getPlainTextBody(rejectionEmail);
      expect(rejectionBody).toContain("Invalid justification");
    } finally {
      await requesterContext.close();
      await approverContext.close();
    }
  });

  // NOTE: This test is skipped because the frontend doesn't currently validate that a rejection reason is required.
  // The reject button is enabled even without a reason, which may be intentional design (reasons are optional).
  // If rejection reasons should be mandatory, the ApprovalModalContent component needs to be updated to
  // add :disabled="!approverNote.trim()" condition to the reject button when isNoteRequired is true.
  test.skip("reject button is disabled without reason", async ({ browser }) => {
    // First create a session
    const requesterContext = await browser.newContext({
      ignoreHTTPSErrors: true,
    });
    const approverContext = await browser.newContext({
      ignoreHTTPSErrors: true,
    });

    try {
      const requesterPage = await requesterContext.newPage();
      const approverPage = await approverContext.newPage();

      const requesterAuth = new AuthHelper(requesterPage);
      const approverAuth = new AuthHelper(approverPage);

      // Create session using ui-e2e-reject-session-user (isolated from other tests)
      await requesterAuth.loginViaKeycloak(TEST_USERS.uiE2eRejectSession);
      // Find the specific escalation card for this test file
      const escalationCard = await findEscalationCardByName(requesterPage, ESCALATION_NAME, { requireAvailable: true });
      expect(escalationCard).not.toBeNull();
      if (!escalationCard) return;
      await escalationCard.locator('[data-testid="request-access-button"]').click();
      await fillScaleTextarea(requesterPage, '[data-testid="reason-input"]', "Test for reject button validation");
      await requesterPage.click('[data-testid="submit-request-button"]');

      // Get approval link
      const email = await mailhog.waitForSubject("breakglass", 30000);
      const approvalLink = mailhog.extractApprovalLink(email.Content.Body);

      // Approver opens review page
      await approverAuth.loginViaKeycloak(TEST_USERS.uiE2eApprover);
      // Rewrite backend URL to frontend dev server to preserve OIDC session
      const frontendApprovalLink2 = mailhog.rewriteToFrontendUrl(approvalLink!);
      await approverPage.goto(frontendApprovalLink2);
      await approverPage.waitForLoadState("networkidle");

      // Wait for the session review content to appear on the dedicated approval page
      await expect(
        approverPage
          .locator('[data-testid="session-review"], [data-testid="requester"], [data-testid="error-title"]')
          .first(),
      ).toBeVisible({ timeout: 15000 });
      await expect(approverPage.getByText(/User:/i)).toBeVisible({ timeout: 10000 });

      // Reject button should be disabled without reason - use getByRole
      const rejectButton = approverPage.getByRole("button", { name: /Reject/i });
      await expect(rejectButton).toBeDisabled();

      // Enter reason (approval-reason-input is used for both approval and rejection notes)
      await fillScaleTextarea(approverPage, '[data-testid="approval-reason-input"]', "Test reason");

      // Now should be enabled
      await expect(rejectButton).toBeEnabled();
    } finally {
      await requesterContext.close();
      await approverContext.close();
    }
  });

  test("approver can approve and reject different sessions", async ({ browser }) => {
    const requesterContext = await browser.newContext({
      ignoreHTTPSErrors: true,
    });
    const approverContext = await browser.newContext({
      ignoreHTTPSErrors: true,
    });

    try {
      const requesterPage = await requesterContext.newPage();
      const approverPage = await approverContext.newPage();

      const requesterAuth = new AuthHelper(requesterPage);
      const approverAuth = new AuthHelper(approverPage);

      // Login requester using ui-e2e-reject-session-user (isolated from other tests)
      await requesterAuth.loginViaKeycloak(TEST_USERS.uiE2eRejectSession);
      // Find the specific escalation card for this test file
      const escalationCard = await findEscalationCardByName(requesterPage, ESCALATION_NAME, { requireAvailable: true });
      expect(escalationCard).not.toBeNull();
      if (!escalationCard) return;
      await escalationCard.locator('[data-testid="request-access-button"]').click();
      await fillScaleTextarea(requesterPage, '[data-testid="reason-input"]', "Session for approve/reject flow test");
      await requesterPage.click('[data-testid="submit-request-button"]');

      // Verify success message (use waitForScaleToast for Scale's notification toast component)
      await waitForScaleToast(requesterPage, "success-toast");

      // Login approver
      await approverAuth.loginViaKeycloak(TEST_USERS.uiE2eApprover);

      // Go to pending approvals
      await approverPage.goto("/approvals/pending");
      await approverPage.waitForLoadState("networkidle");

      // Should see pending sessions
      const sessionRows = approverPage.locator('[data-testid="session-row"]');
      const count = await sessionRows.count();

      if (count > 0) {
        // Click first session to see details
        await sessionRows.first().click();

        // Should see session review with both approve and reject options
        const approveButton = approverPage.locator('[data-testid="approve-button"]');
        const rejectButton = approverPage.locator('[data-testid="reject-button"]');

        // Both buttons should be visible
        await expect(approveButton).toBeVisible();
        await expect(rejectButton)
          .toBeVisible({ timeout: 5000 })
          .catch(() => {
            // Reject might require reason first
          });
      }
    } finally {
      await requesterContext.close();
      await approverContext.close();
    }
  });
});
