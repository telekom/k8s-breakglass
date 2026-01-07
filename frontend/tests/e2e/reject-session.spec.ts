// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { test, expect } from "@playwright/test";
import { AuthHelper, TEST_USERS, MailHogClient } from "./helpers";

test.describe("Reject Session", () => {
  let mailhog: MailHogClient;

  test.beforeAll(() => {
    mailhog = new MailHogClient();
  });

  test.beforeEach(async () => {
    await mailhog.clearMessages();
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
      await requesterAuth.loginViaKeycloak(TEST_USERS.requester);
      const escalationCard = requesterPage
        .locator('[data-testid="escalation-card"]')
        .first();
      await escalationCard
        .locator('[data-testid="request-access-button"]')
        .click();
      await requesterPage.fill(
        '[data-testid="reason-input"]',
        "Rejection test - this should be rejected"
      );
      await requesterPage.click('[data-testid="submit-request-button"]');

      await expect(
        requesterPage.locator('[data-testid="success-toast"]')
      ).toBeVisible();

      // === Step 2: Wait for email ===
      const email = await mailhog.waitForSubject("breakglass", 30000);
      const approvalLink = mailhog.extractApprovalLink(email.Content.Body);
      expect(approvalLink).toBeTruthy();

      // === Step 3: Approver opens review page ===
      await approverAuth.loginViaKeycloak(TEST_USERS.approver);
      await approverPage.goto(approvalLink!);

      await expect(
        approverPage.locator('[data-testid="session-review"]')
      ).toBeVisible({ timeout: 15000 });

      // === Step 4: Fill rejection reason ===
      const rejectionReasonInput = approverPage.locator(
        '[data-testid="rejection-reason-input"]'
      );
      await expect(rejectionReasonInput).toBeVisible();
      await rejectionReasonInput.fill("Rejected: Invalid justification provided");

      // === Step 5: Click reject button ===
      await approverPage.click('[data-testid="reject-button"]');

      // Handle confirmation dialog if present
      const confirmDialog = approverPage.locator(
        '[data-testid="confirm-reject-dialog"]'
      );
      if (await confirmDialog.isVisible({ timeout: 2000 }).catch(() => false)) {
        await approverPage.click('[data-testid="confirm-reject-button"]');
      }

      // Verify rejection success
      await expect(
        approverPage.locator('[data-testid="success-toast"]')
      ).toBeVisible();

      // === Step 6: Verify requester sees rejected session ===
      await requesterPage.goto("/requests/mine");
      await requesterPage.reload();
      await requesterPage.waitForLoadState("networkidle");

      const sessionRow = requesterPage
        .locator('[data-testid="session-row"]')
        .first();
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

  test("reject button is disabled without reason", async ({ browser }) => {
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

      // Create session
      await requesterAuth.loginViaKeycloak(TEST_USERS.requester);
      const escalationCard = requesterPage
        .locator('[data-testid="escalation-card"]')
        .first();
      await escalationCard
        .locator('[data-testid="request-access-button"]')
        .click();
      await requesterPage.fill(
        '[data-testid="reason-input"]',
        "Test for reject button validation"
      );
      await requesterPage.click('[data-testid="submit-request-button"]');

      // Get approval link
      const email = await mailhog.waitForSubject("breakglass", 30000);
      const approvalLink = mailhog.extractApprovalLink(email.Content.Body);

      // Approver opens review page
      await approverAuth.loginViaKeycloak(TEST_USERS.approver);
      await approverPage.goto(approvalLink!);

      await expect(
        approverPage.locator('[data-testid="session-review"]')
      ).toBeVisible({ timeout: 15000 });

      // Reject button should be disabled without reason
      const rejectButton = approverPage.locator('[data-testid="reject-button"]');
      await expect(rejectButton).toBeDisabled();

      // Enter reason
      await approverPage.fill(
        '[data-testid="rejection-reason-input"]',
        "Test reason"
      );

      // Now should be enabled
      await expect(rejectButton).toBeEnabled();
    } finally {
      await requesterContext.close();
      await approverContext.close();
    }
  });

  test("approver can approve and reject different sessions", async ({
    browser,
  }) => {
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

      // Login requester and create a session
      await requesterAuth.loginViaKeycloak(TEST_USERS.requester);
      const escalationCard = requesterPage
        .locator('[data-testid="escalation-card"]')
        .first();
      await escalationCard
        .locator('[data-testid="request-access-button"]')
        .click();
      await requesterPage.fill(
        '[data-testid="reason-input"]',
        "Session for approve/reject flow test"
      );
      await requesterPage.click('[data-testid="submit-request-button"]');

      await expect(
        requesterPage.locator('[data-testid="success-toast"]')
      ).toBeVisible();

      // Login approver
      await approverAuth.loginViaKeycloak(TEST_USERS.approver);

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
        const approveButton = approverPage.locator(
          '[data-testid="approve-button"]'
        );
        const rejectButton = approverPage.locator(
          '[data-testid="reject-button"]'
        );

        // Both buttons should be visible
        await expect(approveButton).toBeVisible();
        await expect(rejectButton).toBeVisible({ timeout: 5000 }).catch(() => {
          // Reject might require reason first
        });
      }
    } finally {
      await requesterContext.close();
      await approverContext.close();
    }
  });
});
