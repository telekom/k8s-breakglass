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
} from "./helpers";

// This test file uses dev-user-alpha (TEST_USERS.devAlpha) who has group "frontend-team"
// It targets the "ui-e2e-approve-email-test" escalation which only allows "frontend-team" group
// The UI displays the escalatedGroup field, not the metadata.name
const ESCALATION_NAME = "ui-e2e-approve-email-group";

// Tests that create sessions must run serially to avoid race conditions
// when multiple tests try to use the same escalation concurrently
test.describe.serial("Approve Session via Email Link", () => {
  let mailhog: MailHogClient;

  test.beforeAll(() => {
    mailhog = new MailHogClient();
  });

  test.beforeEach(async () => {
    await mailhog.clearMessages();
  });

  test("approver can approve session by clicking email link", async ({ browser }) => {
    // Create two browser contexts: requester and approver
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
      // Use dev-user-alpha who has frontend-team group (isolated from other tests)
      await requesterAuth.loginViaKeycloak(TEST_USERS.devAlpha);

      // Find the specific escalation card for this test file
      const escalationCard = await findEscalationCardByName(requesterPage, ESCALATION_NAME, { requireAvailable: true });
      expect(escalationCard).not.toBeNull();
      if (!escalationCard) return;
      await escalationCard.locator('[data-testid="request-access-button"]').click();

      await fillScaleTextarea(
        requesterPage,
        '[data-testid="reason-input"]',
        "Email approval test - please approve via link",
      );
      await requesterPage.click('[data-testid="submit-request-button"]');

      // Verify success message (use waitForScaleToast for Scale's notification toast component)
      await waitForScaleToast(requesterPage, "success-toast");

      // === Step 2: Wait for email ===
      const email = await mailhog.waitForSubject("breakglass", 30000);
      expect(email).toBeTruthy();

      // Extract approval link
      const approvalLink = mailhog.extractApprovalLink(email.Content.Body);
      expect(approvalLink).toBeTruthy();

      // === Step 3: Approver logs in and clicks email link ===
      await approverAuth.loginViaKeycloak(TEST_USERS.approver);

      // Navigate to approval link
      await approverPage.goto(approvalLink!);

      // Should see session review page
      await expect(approverPage.locator('[data-testid="session-review"]')).toBeVisible({ timeout: 15000 });

      // Verify session details - requester is dev-user-alpha
      await expect(approverPage.locator('[data-testid="requester"]')).toContainText("dev-user-alpha");
      await expect(approverPage.locator('[data-testid="request-reason"]')).toContainText("Email approval test");

      // Approve the session
      const approvalReasonInput = approverPage.locator('[data-testid="approval-reason-input"]');
      if (await approvalReasonInput.isVisible()) {
        await approvalReasonInput.fill("Approved via email link - E2E test");
      }
      await approverPage.click('[data-testid="approve-button"]');

      // Verify approval success (use waitForScaleToast for Scale's notification toast component)
      await waitForScaleToast(approverPage, "success-toast");

      // === Step 4: Verify requester sees approved session ===
      await requesterPage.goto("/requests/mine");
      await requesterPage.reload();
      await requesterPage.waitForLoadState("networkidle");

      const sessionRow = requesterPage.locator('[data-testid="session-row"]').first();
      await expect(sessionRow).toContainText(/active|approved/i);

      // === Step 5: Verify approval email sent to requester ===
      const approvalEmail = await mailhog.waitForSubject("approved", 15000);
      expect(approvalEmail).toBeTruthy();

      const approvalBody = mailhog.getPlainTextBody(approvalEmail);
      expect(approvalBody.toLowerCase()).toContain("carol"); // Approver
    } finally {
      await requesterContext.close();
      await approverContext.close();
    }
  });

  test("approval link without login redirects to Keycloak then back", async ({ browser }) => {
    // First create a session with logged in user
    const requesterContext = await browser.newContext({
      ignoreHTTPSErrors: true,
    });
    const requesterPage = await requesterContext.newPage();
    const requesterAuth = new AuthHelper(requesterPage);

    try {
      // Use dev-user-alpha who has frontend-team group (isolated from other tests)
      await requesterAuth.loginViaKeycloak(TEST_USERS.devAlpha);

      // Find the specific escalation card for this test file
      const escalationCard = await findEscalationCardByName(requesterPage, ESCALATION_NAME, { requireAvailable: true });
      expect(escalationCard).not.toBeNull();
      if (!escalationCard) return;
      await escalationCard.locator('[data-testid="request-access-button"]').click();
      await fillScaleTextarea(requesterPage, '[data-testid="reason-input"]', "Deep link test");
      await requesterPage.click('[data-testid="submit-request-button"]');

      // Wait for email
      const email = await mailhog.waitForSubject("breakglass", 30000);
      const approvalLink = mailhog.extractApprovalLink(email.Content.Body);
      expect(approvalLink).toBeTruthy();

      // Open new context (not logged in)
      const newContext = await browser.newContext({ ignoreHTTPSErrors: true });
      const newPage = await newContext.newPage();

      try {
        // Navigate to approval link
        await newPage.goto(approvalLink!);

        // Should redirect to Keycloak
        await expect(newPage).toHaveURL(/keycloak|auth/, { timeout: 15000 });

        // Login as approver
        await newPage.fill("#username", TEST_USERS.approver.username);
        await newPage.fill("#password", TEST_USERS.approver.password);
        await newPage.click("#kc-login");

        // Should redirect back to session review (deep link preserved)
        await newPage.waitForURL(/session|review/, { timeout: 30000 });
        await expect(newPage.locator('[data-testid="session-review"]')).toBeVisible({ timeout: 15000 });
      } finally {
        await newContext.close();
      }
    } finally {
      await requesterContext.close();
    }
  });

  test("non-approver cannot approve session", async ({ browser }) => {
    // Create session with requester
    const requesterContext = await browser.newContext({
      ignoreHTTPSErrors: true,
    });
    const requesterPage = await requesterContext.newPage();
    const requesterAuth = new AuthHelper(requesterPage);

    try {
      // Use dev-user-alpha who has frontend-team group (isolated from other tests)
      await requesterAuth.loginViaKeycloak(TEST_USERS.devAlpha);

      // Find the specific escalation card for this test file
      const escalationCard = await findEscalationCardByName(requesterPage, ESCALATION_NAME, { requireAvailable: true });
      expect(escalationCard).not.toBeNull();
      if (!escalationCard) return;
      await escalationCard.locator('[data-testid="request-access-button"]').click();
      await fillScaleTextarea(requesterPage, '[data-testid="reason-input"]', "Non-approver test");
      await requesterPage.click('[data-testid="submit-request-button"]');

      const email = await mailhog.waitForSubject("breakglass", 30000);
      const approvalLink = mailhog.extractApprovalLink(email.Content.Body);

      // Try to access with requester (not an approver for own request)
      await requesterPage.goto(approvalLink!);

      // Should either show error or not show approve button
      const approveButton = requesterPage.locator('[data-testid="approve-button"]');
      const errorMessage = requesterPage.locator('[data-testid="error-message"]');

      // Either approve button is not visible, or error is shown
      const canApprove = await approveButton.isVisible().catch(() => false);
      const hasError = await errorMessage.isVisible().catch(() => false);

      // At least one of these should be true for proper access control
      expect(canApprove === false || hasError).toBe(true);
    } finally {
      await requesterContext.close();
    }
  });
});
