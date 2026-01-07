// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { test, expect } from "@playwright/test";
import { AuthHelper, TEST_USERS, MailHogClient } from "./helpers";

test.describe("Request Session via UI", () => {
  let mailhog: MailHogClient;

  test.beforeAll(() => {
    mailhog = new MailHogClient();
  });

  test.beforeEach(async () => {
    // Clear any existing emails before each test
    await mailhog.clearMessages();
  });

  test("developer can request escalation and approver receives email", async ({ page }) => {
    const auth = new AuthHelper(page);

    // Login as Bob (developer)
    await auth.loginViaKeycloak(TEST_USERS.requester);

    // Find an escalation card and click "Request Access"
    const escalationCard = page.locator('[data-testid="escalation-card"]').first();
    await expect(escalationCard).toBeVisible();

    // Get escalation name for later verification
    const escalationName = await escalationCard.locator('[data-testid="escalation-name"]').textContent();
    expect(escalationName).toBeTruthy();

    // Click request button
    await escalationCard.locator('[data-testid="request-access-button"]').click();

    // Fill request form
    await expect(page.locator('[data-testid="request-modal"]')).toBeVisible();

    // Select cluster (if multiple available)
    const clusterSelect = page.locator('[data-testid="cluster-select"]');
    if (await clusterSelect.isVisible()) {
      await clusterSelect.selectOption({ index: 0 });
    }

    // Enter reason
    const reason = "UI E2E Test: Debugging production issue #12345";
    await page.fill('[data-testid="reason-input"]', reason);

    // Select duration (if available)
    const durationSelect = page.locator('[data-testid="duration-select"]');
    if (await durationSelect.isVisible()) {
      await durationSelect.selectOption("1h");
    }

    // Submit request
    await page.click('[data-testid="submit-request-button"]');

    // Verify success message
    await expect(page.locator('[data-testid="success-toast"]')).toBeVisible();

    // Verify session appears in "My Requests"
    await page.goto("/requests/mine");
    await page.waitForLoadState("networkidle");

    const sessionRow = page.locator('[data-testid="session-row"]').first();
    await expect(sessionRow).toBeVisible();
    await expect(sessionRow).toContainText(/pending/i);

    // Wait for and verify email to approver
    const email = await mailhog.waitForSubject("breakglass", 30000);
    expect(email).toBeTruthy();

    // Verify email contains requester info
    const emailBody = mailhog.getPlainTextBody(email);
    expect(emailBody.toLowerCase()).toContain("bob");
    expect(emailBody).toContain(reason.substring(0, 20)); // At least part of the reason

    // Verify approval link exists in email
    const approvalLink = mailhog.extractApprovalLink(email.Content.Body);
    expect(approvalLink).toBeTruthy();
  });

  test("reason validation prevents empty submission", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.requester);

    // Start request flow
    const escalationCard = page.locator('[data-testid="escalation-card"]').first();
    await expect(escalationCard).toBeVisible();
    await escalationCard.locator('[data-testid="request-access-button"]').click();

    // Verify modal is open
    await expect(page.locator('[data-testid="request-modal"]')).toBeVisible();

    // Try to submit without reason
    await page.click('[data-testid="submit-request-button"]');

    // Should show validation error
    const reasonError = page.locator('[data-testid="reason-error"]');
    await expect(reasonError).toBeVisible();
    await expect(reasonError).toContainText(/required/i);

    // Modal should still be open
    await expect(page.locator('[data-testid="request-modal"]')).toBeVisible();
  });

  test("user can cancel request", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.requester);

    // Start request flow
    const escalationCard = page.locator('[data-testid="escalation-card"]').first();
    await escalationCard.locator('[data-testid="request-access-button"]').click();

    // Verify modal is open
    await expect(page.locator('[data-testid="request-modal"]')).toBeVisible();

    // Click cancel button
    await page.click('[data-testid="cancel-button"]');

    // Modal should close
    await expect(page.locator('[data-testid="request-modal"]')).not.toBeVisible();
  });

  test("escalation cards show correct information", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.requester);

    // Wait for escalation list to load
    await expect(page.locator('[data-testid="escalation-list"]')).toBeVisible();

    // Check that escalation cards have required elements
    const firstCard = page.locator('[data-testid="escalation-card"]').first();
    await expect(firstCard).toBeVisible();

    // Should have a name
    await expect(firstCard.locator('[data-testid="escalation-name"]')).toBeVisible();

    // Should have a request button
    await expect(firstCard.locator('[data-testid="request-access-button"]')).toBeVisible();
  });
});
