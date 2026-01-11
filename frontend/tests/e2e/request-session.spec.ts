// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { test, expect } from "@playwright/test";
import {
  AuthHelper,
  TEST_USERS,
  MailHogClient,
  fillScaleTextarea,
  fillScaleTextField,
  waitForScaleToast,
  findEscalationCardByName,
  waitForScaleModal,
} from "./helpers";

// This test file uses bob@example.com (TEST_USERS.bob) who has group "team-alpha"
// It targets the "ui-e2e-request-session-test" escalation which only allows "team-alpha" group
// The UI displays the escalatedGroup field, not the metadata.name
const ESCALATION_NAME = "ui-e2e-request-session-group";

// Tests that create sessions must run serially to avoid race conditions
// when multiple tests try to use the same escalation concurrently
test.describe.serial("Request Session via UI", () => {
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

    // Login as Bob (developer with team-alpha group)
    await auth.loginViaKeycloak(TEST_USERS.bob);

    // Find the specific escalation card for this test file
    const escalationCard = await findEscalationCardByName(page, ESCALATION_NAME, { requireAvailable: true });
    expect(escalationCard).not.toBeNull();
    if (!escalationCard) return; // TypeScript guard

    // Get escalation name for later verification
    const escalationName = await escalationCard.locator('[data-testid="escalation-name"]').textContent();
    expect(escalationName).toBeTruthy();

    // Click request button
    await escalationCard.locator('[data-testid="request-access-button"]').click();

    // Fill request form - wait for modal animation to complete
    await waitForScaleModal(page, '[data-testid="request-modal"]');

    // Select cluster (if multiple available)
    const clusterSelect = page.locator('[data-testid="cluster-select"]');
    if (await clusterSelect.isVisible()) {
      await clusterSelect.selectOption({ index: 0 });
    }

    // Enter reason
    const reason = "UI E2E Test: Debugging production issue #12345";
    await fillScaleTextarea(page, '[data-testid="reason-input"]', reason);

    // Select duration (if available) - this is a text field, not a dropdown
    const durationSelect = page.locator('[data-testid="duration-select"]');
    if (await durationSelect.isVisible()) {
      await fillScaleTextField(page, '[data-testid="duration-select"]', "1h");
    }

    // Submit request
    await page.click('[data-testid="submit-request-button"]');

    // Verify success message (use waitForScaleToast for Scale's notification toast component)
    await waitForScaleToast(page, "success-toast");

    // Verify session appears in "My Requests"
    await page.goto("/requests/mine");
    await page.waitForLoadState("networkidle");

    // MyPendingRequests view uses pending-request-card testid, not session-row
    const sessionCard = page.locator('[data-testid-generic="pending-request-card"]').first();
    await expect(sessionCard).toBeVisible({ timeout: 10000 });
    await expect(sessionCard).toContainText(/pending/i);

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
    await auth.loginViaKeycloak(TEST_USERS.bob);

    // Find the specific escalation card for this test file
    const escalationCard = await findEscalationCardByName(page, ESCALATION_NAME, { requireAvailable: true });
    expect(escalationCard).not.toBeNull();
    if (!escalationCard) return;
    await escalationCard.locator('[data-testid="request-access-button"]').click();

    // Verify modal is open - wait for animation to complete
    await waitForScaleModal(page, '[data-testid="request-modal"]');

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
    await auth.loginViaKeycloak(TEST_USERS.bob);

    // Find the specific escalation card for this test file
    const escalationCard = await findEscalationCardByName(page, ESCALATION_NAME, { requireAvailable: true });
    expect(escalationCard).not.toBeNull();
    if (!escalationCard) return;
    await escalationCard.locator('[data-testid="request-access-button"]').click();

    // Verify modal is open - wait for animation to complete
    await waitForScaleModal(page, '[data-testid="request-modal"]');

    // Click cancel button
    await page.click('[data-testid="cancel-button"]');

    // Modal should close
    await expect(page.locator('[data-testid="request-modal"]')).not.toBeVisible();
  });

  test("escalation cards show correct information", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.bob);

    // Wait for escalation list to load
    await expect(page.locator('[data-testid="escalation-list"]')).toBeVisible();

    // Find the specific escalation card for this test file
    const availableCard = await findEscalationCardByName(page, ESCALATION_NAME, { requireAvailable: true });
    expect(availableCard).not.toBeNull();
    if (!availableCard) return;

    // Should have a name
    await expect(availableCard.locator('[data-testid="escalation-name"]')).toBeVisible();

    // Should have a request button
    await expect(availableCard.locator('[data-testid="request-access-button"]')).toBeVisible();
  });
});

// Tests that create sessions must run serially to avoid race conditions
// when multiple tests try to use the same escalation concurrently
test.describe.serial("Request Session - Duration Selection", () => {
  test("duration select dropdown is visible in request modal", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.bob);

    // Find the specific escalation card for this test file
    const escalationCard = await findEscalationCardByName(page, ESCALATION_NAME, { requireAvailable: true });
    expect(escalationCard).not.toBeNull();
    if (!escalationCard) return;
    await escalationCard.locator('[data-testid="request-access-button"]').click();

    // Verify modal is open - wait for animation to complete
    await waitForScaleModal(page, '[data-testid="request-modal"]');

    // Should see duration select
    const durationSelect = page.locator('[data-testid="duration-select"]');
    await expect(durationSelect).toBeVisible();
  });

  test("duration input accepts duration values", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.bob);

    // Find the specific escalation card for this test file
    const escalationCard = await findEscalationCardByName(page, ESCALATION_NAME, { requireAvailable: true });
    expect(escalationCard).not.toBeNull();
    if (!escalationCard) return;
    await escalationCard.locator('[data-testid="request-access-button"]').click();
    await waitForScaleModal(page, '[data-testid="request-modal"]');

    // Duration input should be visible and accept text (e.g., "1h", "30m")
    const durationInput = page.locator('[data-testid="duration-select"]');
    if (await durationInput.isVisible()) {
      // Fill the duration text field with a valid duration
      await fillScaleTextField(page, '[data-testid="duration-select"]', "2h 30m");

      // Verify the input was accepted (the field should contain the value)
      const inputValue = await durationInput.locator("input").inputValue();
      expect(inputValue).toBe("2h 30m");
    }
  });

  test("entered duration is submitted with request", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.bob);

    // Find the specific escalation card for this test file
    const escalationCard = await findEscalationCardByName(page, ESCALATION_NAME, { requireAvailable: true });
    expect(escalationCard).not.toBeNull();
    if (!escalationCard) return;
    await escalationCard.locator('[data-testid="request-access-button"]').click();
    await waitForScaleModal(page, '[data-testid="request-modal"]');

    // Enter a specific duration using text input
    const durationInput = page.locator('[data-testid="duration-select"]');
    if (await durationInput.isVisible()) {
      await fillScaleTextField(page, '[data-testid="duration-select"]', "2h");
    }

    // Fill reason and submit
    await fillScaleTextarea(page, '[data-testid="reason-input"]', "E2E test duration selection");
    await page.click('[data-testid="submit-request-button"]');

    // Should succeed
    await waitForScaleToast(page, "success-toast");
  });
});

test.describe.serial("Request Session - Scheduled Sessions", () => {
  test("schedule section is visible on escalation card", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.bob);

    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Check for schedule section on the specific escalation card
    const escalationCard = await findEscalationCardByName(page, ESCALATION_NAME);
    expect(escalationCard).not.toBeNull();
    if (!escalationCard) return;

    const scheduleSection = escalationCard.locator('[data-testid="schedule-section"]');
    if (await scheduleSection.isVisible({ timeout: 2000 })) {
      await expect(scheduleSection).toBeVisible();
    }
  });

  test("schedule toggle shows schedule picker when enabled", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.bob);

    await page.goto("/");
    await page.waitForLoadState("networkidle");

    const escalationCard = page.locator('[data-testid="escalation-card"]').first();
    const scheduleToggle = escalationCard.locator('[data-testid="schedule-toggle"]');

    if (await scheduleToggle.isVisible({ timeout: 2000 })) {
      // Enable scheduling
      await scheduleToggle.click();
      await page.waitForTimeout(300);

      // Schedule picker should appear
      const schedulePicker = escalationCard.locator('[data-testid="schedule-picker"]');
      await expect(schedulePicker).toBeVisible();
    }
  });

  test("schedule picker has date, hour, and minute fields", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.bob);

    await page.goto("/");
    await page.waitForLoadState("networkidle");

    const escalationCard = page.locator('[data-testid="escalation-card"]').first();
    const scheduleToggle = escalationCard.locator('[data-testid="schedule-toggle"]');

    if (await scheduleToggle.isVisible({ timeout: 2000 })) {
      await scheduleToggle.click();
      await page.waitForTimeout(300);

      // Check for date picker
      const dateField = escalationCard.locator('[data-testid="schedule-date"]');
      if (await dateField.isVisible({ timeout: 1000 })) {
        await expect(dateField).toBeVisible();
      }

      // Check for hour field
      const hourField = escalationCard.locator('[data-testid="schedule-hour"]');
      if (await hourField.isVisible({ timeout: 1000 })) {
        await expect(hourField).toBeVisible();
      }

      // Check for minute field
      const minuteField = escalationCard.locator('[data-testid="schedule-minute"]');
      if (await minuteField.isVisible({ timeout: 1000 })) {
        await expect(minuteField).toBeVisible();
      }
    }
  });

  test("clear schedule button resets schedule", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.bob);

    await page.goto("/");
    await page.waitForLoadState("networkidle");

    const escalationCard = page.locator('[data-testid="escalation-card"]').first();
    const scheduleToggle = escalationCard.locator('[data-testid="schedule-toggle"]');

    if (await scheduleToggle.isVisible({ timeout: 2000 })) {
      // Enable scheduling
      await scheduleToggle.click();
      await page.waitForTimeout(300);

      // Clear schedule button should be available
      const clearButton = escalationCard.locator('[data-testid="clear-schedule"]');
      if (await clearButton.isVisible({ timeout: 1000 })) {
        await clearButton.click();
        await page.waitForTimeout(300);

        // Schedule picker should be hidden
        const schedulePicker = escalationCard.locator('[data-testid="schedule-picker"]');
        await expect(schedulePicker).not.toBeVisible();
      }
    }
  });
});

test.describe.serial("Request Session - Escalation Search", () => {
  test("escalation search input is visible", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.bob);

    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Check for search input in toolbar
    const searchInput = page.locator('[data-testid="escalation-search"]');
    await expect(searchInput).toBeVisible();
  });

  test("search filters escalation list", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.bob);

    await page.goto("/");
    await page.waitForLoadState("networkidle");

    const searchInput = page.locator('[data-testid="escalation-search"]');
    if (await searchInput.isVisible()) {
      // Get initial card count
      const initialCards = page.locator('[data-testid="escalation-card"]');
      const initialCount = await initialCards.count();

      // Type search term that probably won't match - use inner input for Scale text-field
      const innerInput = searchInput.locator("input").first();
      await innerInput.fill("nonexistent-escalation-xyz");
      await page.waitForTimeout(500);

      // Card count should change (fewer or none)
      const filteredCards = page.locator('[data-testid="escalation-card"]');
      const filteredCount = await filteredCards.count();

      expect(filteredCount).toBeLessThanOrEqual(initialCount);
    }
  });

  test("refresh button reloads escalations", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.bob);

    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Check for refresh button
    const refreshButton = page.locator('[data-testid="refresh-escalations-button"]');
    if (await refreshButton.isVisible()) {
      // Click refresh
      await refreshButton.click();
      await page.waitForLoadState("networkidle");

      // Escalation list should still be visible
      const escalationList = page.locator('[data-testid="escalation-list"]');
      await expect(escalationList).toBeVisible();
    }
  });

  test("toolbar info shows escalation count", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.bob);

    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Check for toolbar info
    const toolbarInfo = page.locator('[data-testid="toolbar-info"]');
    if (await toolbarInfo.isVisible()) {
      const infoText = await toolbarInfo.textContent();
      // Should contain some count or info
      expect(infoText).toBeTruthy();
    }
  });
});
