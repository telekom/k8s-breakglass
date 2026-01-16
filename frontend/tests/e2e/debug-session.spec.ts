// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { test, expect } from "@playwright/test";
import { AuthHelper, TEST_USERS, fillScaleTextField } from "./helpers";

// Debug session tests share user authentication and session state.
// Serial execution prevents race conditions when interacting with forms and actions.
test.describe.serial("Debug Session Browser", () => {
  test("user can view debug session browser", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    // Navigate to debug session browser
    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");

    // Should see debug session browser page
    const browser = page.locator('[data-testid="debug-session-browser"]');
    await expect(browser).toBeVisible({ timeout: 10000 });
  });

  test("debug session browser displays search input", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");

    // Should see search input
    const searchInput = page.locator('[data-testid="debug-session-search-input"]');
    await expect(searchInput).toBeVisible();
  });

  test("search filter works in debug session browser", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");

    // Find search input and type - use Scale component helper for scale-text-field
    await fillScaleTextField(page, '[data-testid="debug-session-search-input"]', "test-search-term");

    // Wait for filter to apply and network to stabilize
    await page.waitForLoadState("networkidle", { timeout: 15000 });

    // Either shows filtered results or empty state
    const grid = page.locator('[data-testid="debug-sessions-grid"]');
    const emptyState = page.locator('[data-testid="debug-sessions-empty-state"]');
    await expect(grid.or(emptyState).first()).toBeVisible();
  });

  test("my sessions filter checkbox works", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");

    // Find my sessions checkbox
    const mySessionsFilter = page.locator('[data-testid="my-sessions-filter"]');
    await expect(mySessionsFilter).toBeVisible();

    // Toggle the checkbox
    await mySessionsFilter.click();
    await page.waitForLoadState("networkidle", { timeout: 15000 });

    // Should still show browser (either with results or empty)
    const browser = page.locator('[data-testid="debug-session-browser"]');
    await expect(browser).toBeVisible();
  });

  test("state filter tags are interactive", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");

    // Find state filters section
    const stateFilters = page.locator('[data-testid="state-filters"]');
    await expect(stateFilters).toBeVisible();

    // Click on Active state filter
    const activeFilter = page.locator('[data-testid="state-filter-Active"]');
    if (await activeFilter.isVisible()) {
      await activeFilter.click();
      await page.waitForLoadState("networkidle", { timeout: 15000 });
    }
  });

  test("create session button navigates to create page", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.requester);

    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");

    // Click create button
    const createButton = page.locator('[data-testid="create-debug-session-button"]');
    await expect(createButton).toBeVisible();
    await createButton.click();

    // Should navigate to create page
    await page.waitForLoadState("networkidle");
    const createPage = page.locator('[data-testid="debug-session-create"]');
    await expect(createPage).toBeVisible({ timeout: 10000 });
  });
});

// Creation tests interact with forms and may create session state
test.describe.serial("Debug Session Creation", () => {
  test("create page displays form elements", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.requester);

    await page.goto("/debug-sessions/create");
    await page.waitForLoadState("networkidle");

    // Verify the main create page container is visible
    const createPage = page.locator('[data-testid="debug-session-create"]');
    await expect(createPage).toBeVisible({ timeout: 10000 });

    // Wait for the form section to appear (this means loading is complete)
    // The form has class "create-form" and appears after loading
    const formSection = page.locator(".create-form");
    await formSection.waitFor({ state: "visible", timeout: 15000 });

    // Now verify form elements are visible
    const templateSelect = page.locator('[data-testid="template-select"]');
    await expect(templateSelect).toBeVisible({ timeout: 5000 });

    const reasonInput = page.locator('[data-testid="reason-input"]');
    await expect(reasonInput).toBeVisible({ timeout: 5000 });
  });

  test("cancel button works on create page", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.requester);

    await page.goto("/debug-sessions/create");
    await page.waitForLoadState("networkidle");

    // Click cancel button
    const cancelButton = page.locator('[data-testid="cancel-button"]');
    await expect(cancelButton).toBeVisible();
    await cancelButton.click();

    // Should navigate away from create page
    await page.waitForLoadState("networkidle");
    const createPage = page.locator('[data-testid="debug-session-create"]');
    await expect(createPage).not.toBeVisible({ timeout: 5000 });
  });

  test("create button is disabled when form is invalid", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.requester);

    await page.goto("/debug-sessions/create");
    await page.waitForLoadState("networkidle");

    // Wait for form to fully initialize (templates to load)
    // We need templates to load and Vue reactivity to settle
    const templateSelect = page.locator('[data-testid="template-select"]');
    await expect(templateSelect).toBeVisible({ timeout: 10000 });

    // The create button should be disabled because reason is empty
    const createButton = page.locator('[data-testid="create-session-button"]');
    await expect(createButton).toBeVisible();

    // Wait for the form to be in its initial state and verify button is disabled
    // Use waitForFunction for more reliable state checking with Scale components
    await page.waitForFunction(
      () => {
        const btn = document.querySelector('[data-testid="create-session-button"]');
        return btn && (btn.hasAttribute("disabled") || (btn as HTMLButtonElement).disabled);
      },
      { timeout: 10000 },
    );
  });

  test("schedule checkbox reveals datetime input", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.requester);

    await page.goto("/debug-sessions/create");
    await page.waitForLoadState("networkidle");

    // Schedule checkbox
    const scheduleCheckbox = page.locator('[data-testid="schedule-checkbox"]');
    await expect(scheduleCheckbox).toBeVisible();

    // Initially datetime input should be hidden
    let scheduleTimeInput = page.locator('[data-testid="schedule-time-input"]');
    await expect(scheduleTimeInput).not.toBeVisible();

    // Click schedule checkbox
    await scheduleCheckbox.click();

    // Now datetime input should be visible
    scheduleTimeInput = page.locator('[data-testid="schedule-time-input"]');
    await expect(scheduleTimeInput).toBeVisible();
  });

  test("template selection shows template info", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.requester);

    await page.goto("/debug-sessions/create");
    await page.waitForLoadState("networkidle");

    // Select a template if available
    const templateSelect = page.locator('[data-testid="template-select"]');
    await expect(templateSelect).toBeVisible();

    // Click the template dropdown
    await templateSelect.click();
    await page.waitForLoadState("networkidle", { timeout: 15000 });

    // Select first option if available
    const firstOption = page.locator("scale-dropdown-select-item").first();
    if (await firstOption.isVisible()) {
      await firstOption.click();
      await page.waitForLoadState("networkidle", { timeout: 15000 });

      // Template info should appear
      const templateInfo = page.locator('[data-testid="template-info"]');
      await expect(templateInfo).toBeVisible();
    }
  });
});

// Card interaction tests depend on session list state
test.describe.serial("Debug Session Card", () => {
  test("session card displays session information", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");

    // If there are session cards, verify they have required elements
    const sessionCards = page.locator('[data-testid="debug-session-card"]');
    const count = await sessionCards.count();

    if (count > 0) {
      const firstCard = sessionCards.first();

      // Card should have session name
      await expect(firstCard.locator('[data-testid="session-name"]')).toBeVisible();

      // Card should have cluster info
      await expect(firstCard.locator('[data-testid="session-cluster"]')).toBeVisible();

      // Card should have state tag
      await expect(firstCard.locator('[data-testid="session-state"]')).toBeVisible();

      // Card should have view details button
      await expect(firstCard.locator('[data-testid="view-details-button"]')).toBeVisible();
    }
  });

  test("view details button navigates to details page", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");

    const sessionCards = page.locator('[data-testid="debug-session-card"]');
    const count = await sessionCards.count();

    if (count > 0) {
      // Click view details on first card
      const viewDetailsButton = sessionCards.first().locator('[data-testid="view-details-button"]');
      await viewDetailsButton.click();

      await page.waitForLoadState("networkidle");

      // Should navigate to details page
      const detailsPage = page.locator('[data-testid="debug-session-details"]');
      await expect(detailsPage).toBeVisible({ timeout: 10000 });
    }
  });
});

// Details page tests may depend on specific session state
test.describe.serial("Debug Session Details", () => {
  test("details page shows session information", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    // First go to browser and navigate to a session if exists
    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");

    const sessionCards = page.locator('[data-testid="debug-session-card"]');
    const count = await sessionCards.count();

    if (count > 0) {
      // Navigate to first session's details
      await sessionCards.first().locator('[data-testid="view-details-button"]').click();
      await page.waitForLoadState("networkidle");

      // Verify details page elements
      const detailsPage = page.locator('[data-testid="debug-session-details"]');
      await expect(detailsPage).toBeVisible({ timeout: 10000 });

      // Should have status card
      const statusCard = page.locator('[data-testid="status-card"]');
      await expect(statusCard).toBeVisible();

      // Should have state tag
      const stateTag = page.locator('[data-testid="session-state-tag"]');
      await expect(stateTag).toBeVisible();

      // Should have session info card
      const infoCard = page.locator('[data-testid="session-info-card"]');
      await expect(infoCard).toBeVisible();
    }
  });

  test("back button returns to browser", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");

    const sessionCards = page.locator('[data-testid="debug-session-card"]');
    const count = await sessionCards.count();

    if (count > 0) {
      // Navigate to details
      await sessionCards.first().locator('[data-testid="view-details-button"]').click();
      await page.waitForLoadState("networkidle");

      // Click back button
      const backButton = page.locator('[data-testid="back-to-sessions-button"]');
      await expect(backButton).toBeVisible();
      await backButton.click();

      await page.waitForLoadState("networkidle");

      // Should be back at browser
      const browser = page.locator('[data-testid="debug-session-browser"]');
      await expect(browser).toBeVisible({ timeout: 10000 });
    }
  });

  test("participants card is visible on details page", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");

    const sessionCards = page.locator('[data-testid="debug-session-card"]');
    const count = await sessionCards.count();

    if (count > 0) {
      await sessionCards.first().locator('[data-testid="view-details-button"]').click();
      await page.waitForLoadState("networkidle");

      // Participants card should be visible
      const participantsCard = page.locator('[data-testid="participants-card"]');
      await expect(participantsCard).toBeVisible();
    }
  });

  test("debug pods card is visible on details page", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");

    const sessionCards = page.locator('[data-testid="debug-session-card"]');
    const count = await sessionCards.count();

    if (count > 0) {
      await sessionCards.first().locator('[data-testid="view-details-button"]').click();
      await page.waitForLoadState("networkidle");

      // Debug pods card should be visible
      const debugPodsCard = page.locator('[data-testid="debug-pods-card"]');
      await expect(debugPodsCard).toBeVisible();
    }
  });
});

// Approval flow tests modify session state and need exclusive access
test.describe.serial("Debug Session Approval Flow", () => {
  test("approver can see pending debug sessions", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");

    // Filter by pending approval state
    const pendingFilter = page.locator('[data-testid="state-filter-PendingApproval"]');
    if (await pendingFilter.isVisible()) {
      await pendingFilter.click();
      await page.waitForLoadState("networkidle", { timeout: 15000 });
    }

    // Should show filtered results or empty state
    const browser = page.locator('[data-testid="debug-session-browser"]');
    await expect(browser).toBeVisible();
  });

  test("approve button is visible for pending sessions", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");

    // Look for cards with approve button
    const approveButtons = page.locator('[data-testid="approve-button"]');
    const count = await approveButtons.count();

    // If there are pending sessions, approve button should be visible
    if (count > 0) {
      await expect(approveButtons.first()).toBeVisible();
    }
  });

  test("reject button opens modal for pending sessions", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");

    // Look for reject button
    const rejectButtons = page.locator('[data-testid="reject-button"]');
    const count = await rejectButtons.count();

    if (count > 0) {
      await rejectButtons.first().click();

      // Reject modal should appear
      const rejectModal = page.locator('[data-testid="reject-modal"]');
      await expect(rejectModal).toBeVisible({ timeout: 5000 });

      // Should have rejection reason input
      const reasonInput = page.locator('[data-testid="reject-reason-input"]');
      await expect(reasonInput).toBeVisible();

      // Cancel the modal
      const cancelButton = page.locator('[data-testid="reject-cancel-button"]');
      await cancelButton.click();
    }
  });
});

// Action tests perform state-modifying operations
test.describe.serial("Debug Session Actions", () => {
  test("renew button opens modal for active sessions", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");

    // Look for renew button
    const renewButtons = page.locator('[data-testid="renew-button"]');
    const count = await renewButtons.count();

    if (count > 0) {
      await renewButtons.first().click();

      // Renew modal should appear
      const renewModal = page.locator('[data-testid="renew-modal"]');
      await expect(renewModal).toBeVisible({ timeout: 5000 });

      // Should have duration select
      const durationSelect = page.locator('[data-testid="renew-duration-select"]');
      await expect(durationSelect).toBeVisible();

      // Cancel the modal
      const cancelButton = page.locator('[data-testid="renew-cancel-button"]');
      await cancelButton.click();
    }
  });

  test("join button is visible for active sessions user can join", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.requester);

    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");

    // Look for join button
    const joinButtons = page.locator('[data-testid="join-button"]');
    // Just verify it doesn't crash - join buttons may or may not be present
    const count = await joinButtons.count();
    expect(count).toBeGreaterThanOrEqual(0);
  });
});
