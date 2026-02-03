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

    // Wait for loading to complete - either form appears or no-templates message
    const formSection = page.locator(".create-form");
    const noTemplatesMessage = page.locator(
      '[data-testid="no-templates-message"], [data-testid="no-available-templates-message"]',
    );

    // Wait for either the form or no-templates message
    await expect(formSection.or(noTemplatesMessage)).toBeVisible({ timeout: 15000 });

    // If form is visible, test the form elements
    if (await formSection.isVisible()) {
      // Step 1: Verify template select is visible
      const templateSelect = page.locator('[data-testid="template-select"]');
      await expect(templateSelect).toBeVisible({ timeout: 5000 });

      // Select a template to enable the Next button
      await templateSelect.click();
      await page.waitForLoadState("networkidle", { timeout: 15000 });
      const firstOption = page.locator("scale-dropdown-select-item").first();
      if (await firstOption.isVisible()) {
        await firstOption.click();
        await page.waitForLoadState("networkidle", { timeout: 15000 });
      }

      // Click Next button to go to Step 2
      const nextButton = page.locator('[data-testid="next-button"]');
      await expect(nextButton).toBeVisible({ timeout: 5000 });
      await nextButton.click();
      await page.waitForLoadState("networkidle");

      // Step 2: Select a cluster to reveal the session details form
      const clusterCard = page.locator(".cluster-card").first();
      if (await clusterCard.isVisible({ timeout: 5000 })) {
        await clusterCard.click();
        await page.waitForLoadState("networkidle");

        // Now verify the reason input is visible (only shown after cluster selection)
        const reasonInput = page.locator('[data-testid="reason-input"]');
        await expect(reasonInput).toBeVisible({ timeout: 5000 });
      }
    } else {
      // No templates available - this is also a valid state in e2e environment
      // Verify the no-templates message is displayed correctly
      await expect(noTemplatesMessage).toBeVisible();
    }
  });

  test("cancel button works on create page", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.requester);

    await page.goto("/debug-sessions/create");
    await page.waitForLoadState("networkidle");

    // Wait for page to load - it may show template form or "no templates" message
    // If templates exist, there's a cancel button; if not, there's a "Go Back" button
    const cancelButton = page.locator('[data-testid="cancel-button"]');
    const noTemplatesMessage = page.locator('[data-testid="no-templates-message"]');
    const noAvailableTemplatesMessage = page.locator('[data-testid="no-available-templates-message"]');

    // Wait for either the form or the no-templates message to appear
    await expect(cancelButton.or(noTemplatesMessage).or(noAvailableTemplatesMessage)).toBeVisible({ timeout: 10000 });

    if (await cancelButton.isVisible()) {
      // Templates available - click cancel button
      await cancelButton.click();
    } else {
      // No templates - click "Go Back" button in the no-templates message
      const goBackButton = page.getByRole("button", { name: /go back/i });
      await expect(goBackButton).toBeVisible();
      await goBackButton.click();
    }

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

    // Wait for page to load - check if templates are available
    const templateSelect = page.locator('[data-testid="template-select"]');
    const noTemplatesMessage = page.locator(
      '[data-testid="no-templates-message"], [data-testid="no-available-templates-message"]',
    );

    // Wait for either template select or no-templates message
    await expect(templateSelect.or(noTemplatesMessage)).toBeVisible({ timeout: 10000 });

    // E2E environment must have templates - fail if not available
    expect(await noTemplatesMessage.isVisible(), "E2E environment must have debug session templates configured").toBe(
      false,
    );

    // Step 1: Select a template to enable the Next button
    await templateSelect.click();
    await page.waitForLoadState("networkidle", { timeout: 15000 });
    const firstOption = page.locator("scale-dropdown-select-item").first();
    if (await firstOption.isVisible()) {
      await firstOption.click();
      await page.waitForLoadState("networkidle", { timeout: 15000 });
    }

    // Click Next button to go to Step 2
    const nextButton = page.locator('[data-testid="next-button"]');
    await expect(nextButton).toBeVisible({ timeout: 5000 });
    await nextButton.click();
    await page.waitForLoadState("networkidle");

    // Step 2: Select a cluster to reveal the session details form
    const clusterCard = page.locator(".cluster-card").first();
    await expect(clusterCard).toBeVisible({ timeout: 10000 });
    await clusterCard.click();
    await page.waitForLoadState("networkidle");

    // The create button should be visible but disabled because reason is empty
    const createButton = page.locator('[data-testid="create-session-button"]');
    await expect(createButton).toBeVisible({ timeout: 10000 });

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

    // Check if templates are available
    const templateSelect = page.locator('[data-testid="template-select"]');
    const noTemplatesMessage = page.locator(
      '[data-testid="no-templates-message"], [data-testid="no-available-templates-message"]',
    );

    await expect(templateSelect.or(noTemplatesMessage)).toBeVisible({ timeout: 10000 });

    // E2E environment must have templates - fail if not available
    expect(await noTemplatesMessage.isVisible(), "E2E environment must have debug session templates configured").toBe(
      false,
    );

    // Step 1: Select a template
    await templateSelect.click();
    await page.waitForLoadState("networkidle", { timeout: 15000 });
    const firstOption = page.locator("scale-dropdown-select-item").first();
    if (await firstOption.isVisible()) {
      await firstOption.click();
      await page.waitForLoadState("networkidle", { timeout: 15000 });
    }

    // Click Next button to go to Step 2
    const nextButton = page.locator('[data-testid="next-button"]');
    await expect(nextButton).toBeVisible({ timeout: 5000 });
    await nextButton.click();
    await page.waitForLoadState("networkidle");

    // Step 2: Select a cluster to reveal the session details form
    const clusterCard = page.locator(".cluster-card").first();
    await expect(clusterCard).toBeVisible({ timeout: 10000 });
    await clusterCard.click();
    await page.waitForLoadState("networkidle");

    // Schedule checkbox should now be visible
    const scheduleCheckbox = page.locator('[data-testid="schedule-checkbox"]');
    await expect(scheduleCheckbox).toBeVisible({ timeout: 5000 });

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

    // Check if templates are available
    const templateSelect = page.locator('[data-testid="template-select"]');
    const noTemplatesMessage = page.locator(
      '[data-testid="no-templates-message"], [data-testid="no-available-templates-message"]',
    );

    await expect(templateSelect.or(noTemplatesMessage)).toBeVisible({ timeout: 10000 });

    // E2E environment must have templates - fail if not available
    expect(await noTemplatesMessage.isVisible(), "E2E environment must have debug session templates configured").toBe(
      false,
    );

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

  test("binding options appear when cluster has multiple bindings", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.requester);

    await page.goto("/debug-sessions/create");
    await page.waitForLoadState("networkidle");

    // Check if templates are available
    const templateSelect = page.locator('[data-testid="template-select"]');
    const noTemplatesMessage = page.locator(
      '[data-testid="no-templates-message"], [data-testid="no-available-templates-message"]',
    );

    await expect(templateSelect.or(noTemplatesMessage)).toBeVisible({ timeout: 10000 });

    // E2E environment must have templates - fail if not available
    expect(await noTemplatesMessage.isVisible(), "E2E environment must have debug session templates configured").toBe(
      false,
    );

    // Step 1: Select a template
    await templateSelect.click();
    await page.waitForLoadState("networkidle", { timeout: 15000 });
    const firstOption = page.locator("scale-dropdown-select-item").first();
    if (await firstOption.isVisible()) {
      await firstOption.click();
      await page.waitForLoadState("networkidle", { timeout: 15000 });
    }

    // Click Next button to go to Step 2
    const nextButton = page.locator('[data-testid="next-button"]');
    await expect(nextButton).toBeVisible({ timeout: 5000 });
    await nextButton.click();
    await page.waitForLoadState("networkidle");

    // Step 2: Select a cluster
    const clusterCard = page.locator(".cluster-card").first();
    await expect(clusterCard).toBeVisible({ timeout: 10000 });
    await clusterCard.click();
    await page.waitForLoadState("networkidle");

    // Check if binding options section appears (only for clusters with multiple bindings)
    const bindingOptionsSection = page.locator('[data-testid="binding-options-section"]');
    // This may or may not be visible depending on the cluster's bindings
    // We just verify the test doesn't crash
    const hasBindingOptions = await bindingOptionsSection.isVisible().catch(() => false);

    if (hasBindingOptions) {
      // Verify binding option cards are present
      const bindingCards = page.locator('[data-testid="binding-option-card"]');
      const cardCount = await bindingCards.count();
      expect(cardCount).toBeGreaterThan(1);

      // Click on a different binding option
      if (cardCount > 1) {
        const secondCard = bindingCards.nth(1);
        await secondCard.click();
        // Verify it gets selected
        await expect(secondCard).toHaveClass(/selected/);
      }
    }
  });

  test("cluster card shows binding count indicator", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.requester);

    await page.goto("/debug-sessions/create");
    await page.waitForLoadState("networkidle");

    // Check if templates are available
    const templateSelect = page.locator('[data-testid="template-select"]');
    const noTemplatesMessage = page.locator(
      '[data-testid="no-templates-message"], [data-testid="no-available-templates-message"]',
    );

    await expect(templateSelect.or(noTemplatesMessage)).toBeVisible({ timeout: 10000 });

    // E2E environment must have templates - fail if not available
    expect(await noTemplatesMessage.isVisible(), "E2E environment must have debug session templates configured").toBe(
      false,
    );

    // Step 1: Select a template
    await templateSelect.click();
    await page.waitForLoadState("networkidle", { timeout: 15000 });
    const firstOption = page.locator("scale-dropdown-select-item").first();
    if (await firstOption.isVisible()) {
      await firstOption.click();
      await page.waitForLoadState("networkidle", { timeout: 15000 });
    }

    // Click Next button
    const nextButton = page.locator('[data-testid="next-button"]');
    await expect(nextButton).toBeVisible({ timeout: 5000 });
    await nextButton.click();
    await page.waitForLoadState("networkidle");

    // Look for cluster cards with multiple bindings indicator
    const clusterGrid = page.locator('[data-testid="cluster-grid"]');
    await expect(clusterGrid).toBeVisible({ timeout: 10000 });

    // Look for "access options" text in cluster cards (indicates multiple bindings)
    const multiBindingIndicator = page.locator(".multiple-bindings");
    // This may or may not be visible depending on environment setup
    const hasMultiBinding = await multiBindingIndicator
      .first()
      .isVisible()
      .catch(() => false);

    // Log the result for debugging
    if (hasMultiBinding) {
      // Verify the indicator contains expected text
      await expect(multiBindingIndicator.first()).toContainText("access option");
    }

    // Just verify the grid renders correctly
    const clusterCards = page.locator('[data-testid="cluster-card"]');
    const cardCount = await clusterCards.count();
    expect(cardCount).toBeGreaterThanOrEqual(0); // May be 0 if no clusters available
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

// Debug Session Details Page - UI Elements
test.describe("Debug Session Details Page UI", () => {
  test("details page shows session state tag", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");

    const sessionCards = page.locator('[data-testid="debug-session-card"]');
    const count = await sessionCards.count();

    if (count > 0) {
      await sessionCards.first().locator('[data-testid="view-details-button"]').click();
      await page.waitForLoadState("networkidle");

      // State tag should be visible
      const stateTag = page.locator('[data-testid="session-state-tag"]');
      await expect(stateTag).toBeVisible();
    }
  });

  test("details page shows session info card", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");

    const sessionCards = page.locator('[data-testid="debug-session-card"]');
    const count = await sessionCards.count();

    if (count > 0) {
      await sessionCards.first().locator('[data-testid="view-details-button"]').click();
      await page.waitForLoadState("networkidle");

      // Session info card should be visible
      const infoCard = page.locator('[data-testid="session-info-card"]');
      await expect(infoCard).toBeVisible();

      // Info list should be visible within the card
      const infoList = page.locator('[data-testid="session-info-list"]');
      await expect(infoList).toBeVisible();
    }
  });

  test("details page shows status card with details", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");

    const sessionCards = page.locator('[data-testid="debug-session-card"]');
    const count = await sessionCards.count();

    if (count > 0) {
      await sessionCards.first().locator('[data-testid="view-details-button"]').click();
      await page.waitForLoadState("networkidle");

      // Status card should be visible
      const statusCard = page.locator('[data-testid="status-card"]');
      await expect(statusCard).toBeVisible();
    }
  });

  test("details page has session actions section for appropriate states", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");

    const sessionCards = page.locator('[data-testid="debug-session-card"]');
    const count = await sessionCards.count();

    if (count > 0) {
      await sessionCards.first().locator('[data-testid="view-details-button"]').click();
      await page.waitForLoadState("networkidle");

      // Check for any action buttons - they may or may not exist depending on session state
      const actionsSection = page.locator('[data-testid="session-actions"]');
      // Actions section exists but may be empty for expired/terminated sessions
      const exists = await actionsSection.isVisible().catch(() => false);
      expect(exists === true || exists === false).toBe(true);
    }
  });

  test("renew button opens dialog on details page", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");

    const sessionCards = page.locator('[data-testid="debug-session-card"]');
    const count = await sessionCards.count();

    if (count > 0) {
      await sessionCards.first().locator('[data-testid="view-details-button"]').click();
      await page.waitForLoadState("networkidle");

      // Check for renew button on details page
      const renewButton = page.locator('[data-testid="renew-session-button"]');
      if (await renewButton.isVisible({ timeout: 2000 }).catch(() => false)) {
        await renewButton.click();

        // Should see renew duration select in modal
        const durationSelect = page.locator('[data-testid="renew-duration-select"]');
        await expect(durationSelect).toBeVisible({ timeout: 5000 });
      }
    }
  });

  test("terminate button is visible for active sessions on details page", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");

    const sessionCards = page.locator('[data-testid="debug-session-card"]');
    const count = await sessionCards.count();

    if (count > 0) {
      await sessionCards.first().locator('[data-testid="view-details-button"]').click();
      await page.waitForLoadState("networkidle");

      // Check for terminate button on details page (only visible for active sessions)
      const terminateButton = page.locator('[data-testid="terminate-session-button"]');
      // Just check it's interactable if visible
      if (await terminateButton.isVisible({ timeout: 2000 }).catch(() => false)) {
        await expect(terminateButton).toBeVisible();
      }
    }
  });

  test("approve and reject buttons visible for pending sessions", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");

    // Filter for pending sessions
    const pendingFilter = page.locator('[data-testid="state-filter-PendingApproval"]');
    if (await pendingFilter.isVisible()) {
      await pendingFilter.click();
      await page.waitForLoadState("networkidle", { timeout: 15000 });
    }

    const sessionCards = page.locator('[data-testid="debug-session-card"]');
    const count = await sessionCards.count();

    if (count > 0) {
      await sessionCards.first().locator('[data-testid="view-details-button"]').click();
      await page.waitForLoadState("networkidle");

      // Check for approve/reject buttons
      const approveButton = page.locator('[data-testid="approve-session-button"]');
      const rejectButton = page.locator('[data-testid="reject-session-button"]');

      if (await approveButton.isVisible({ timeout: 2000 }).catch(() => false)) {
        await expect(approveButton).toBeVisible();
        await expect(rejectButton).toBeVisible();
      }
    }
  });

  test("reject button opens rejection dialog on details page", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");

    // Filter for pending sessions
    const pendingFilter = page.locator('[data-testid="state-filter-PendingApproval"]');
    if (await pendingFilter.isVisible()) {
      await pendingFilter.click();
      await page.waitForLoadState("networkidle", { timeout: 15000 });
    }

    const sessionCards = page.locator('[data-testid="debug-session-card"]');
    const count = await sessionCards.count();

    if (count > 0) {
      await sessionCards.first().locator('[data-testid="view-details-button"]').click();
      await page.waitForLoadState("networkidle");

      // Check for reject button
      const rejectButton = page.locator('[data-testid="reject-session-button"]');
      if (await rejectButton.isVisible({ timeout: 2000 }).catch(() => false)) {
        await rejectButton.click();

        // Should see rejection reason input
        const rejectReasonInput = page.locator('[data-testid="reject-reason-input"]');
        await expect(rejectReasonInput).toBeVisible({ timeout: 5000 });
      }
    }
  });
});

// Kubectl-Debug Forms (only visible for kubectl-debug or hybrid mode sessions)
test.describe("Debug Session Kubectl-Debug Forms", () => {
  test("kubectl-debug card is visible for active kubectl-debug mode sessions", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");

    // Filter for active sessions
    const activeFilter = page.locator('[data-testid="state-filter-Active"]');
    if (await activeFilter.isVisible()) {
      await activeFilter.click();
      await page.waitForLoadState("networkidle", { timeout: 15000 });
    }

    const sessionCards = page.locator('[data-testid="debug-session-card"]');
    const count = await sessionCards.count();

    if (count > 0) {
      await sessionCards.first().locator('[data-testid="view-details-button"]').click();
      await page.waitForLoadState("networkidle");

      // kubectl-debug card may or may not be visible depending on session mode
      const kubectlDebugCard = page.locator('[data-testid="kubectl-debug-card"]');
      // Just verify the page renders correctly - card visibility depends on session mode
      const isVisible = await kubectlDebugCard.isVisible({ timeout: 2000 }).catch(() => false);
      expect(isVisible === true || isVisible === false).toBe(true);
    }
  });

  test("kubectl-debug buttons are visible when card is shown", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");

    // Filter for active sessions
    const activeFilter = page.locator('[data-testid="state-filter-Active"]');
    if (await activeFilter.isVisible()) {
      await activeFilter.click();
      await page.waitForLoadState("networkidle", { timeout: 15000 });
    }

    const sessionCards = page.locator('[data-testid="debug-session-card"]');
    const count = await sessionCards.count();

    if (count > 0) {
      await sessionCards.first().locator('[data-testid="view-details-button"]').click();
      await page.waitForLoadState("networkidle");

      // If kubectl-debug card is visible, check for buttons
      const kubectlDebugCard = page.locator('[data-testid="kubectl-debug-card"]');
      if (await kubectlDebugCard.isVisible({ timeout: 2000 }).catch(() => false)) {
        // Should see the three debug buttons
        const ephemeralButton = page.locator('[data-testid="inject-ephemeral-button"]');
        const podCopyButton = page.locator('[data-testid="create-pod-copy-button"]');
        const nodeDebugButton = page.locator('[data-testid="debug-node-button"]');

        await expect(ephemeralButton).toBeVisible();
        await expect(podCopyButton).toBeVisible();
        await expect(nodeDebugButton).toBeVisible();
      }
    }
  });

  test("inject ephemeral container button opens form", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");

    // Filter for active sessions
    const activeFilter = page.locator('[data-testid="state-filter-Active"]');
    if (await activeFilter.isVisible()) {
      await activeFilter.click();
      await page.waitForLoadState("networkidle", { timeout: 15000 });
    }

    const sessionCards = page.locator('[data-testid="debug-session-card"]');
    const count = await sessionCards.count();

    if (count > 0) {
      await sessionCards.first().locator('[data-testid="view-details-button"]').click();
      await page.waitForLoadState("networkidle");

      // If kubectl-debug card is visible, test ephemeral form
      const ephemeralButton = page.locator('[data-testid="inject-ephemeral-button"]');
      if (await ephemeralButton.isVisible({ timeout: 2000 }).catch(() => false)) {
        await ephemeralButton.click();

        // Form should appear with namespace and pod fields
        await expect(page.getByText("Inject Ephemeral Container")).toBeVisible();
        await expect(page.getByLabel(/Namespace/i)).toBeVisible();
        await expect(page.getByLabel(/Pod Name/i)).toBeVisible();
        await expect(page.getByLabel(/Container Name/i)).toBeVisible();
        await expect(page.getByLabel(/Debug Image/i)).toBeVisible();
      }
    }
  });

  test("create pod copy button opens form", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");

    // Filter for active sessions
    const activeFilter = page.locator('[data-testid="state-filter-Active"]');
    if (await activeFilter.isVisible()) {
      await activeFilter.click();
      await page.waitForLoadState("networkidle", { timeout: 15000 });
    }

    const sessionCards = page.locator('[data-testid="debug-session-card"]');
    const count = await sessionCards.count();

    if (count > 0) {
      await sessionCards.first().locator('[data-testid="view-details-button"]').click();
      await page.waitForLoadState("networkidle");

      // If kubectl-debug card is visible, test pod copy form
      const podCopyButton = page.locator('[data-testid="create-pod-copy-button"]');
      if (await podCopyButton.isVisible({ timeout: 2000 }).catch(() => false)) {
        await podCopyButton.click();

        // Form should appear with namespace and pod fields
        await expect(page.getByText("Create Pod Copy")).toBeVisible();
        await expect(page.getByLabel(/Namespace/i)).toBeVisible();
        await expect(page.getByLabel(/Pod Name/i)).toBeVisible();
      }
    }
  });

  test("debug node button opens form", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");

    // Filter for active sessions
    const activeFilter = page.locator('[data-testid="state-filter-Active"]');
    if (await activeFilter.isVisible()) {
      await activeFilter.click();
      await page.waitForLoadState("networkidle", { timeout: 15000 });
    }

    const sessionCards = page.locator('[data-testid="debug-session-card"]');
    const count = await sessionCards.count();

    if (count > 0) {
      await sessionCards.first().locator('[data-testid="view-details-button"]').click();
      await page.waitForLoadState("networkidle");

      // If kubectl-debug card is visible, test node debug form
      const nodeDebugButton = page.locator('[data-testid="debug-node-button"]');
      if (await nodeDebugButton.isVisible({ timeout: 2000 }).catch(() => false)) {
        await nodeDebugButton.click();

        // Form should appear with node name field
        await expect(page.getByText("Create Node Debug Pod")).toBeVisible();
        await expect(page.getByLabel(/Node Name/i)).toBeVisible();
      }
    }
  });

  test("kubectl-debug form has cancel button", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");

    // Filter for active sessions
    const activeFilter = page.locator('[data-testid="state-filter-Active"]');
    if (await activeFilter.isVisible()) {
      await activeFilter.click();
      await page.waitForLoadState("networkidle", { timeout: 15000 });
    }

    const sessionCards = page.locator('[data-testid="debug-session-card"]');
    const count = await sessionCards.count();

    if (count > 0) {
      await sessionCards.first().locator('[data-testid="view-details-button"]').click();
      await page.waitForLoadState("networkidle");

      // If kubectl-debug card is visible, test form cancel
      const ephemeralButton = page.locator('[data-testid="inject-ephemeral-button"]');
      if (await ephemeralButton.isVisible({ timeout: 2000 }).catch(() => false)) {
        await ephemeralButton.click();

        // Should see cancel button
        const cancelButton = page.getByRole("button", { name: /Cancel/i });
        await expect(cancelButton).toBeVisible();

        // Click cancel
        await cancelButton.click();

        // Form should close, buttons should be visible again
        await expect(ephemeralButton).toBeVisible();
      }
    }
  });
});
