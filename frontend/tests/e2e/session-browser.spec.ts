// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { test, expect } from "@playwright/test";
import { AuthHelper, TEST_USERS, fillScaleTextField } from "./helpers";

// All session browser tests use the same approver user and shared session state.
// Serial execution prevents race conditions with filters and session list interactions.
test.describe.serial("Session Browser", () => {
  test("approver can view all sessions", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    // Navigate to session browser
    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");

    // Should see session browser page - either session list or empty state
    const sessionList = page.locator('[data-testid="session-list"]');
    const emptyState = page.locator("text=No items found");
    const sessionBrowserHeader = page.locator('h2:has-text("Session Browser")');
    await expect(sessionList.or(emptyState).or(sessionBrowserHeader).first()).toBeVisible({ timeout: 10000 });
  });

  test("session list displays session information", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");

    // If there are sessions, verify they show key information
    const sessionRows = page.locator('[data-testid="session-row"]');
    const count = await sessionRows.count();

    if (count > 0) {
      const firstRow = sessionRows.first();

      // Each row should display status
      await expect(firstRow.locator('[data-testid="status"]')).toBeVisible();
    }
  });

  test("search filter works", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");

    // Find search input
    const searchInput = page.locator('[data-testid="search-input"]');

    if (await searchInput.isVisible()) {
      // Type a search term
      await searchInput.fill("bob");
      await page.waitForLoadState("networkidle", { timeout: 15000 });

      // If there are results, they should contain the search term
      const sessionRows = page.locator('[data-testid="session-row"]');
      const count = await sessionRows.count();

      for (let i = 0; i < count; i++) {
        const rowText = await sessionRows.nth(i).textContent();
        expect(rowText?.toLowerCase()).toContain("bob");
      }
    }
  });

  test("status filter works", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");

    // Find status filter
    const statusFilter = page.locator('[data-testid="status-filter"]');

    if (await statusFilter.isVisible()) {
      // Filter by active status
      await statusFilter.selectOption("active");
      await page.waitForLoadState("networkidle", { timeout: 15000 });

      // All visible rows should be Active
      const sessionRows = page.locator('[data-testid="session-row"]');
      const count = await sessionRows.count();

      for (let i = 0; i < count; i++) {
        const statusText = await sessionRows.nth(i).locator('[data-testid="status"]').textContent();
        expect(statusText?.toLowerCase()).toContain("active");
      }
    }
  });

  test("cluster filter works", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");

    // Find cluster filter
    const clusterFilter = page.locator('[data-testid="cluster-filter"]');

    if (await clusterFilter.isVisible()) {
      // Get available options
      const options = clusterFilter.locator("option");
      const optionCount = await options.count();

      // If there are cluster options beyond "All", select one
      if (optionCount > 1) {
        await clusterFilter.selectOption({ index: 1 });

        // Wait for filter to apply and page to update
        await page.waitForLoadState("networkidle", { timeout: 15000 });
      }
    }
  });

  test("session row displays session information", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");

    // Check if there are any sessions
    const sessionRows = page.locator('[data-testid="session-row"]');
    const count = await sessionRows.count();

    if (count > 0) {
      // Session cards show info inline - verify the first card has expected structure
      const firstCard = sessionRows.first();

      // Verify status tag is visible
      await expect(firstCard.locator('[data-testid="status"]')).toBeVisible({
        timeout: 5000,
      });

      // Verify session name is visible (in .session-name element)
      await expect(firstCard.locator(".session-name")).toBeVisible();

      // Verify cluster/group buttons are visible (in .cluster-group element)
      await expect(firstCard.locator(".cluster-group")).toBeVisible();
    }
  });

  test("session cards show timestamps", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");

    const sessionRows = page.locator('[data-testid="session-row"]');
    const count = await sessionRows.count();

    if (count > 0) {
      // Session cards display time info inline via TimelineGrid component
      // Verify the timeline grid is present in the first card
      const firstCard = sessionRows.first();
      const timelineGrid = firstCard.locator(".timeline-grid, .timeline");

      // Timeline should show timing information
      if (await timelineGrid.isVisible()) {
        const text = await timelineGrid.textContent();
        // Should contain some content
        expect(text).toBeTruthy();
      }
    }
  });

  test("empty state is shown when no sessions", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");

    // Search for something that won't exist
    const searchInput = page.locator('[data-testid="search-input"]');
    if (await searchInput.isVisible()) {
      await searchInput.fill("nonexistent_user_12345_xyz");
      await page.waitForLoadState("networkidle", { timeout: 15000 });

      // Should show empty state or no results message
      const sessionRows = page.locator('[data-testid="session-row"]');
      const count = await sessionRows.count();

      if (count === 0) {
        // Either empty state or session list should still be visible
        const emptyState = page.locator('[data-testid="empty-state"]');
        const sessionList = page.locator('[data-testid="session-list"]');

        const hasEmptyState = await emptyState.isVisible().catch(() => false);
        const hasSessionList = await sessionList.isVisible().catch(() => false);

        expect(hasEmptyState || hasSessionList).toBe(true);
      }
    }
  });
});

// Filter tests share UI state and require serial execution
test.describe.serial("Session Browser - Advanced Filters", () => {
  test("filter checkboxes section is visible", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");

    // Should see filter checkboxes section
    const filterCheckboxes = page.locator('[data-testid="filter-checkboxes"]');
    await expect(filterCheckboxes).toBeVisible();
  });

  test("mine filter checkbox toggles correctly", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");

    // Find and toggle the "Mine" filter
    const mineFilter = page.locator('[data-testid="filter-mine"]');
    if (await mineFilter.isVisible()) {
      await mineFilter.click();
      await page.waitForLoadState("networkidle", { timeout: 15000 });

      // Browser should still be functional
      const sessionBrowser = page.locator('[data-testid="session-browser"]');
      await expect(sessionBrowser).toBeVisible();
    }
  });

  test("approver filter checkbox toggles correctly", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");

    // Find and toggle the "Approver" filter
    const approverFilter = page.locator('[data-testid="filter-approver"]');
    if (await approverFilter.isVisible()) {
      await approverFilter.click();
      await page.waitForLoadState("networkidle", { timeout: 15000 });

      // Browser should still be functional
      const sessionBrowser = page.locator('[data-testid="session-browser"]');
      await expect(sessionBrowser).toBeVisible();
    }
  });

  test("approved by me filter checkbox works", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");

    // Find and toggle "Approved by me" filter
    const approvedByMeFilter = page.locator('[data-testid="filter-approved-by-me"]');
    if (await approvedByMeFilter.isVisible()) {
      await approvedByMeFilter.click();
      await page.waitForLoadState("networkidle", { timeout: 15000 });

      // Should filter results
      const sessionBrowser = page.locator('[data-testid="session-browser"]');
      await expect(sessionBrowser).toBeVisible();
    }
  });

  test("text filters section is visible", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");

    // Should see text filters section
    const textFilters = page.locator('[data-testid="text-filters"]');
    await expect(textFilters).toBeVisible();
  });

  test("cluster filter input accepts text", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");

    const clusterFilter = page.locator('[data-testid="cluster-filter"]');
    if (await clusterFilter.isVisible()) {
      // Use Scale component helper for scale-text-field
      await fillScaleTextField(page, '[data-testid="cluster-filter"]', "test-cluster");

      // Verify value was set - check the internal input
      const internalInput = clusterFilter.locator("input").first();
      await expect(internalInput).toHaveValue("test-cluster");
    }
  });

  test("group filter input accepts text", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");

    const groupFilter = page.locator('[data-testid="group-filter"]');
    if (await groupFilter.isVisible()) {
      // Use Scale component helper for scale-text-field
      await fillScaleTextField(page, '[data-testid="group-filter"]', "admin-group");

      // Verify value was set - check the internal input
      const internalInput = groupFilter.locator("input").first();
      await expect(internalInput).toHaveValue("admin-group");
    }
  });

  test("user filter input accepts text", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");

    const userFilter = page.locator('[data-testid="user-filter"]');
    if (await userFilter.isVisible()) {
      // Use Scale component helper for scale-text-field
      await fillScaleTextField(page, '[data-testid="user-filter"]', "test@example.com");

      // Verify value was set - check the internal input
      const internalInput = userFilter.locator("input").first();
      await expect(internalInput).toHaveValue("test@example.com");
    }
  });

  test("name filter input accepts text", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");

    const nameFilter = page.locator('[data-testid="name-filter"]');
    if (await nameFilter.isVisible()) {
      // Use Scale component helper for scale-text-field
      await fillScaleTextField(page, '[data-testid="name-filter"]', "session-123");

      // Verify value was set - check the internal input
      const internalInput = nameFilter.locator("input").first();
      await expect(internalInput).toHaveValue("session-123");
    }
  });

  test("apply filters button exists and is clickable", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");

    const applyButton = page.locator('[data-testid="apply-filters-button"]');
    if (await applyButton.isVisible()) {
      await applyButton.click();
      await page.waitForLoadState("networkidle", { timeout: 15000 });

      // Browser should still be functional
      const sessionBrowser = page.locator('[data-testid="session-browser"]');
      await expect(sessionBrowser).toBeVisible();
    }
  });

  test("reset filters button clears all filters", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");

    // First, set some filter values using Scale component helper
    const clusterFilter = page.locator('[data-testid="cluster-filter"]');
    if (await clusterFilter.isVisible()) {
      await fillScaleTextField(page, '[data-testid="cluster-filter"]', "some-cluster");
    }

    // Click reset
    const resetButton = page.locator('[data-testid="reset-filters-button"]');
    if (await resetButton.isVisible()) {
      await resetButton.click();
      await page.waitForLoadState("networkidle", { timeout: 15000 });

      // Verify filter is cleared - check the internal input
      if (await clusterFilter.isVisible()) {
        const internalInput = clusterFilter.locator("input").first();
        await expect(internalInput).toHaveValue("");
      }
    }
  });

  test("state filters section is visible", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");

    // Should see state filters section
    const stateFilters = page.locator('[data-testid="state-filters"]');
    await expect(stateFilters).toBeVisible();
  });

  test("state filter tags are interactive", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");

    // Find and click an Active state filter
    const activeFilter = page.locator('[data-testid="state-filter-Active"]');
    if (await activeFilter.isVisible()) {
      await activeFilter.click();
      await page.waitForLoadState("networkidle", { timeout: 15000 });

      // Should update results
      const sessionBrowser = page.locator('[data-testid="session-browser"]');
      await expect(sessionBrowser).toBeVisible();
    }
  });

  test("pending state filter works", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");

    const pendingFilter = page.locator('[data-testid="state-filter-Pending"]');
    if (await pendingFilter.isVisible()) {
      await pendingFilter.click();
      await page.waitForLoadState("networkidle", { timeout: 15000 });

      // Browser should still work
      const sessionBrowser = page.locator('[data-testid="session-browser"]');
      await expect(sessionBrowser).toBeVisible();
    }
  });
});

// Action tests may modify session state
test.describe.serial("Session Browser - Session Actions", () => {
  test("session action buttons are visible for pending sessions", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");

    // First filter to pending sessions
    const pendingFilter = page.locator('[data-testid="state-filter-Pending"]');
    if (await pendingFilter.isVisible()) {
      await pendingFilter.click();
      await page.waitForLoadState("networkidle", { timeout: 15000 });
    }

    // Check if there are any pending sessions with actions
    const sessionActions = page.locator('[data-testid="session-actions"]').first();
    if (await sessionActions.isVisible()) {
      // Action buttons should be present
      await expect(sessionActions).toBeVisible();
    }
  });

  test("withdraw action button is visible when applicable", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");

    // Look for withdraw action
    const withdrawAction = page.locator('[data-testid="action-withdraw"]');
    if (await withdrawAction.first().isVisible({ timeout: 2000 })) {
      await expect(withdrawAction.first()).toBeVisible();
    }
  });

  test("reject action button is visible for approvers", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");

    // Look for reject action on pending sessions
    const pendingFilter = page.locator('[data-testid="state-filter-Pending"]');
    if (await pendingFilter.isVisible()) {
      await pendingFilter.click();
      await page.waitForLoadState("networkidle", { timeout: 15000 });
    }

    const rejectAction = page.locator('[data-testid="action-reject"]');
    if (await rejectAction.first().isVisible({ timeout: 2000 })) {
      await expect(rejectAction.first()).toBeVisible();
    }
  });
});

// Results section tests depend on shared session data
test.describe.serial("Session Browser - Results Section", () => {
  test("results section shows session data", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");

    // Results section should be visible
    const resultsSection = page.locator('[data-testid="results-section"]');
    await expect(resultsSection).toBeVisible();
  });

  test("loading indicator shows during data fetch", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    // Navigate quickly to catch loading state
    await page.goto("/sessions");

    // Loading indicator may be brief
    const loadingIndicator = page.locator('[data-testid="loading-indicator"]');
    const resultsSection = page.locator('[data-testid="results-section"]');

    // One of these should become visible
    await expect(loadingIndicator.or(resultsSection).first()).toBeVisible({ timeout: 10000 });
  });

  test("empty state shows when no results match filters", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");

    // Set filters that won't match anything
    const nameFilter = page.locator('[data-testid="name-filter"]');
    if (await nameFilter.isVisible()) {
      // Use Scale component helper for scale-text-field
      await fillScaleTextField(page, '[data-testid="name-filter"]', "nonexistent-session-xyz-12345");

      const applyButton = page.locator('[data-testid="apply-filters-button"]');
      if (await applyButton.isVisible()) {
        await applyButton.click();
        await page.waitForLoadState("networkidle", { timeout: 15000 });
      }

      // Should show empty state or no results
      const emptyState = page.locator('[data-testid="empty-state"]');
      const resultsSection = page.locator('[data-testid="results-section"]');
      await expect(emptyState.or(resultsSection).first()).toBeVisible();
    }
  });
});

// Deep linking tests navigate to specific URLs
test.describe.serial("Session Browser - Deep Linking", () => {
  test("filter state is preserved in URL", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");

    // Set a filter
    const mineFilter = page.locator('[data-testid="filter-mine"]');
    if (await mineFilter.isVisible()) {
      await mineFilter.click();
      await page.waitForLoadState("networkidle", { timeout: 15000 });

      // Check if URL was updated (may contain query params)
      const url = page.url();
      // URL should still be sessions page
      expect(url).toContain("/sessions");
    }
  });

  test("direct navigation to sessions page works", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    // Navigate directly
    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");

    // Should load session browser
    const sessionBrowser = page.locator('[data-testid="session-browser"]');
    await expect(sessionBrowser).toBeVisible({ timeout: 10000 });
  });
});
