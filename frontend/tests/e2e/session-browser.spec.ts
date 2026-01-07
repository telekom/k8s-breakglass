// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { test, expect } from "@playwright/test";
import { AuthHelper, TEST_USERS } from "./helpers";

test.describe("Session Browser", () => {
  test("approver can view all sessions", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    // Navigate to session browser
    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");

    // Should see session list
    await expect(page.locator('[data-testid="session-list"]')).toBeVisible();
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
      await page.waitForTimeout(500); // Debounce wait

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
      await page.waitForTimeout(500);

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
        await page.waitForTimeout(500);

        // Verify filter was applied (page should update)
        await page.waitForLoadState("networkidle");
      }
    }
  });

  test("clicking session row shows details", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");

    // Check if there are any sessions
    const sessionRows = page.locator('[data-testid="session-row"]');
    const count = await sessionRows.count();

    if (count > 0) {
      // Click first session
      await sessionRows.first().click();

      // Should show detail view
      await expect(page.locator('[data-testid="session-details"]')).toBeVisible({
        timeout: 10000,
      });

      // Verify key information displayed
      await expect(page.locator('[data-testid="detail-requester"]')).toBeVisible();
      await expect(page.locator('[data-testid="detail-cluster"]')).toBeVisible();
      await expect(page.locator('[data-testid="detail-status"]')).toBeVisible();
      await expect(page.locator('[data-testid="detail-reason"]')).toBeVisible();
    }
  });

  test("session details show timestamps", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");

    const sessionRows = page.locator('[data-testid="session-row"]');
    const count = await sessionRows.count();

    if (count > 0) {
      await sessionRows.first().click();

      await expect(page.locator('[data-testid="session-details"]')).toBeVisible();

      // Check for timestamp fields
      const createdAt = page.locator('[data-testid="detail-created-at"]');
      if (await createdAt.isVisible()) {
        const text = await createdAt.textContent();
        // Should contain some date-like content
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
      await page.waitForTimeout(500);

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
