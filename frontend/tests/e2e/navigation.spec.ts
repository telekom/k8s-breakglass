// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { test, expect } from "@playwright/test";
import { AuthHelper, TEST_USERS } from "./helpers";

test.describe("Main Navigation", () => {
  test.beforeEach(async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.requester);
  });

  test("can navigate from home to session browser", async ({ page }) => {
    // Start at home
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Navigate to sessions
    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");

    // Should be at session browser
    const sessionBrowser = page.locator('[data-testid="session-browser"]');
    await expect(sessionBrowser).toBeVisible({ timeout: 10000 });
  });

  test("can navigate from home to debug sessions", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");

    // Should be at debug session browser
    const debugBrowser = page.locator('[data-testid="debug-session-browser"]');
    await expect(debugBrowser).toBeVisible({ timeout: 10000 });
  });

  test("can navigate from home to my pending requests", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    await page.goto("/requests/mine");
    await page.waitForLoadState("networkidle");

    // Should be at my pending requests page
    const myRequests = page.locator('[data-testid="my-requests-view"]');
    await expect(myRequests).toBeVisible({ timeout: 10000 });
  });

  test("can navigate from home to pending approvals", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    await page.goto("/approvals/pending");
    await page.waitForLoadState("networkidle");

    // Should be at pending approvals page - check page loaded
    const pendingApprovals = page.locator('[data-testid="pending-approvals-view"]');
    await expect(pendingApprovals).toBeVisible({ timeout: 10000 });
  });

  test("can navigate from session browser to home", async ({ page }) => {
    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");

    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Should be at home with escalation list
    const escalationList = page.locator('[data-testid="escalation-list"]');
    await expect(escalationList).toBeVisible({ timeout: 10000 });
  });

  test("can navigate between debug sessions and breakglass sessions", async ({ page }) => {
    // Debug sessions
    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");
    await expect(page.locator('[data-testid="debug-session-browser"]')).toBeVisible({ timeout: 10000 });

    // Breakglass sessions
    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");
    await expect(page.locator('[data-testid="session-browser"]')).toBeVisible({ timeout: 10000 });

    // Back to debug sessions
    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");
    await expect(page.locator('[data-testid="debug-session-browser"]')).toBeVisible({ timeout: 10000 });
  });
});

test.describe("Navigation via URL", () => {
  test.beforeEach(async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.requester);
  });

  test("direct URL access to session browser works", async ({ page }) => {
    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");

    await expect(page.locator('[data-testid="session-browser"]')).toBeVisible({ timeout: 10000 });
  });

  test("direct URL access to debug sessions works", async ({ page }) => {
    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");

    await expect(page.locator('[data-testid="debug-session-browser"]')).toBeVisible({ timeout: 10000 });
  });

  test("direct URL access to my requests works", async ({ page }) => {
    await page.goto("/requests/mine");
    await page.waitForLoadState("networkidle");

    await expect(page.locator('[data-testid="my-requests-view"]')).toBeVisible({ timeout: 10000 });
  });

  test("direct URL access to pending approvals works", async ({ page }) => {
    await page.goto("/approvals/pending");
    await page.waitForLoadState("networkidle");

    await expect(page.locator('[data-testid="pending-approvals-view"]')).toBeVisible({ timeout: 10000 });
  });

  test("direct URL access to debug session create works", async ({ page }) => {
    await page.goto("/debug-sessions/create");
    await page.waitForLoadState("networkidle");

    // Should be at create page - verify page loads
    const createPage = page.locator('[data-testid="debug-session-create"]');
    await expect(createPage).toBeVisible({ timeout: 10000 });
  });

  test("direct URL access to sessions review works", async ({ page }) => {
    await page.goto("/sessions/review");
    await page.waitForLoadState("networkidle");

    // Should be at review page - verify it loads using page title
    await expect(page.getByRole("heading", { name: /Review Session/i })).toBeVisible({ timeout: 10000 });
  });
});

test.describe("Browser History Navigation", () => {
  test.beforeEach(async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.requester);
  });

  test("browser back button works correctly", async ({ page }) => {
    // Start at home
    await page.goto("/");
    await page.waitForLoadState("networkidle");
    await expect(page.locator('[data-testid="escalation-list"]')).toBeVisible({ timeout: 10000 });

    // Navigate to sessions
    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");
    await expect(page.locator('[data-testid="session-browser"]')).toBeVisible({ timeout: 10000 });

    // Navigate to debug sessions
    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");
    await expect(page.locator('[data-testid="debug-session-browser"]')).toBeVisible({ timeout: 10000 });

    // Go back to sessions
    await page.goBack();
    await page.waitForLoadState("networkidle");
    await expect(page.locator('[data-testid="session-browser"]')).toBeVisible({ timeout: 10000 });

    // Go back to home
    await page.goBack();
    await page.waitForLoadState("networkidle");
    await expect(page.locator('[data-testid="escalation-list"]')).toBeVisible({ timeout: 10000 });
  });

  test("browser forward button works correctly", async ({ page }) => {
    // Build history
    await page.goto("/");
    await page.waitForLoadState("networkidle");
    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");
    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");

    // Go back twice
    await page.goBack();
    await page.waitForLoadState("networkidle");
    await page.goBack();
    await page.waitForLoadState("networkidle");
    await expect(page.locator('[data-testid="escalation-list"]')).toBeVisible({ timeout: 10000 });

    // Go forward
    await page.goForward();
    await page.waitForLoadState("networkidle");
    await expect(page.locator('[data-testid="session-browser"]')).toBeVisible({ timeout: 10000 });

    // Go forward again
    await page.goForward();
    await page.waitForLoadState("networkidle");
    await expect(page.locator('[data-testid="debug-session-browser"]')).toBeVisible({ timeout: 10000 });
  });

  test("deep link into debug session details works with back button", async ({ page }) => {
    // Navigate to debug sessions
    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");

    const sessionCards = page.locator('[data-testid="debug-session-card"]');
    const count = await sessionCards.count();

    if (count > 0) {
      // Go into details
      await sessionCards.first().locator('[data-testid="view-details-button"]').click();
      await page.waitForLoadState("networkidle");

      // Should be on details page
      await expect(page.locator('[data-testid="debug-session-details"]')).toBeVisible({ timeout: 10000 });

      // Use browser back
      await page.goBack();
      await page.waitForLoadState("networkidle");

      // Should be back at browser
      await expect(page.locator('[data-testid="debug-session-browser"]')).toBeVisible({ timeout: 10000 });
    }
  });
});

test.describe("Page Refresh Preservation", () => {
  test.beforeEach(async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.requester);
  });

  test("page refresh preserves location on session browser", async ({ page }) => {
    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");
    await expect(page.locator('[data-testid="session-browser"]')).toBeVisible({ timeout: 10000 });

    // Refresh
    await page.reload();
    await page.waitForLoadState("networkidle");

    // Should still be at session browser
    await expect(page.locator('[data-testid="session-browser"]')).toBeVisible({ timeout: 10000 });
  });

  test("page refresh preserves location on debug sessions", async ({ page }) => {
    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");
    await expect(page.locator('[data-testid="debug-session-browser"]')).toBeVisible({ timeout: 10000 });

    // Refresh
    await page.reload();
    await page.waitForLoadState("networkidle");

    // Should still be at debug session browser
    await expect(page.locator('[data-testid="debug-session-browser"]')).toBeVisible({ timeout: 10000 });
  });

  test("page refresh preserves location on my requests", async ({ page }) => {
    await page.goto("/requests/mine");
    await page.waitForLoadState("networkidle");
    await expect(page.locator('[data-testid="my-requests-view"]')).toBeVisible({ timeout: 10000 });

    // Refresh
    await page.reload();
    await page.waitForLoadState("networkidle");

    // Should still be at my pending requests
    await expect(page.locator('[data-testid="my-requests-view"]')).toBeVisible({ timeout: 10000 });
  });
});
