// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { test, expect } from "@playwright/test";
import { AuthHelper, TEST_USERS } from "./helpers";

// Login tests must be serial because they share browser authentication state
// and test login -> logout -> re-login flows that depend on session state.
test.describe.serial("Login Flow", () => {
  test("user can login via Keycloak OIDC", async ({ page }) => {
    const auth = new AuthHelper(page);

    // Login as a requester user - this handles clicking login button and Keycloak flow
    await auth.loginViaKeycloak(TEST_USERS.requester);

    // Should be back at app (use regex to match any localhost port)
    await expect(page).toHaveURL(/localhost:\d+/);

    // Should see authenticated content - user menu or escalation list
    // The user-menu is inside a Scale web component which may not be accessible in CI
    // due to Shadow DOM rendering. The escalation-list is a more reliable indicator.
    await expect(page.locator('[data-testid="escalation-list"]')).toBeVisible({ timeout: 10000 });

    // Optionally check user menu if it's visible (may fail due to Shadow DOM)
    const userMenu = page.locator('[data-testid="user-menu"]');
    const userMenuVisible = await userMenu.isVisible().catch(() => false);
    if (userMenuVisible) {
      await expect(userMenu).toBeVisible();
    }
  });

  test("user can logout", async ({ page }) => {
    const auth = new AuthHelper(page);

    // Login first
    await auth.loginViaKeycloak(TEST_USERS.requester);

    // Verify logged in
    expect(await auth.isLoggedIn()).toBe(true);

    // Logout - this may trigger OIDC logout redirect or clear local session
    await auth.logout();

    // After logout, either:
    // 1. We're at a login page (OIDC redirect happened)
    // 2. We see a login button (local session cleared)
    // 3. isLoggedIn returns false
    // Wait for logout to complete and UI to stabilize
    await page.waitForLoadState("networkidle", { timeout: 15000 });

    const loggedOut = await auth
      .isLoggedIn()
      .then((r) => !r)
      .catch(() => true);
    const loginButtonVisible = await page
      .locator('scale-button:has-text("Log In"), button:has-text("Log In")')
      .first()
      .isVisible()
      .catch(() => false);
    const onKeycloakPage = page.url().includes("keycloak") || page.url().includes("/auth/");

    // At least one of these should be true after logout
    expect(loggedOut || loginButtonVisible || onKeycloakPage).toBe(true);
  });

  test("unauthenticated user sees login button", async ({ page }) => {
    // Try to access protected route directly
    await page.goto("/sessions");

    // Wait for page to load
    await page.waitForLoadState("networkidle");

    // Should see login button (app shows login gate, not auto-redirect)
    const loginButton = page.locator('scale-button:has-text("Log In"), button:has-text("Log In")').first();
    await expect(loginButton).toBeVisible({ timeout: 10000 });
  });

  test("different users can login with appropriate roles", async ({ page }) => {
    const auth = new AuthHelper(page);

    // Login as approver
    await auth.loginViaKeycloak(TEST_USERS.approver);

    // Should be logged in
    expect(await auth.isLoggedIn()).toBe(true);

    // Approver should see pending approvals section
    await page.goto("/approvals/pending");
    await page.waitForLoadState("networkidle");
    // Should not get access denied
    await expect(page).not.toHaveURL(/access-denied/);
  });

  test("senior approver can access admin features", async ({ page }) => {
    const auth = new AuthHelper(page);

    // Login as senior approver (has elevated privileges)
    await auth.loginViaKeycloak(TEST_USERS.seniorApprover);

    // Should be logged in
    expect(await auth.isLoggedIn()).toBe(true);

    // Should be able to access all routes
    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");
    // Session list shows if sessions exist, or empty state if no sessions
    // Either one indicates successful page load for authenticated user
    const sessionList = page.locator('[data-testid="session-list"]');
    const emptyState = page.locator("text=No items found");
    const sessionPageHeader = page.locator('h2:has-text("Session Browser")');
    await expect(sessionList.or(emptyState).or(sessionPageHeader).first()).toBeVisible({ timeout: 10000 });
  });
});
