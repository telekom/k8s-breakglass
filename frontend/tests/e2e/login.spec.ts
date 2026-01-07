// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { test, expect } from "@playwright/test";
import { AuthHelper, TEST_USERS } from "./helpers";

test.describe("Login Flow", () => {
  test("user can login via Keycloak OIDC", async ({ page }) => {
    const auth = new AuthHelper(page);

    // Start at app root
    await page.goto("/");

    // Should redirect to Keycloak
    await expect(page).toHaveURL(/keycloak|auth/);

    // Login as Bob (developer)
    await auth.loginViaKeycloak(TEST_USERS.requester);

    // Should be back at app
    await expect(page).toHaveURL(/localhost:5173/);

    // Should see user info in the menu
    const userMenu = page.locator('[data-testid="user-menu"]');
    await expect(userMenu).toBeVisible();

    // Should see escalation list (home page)
    await expect(page.locator('[data-testid="escalation-list"]')).toBeVisible();
  });

  test("user can logout", async ({ page }) => {
    const auth = new AuthHelper(page);

    // Login first
    await auth.loginViaKeycloak(TEST_USERS.requester);

    // Verify logged in
    expect(await auth.isLoggedIn()).toBe(true);

    // Logout
    await auth.logout();

    // Should be logged out
    expect(await auth.isLoggedIn()).toBe(false);
  });

  test("unauthenticated user is redirected to login", async ({ page }) => {
    // Try to access protected route directly
    await page.goto("/sessions");

    // Should redirect to Keycloak
    await expect(page).toHaveURL(/keycloak|auth/);
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

  test("admin user can access admin features", async ({ page }) => {
    const auth = new AuthHelper(page);

    // Login as admin
    await auth.loginViaKeycloak(TEST_USERS.admin);

    // Should be logged in
    expect(await auth.isLoggedIn()).toBe(true);

    // Should be able to access all routes
    await page.goto("/sessions");
    await page.waitForLoadState("networkidle");
    await expect(page.locator('[data-testid="session-list"]')).toBeVisible();
  });
});
