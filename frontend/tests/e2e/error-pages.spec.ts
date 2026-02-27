// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { test, expect } from "@playwright/test";
import { AuthHelper, TEST_USERS } from "./helpers";

test.describe("404 Not Found Page", () => {
  test.beforeEach(async ({ page }) => {
    // Login before testing error pages
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.requester);
  });

  test("displays 404 page for unknown routes", async ({ page }) => {
    await page.goto("/some-nonexistent-page-xyz");
    await page.waitForLoadState("networkidle");

    // Verify 404 page content
    await expect(page.getByText("Page not found")).toBeVisible();
    // The text uses curly apostrophe, check for simpler partial match
    await expect(page.getByText(/looking for/i)).toBeVisible();
  });

  test("has return to dashboard link", async ({ page }) => {
    await page.goto("/unknown-route-test");
    await page.waitForLoadState("networkidle");

    // Should have link to return to dashboard
    const returnLink = page.getByRole("link", { name: /Return to dashboard/i });
    await expect(returnLink).toBeVisible();
  });

  test("return to dashboard link navigates home", async ({ page }) => {
    await page.goto("/nonexistent-page");
    await page.waitForLoadState("networkidle");

    // Click the return link
    const returnLink = page.getByRole("link", { name: /Return to dashboard/i });
    await returnLink.click();
    await page.waitForLoadState("networkidle");

    // Should be at home page
    expect(page.url()).toContain("/");
    // Should see the main escalation view
    await expect(page.locator('[data-testid="escalation-list"]')).toBeVisible({ timeout: 10000 });
  });

  test("deep nested unknown routes show 404", async ({ page }) => {
    await page.goto("/some/deeply/nested/path/that/does/not/exist");
    await page.waitForLoadState("networkidle");

    await expect(page.getByText("Page not found")).toBeVisible();
  });
});

test.describe("Session Error View", () => {
  test.beforeEach(async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.requester);
  });

  test("shows error for /session without name", async ({ page }) => {
    await page.goto("/session");
    await page.waitForLoadState("networkidle");

    // Should show session error view - title is always visible
    await expect(page.getByText("Invalid Session Link")).toBeVisible();
    // The error message is inside a scale-notification which may expand
    await expect(page.locator(".error-content")).toBeAttached();
  });

  test("shows error for /session/:name without /approve", async ({ page }) => {
    await page.goto("/session/test-session-name");
    await page.waitForLoadState("networkidle");

    // Should show incomplete URL error - title is visible
    await expect(page.getByText("Invalid Session Link")).toBeVisible();
    // Error content is inside notification
    await expect(page.locator(".error-content")).toBeAttached();
  });

  test("has return to home button", async ({ page }) => {
    await page.goto("/session");
    await page.waitForLoadState("networkidle");

    // Should have home button
    const homeButton = page.getByRole("button", { name: /Return to Home/i });
    await expect(homeButton).toBeVisible();
  });

  test("return to home button navigates home", async ({ page }) => {
    await page.goto("/session");
    await page.waitForLoadState("networkidle");

    // Click home button
    const homeButton = page.getByRole("button", { name: /Return to Home/i });
    await homeButton.click();
    await page.waitForLoadState("networkidle");

    // Should be at home
    expect(page.url().endsWith("/") || page.url().endsWith("/#/")).toBe(true);
  });

  test("has view all sessions button", async ({ page }) => {
    await page.goto("/session");
    await page.waitForLoadState("networkidle");

    // Should have sessions button
    const sessionsButton = page.getByRole("button", { name: /View All Sessions/i });
    await expect(sessionsButton).toBeVisible();
  });

  test("view all sessions button navigates to sessions", async ({ page }) => {
    await page.goto("/session/incomplete-session");
    await page.waitForLoadState("networkidle");

    // Click sessions button
    const sessionsButton = page.getByRole("button", { name: /View All Sessions/i });
    await sessionsButton.click();

    // Wait for the router to navigate to the sessions page
    await page.waitForURL(/\/sessions$/, { timeout: 10000 });
  });

  test("shows expected link format in error message", async ({ page }) => {
    await page.goto("/session");
    await page.waitForLoadState("networkidle");

    // Should show the error title and error content is attached
    await expect(page.getByText("Invalid Session Link")).toBeVisible();
    await expect(page.locator("code")).toBeAttached();
  });
});

test.describe("Navigation Between Error Pages", () => {
  test.beforeEach(async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.requester);
  });

  test("can navigate from 404 to session error and back", async ({ page }) => {
    // Start at 404
    await page.goto("/unknown");
    await expect(page.getByText("Page not found")).toBeVisible();

    // Navigate to session error
    await page.goto("/session");
    await expect(page.getByText("Invalid Session Link")).toBeVisible();

    // Navigate back home
    const homeButton = page.getByRole("button", { name: /Return to Home/i });
    await homeButton.click();
    await page.waitForLoadState("networkidle");

    // Should be home
    await expect(page.locator('[data-testid="escalation-list"]')).toBeVisible({ timeout: 10000 });
  });

  test("browser back button works from error pages", async ({ page }) => {
    // Start at home
    await page.goto("/");
    await page.waitForLoadState("networkidle");
    await expect(page.locator('[data-testid="escalation-list"]')).toBeVisible({ timeout: 10000 });

    // Navigate to 404
    await page.goto("/nonexistent");
    await expect(page.getByText("Page not found")).toBeVisible();

    // Use browser back
    await page.goBack();
    await page.waitForLoadState("networkidle");

    // Should be back at home
    await expect(page.locator('[data-testid="escalation-list"]')).toBeVisible({ timeout: 10000 });
  });
});
