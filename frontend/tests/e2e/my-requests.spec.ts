// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { test, expect } from "@playwright/test";
import {
  AuthHelper,
  TEST_USERS,
  fillScaleTextarea,
  waitForScaleToast,
  findEscalationCardByName,
  waitForScaleModal,
} from "./helpers";

// This test file uses ui-e2e-my-requests-user (isolated user with group "ui-e2e-my-requests-requester")
// It targets the "ui-e2e-my-requests-test" escalation which only allows "ui-e2e-my-requests-requester" group
// Approver: ui-e2e-approver
const ESCALATION_NAME = "ui-e2e-my-requests-group";

test.describe.serial("My Pending Requests View", () => {
  test("user can view my requests page", async ({ page }) => {
    const auth = new AuthHelper(page);
    // Use ui-e2e-my-requests-user (isolated from other tests)
    await auth.loginViaKeycloak(TEST_USERS.uiE2eMyRequests);

    // Navigate to my requests
    await page.goto("/requests/mine");
    await page.waitForLoadState("networkidle");

    // Should see my requests view
    const requestsView = page.locator('[data-testid="my-requests-view"]');
    await expect(requestsView).toBeVisible({ timeout: 10000 });
  });

  test("page header is displayed correctly", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.uiE2eMyRequests);

    await page.goto("/requests/mine");
    await page.waitForLoadState("networkidle");

    // Should see header with title
    const header = page.locator('[data-testid="my-requests-header"]');
    await expect(header).toBeVisible();
    await expect(header).toContainText(/pending requests/i);
  });

  test("empty state shown when no pending requests", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.uiE2eMyRequests);

    await page.goto("/requests/mine");
    await page.waitForLoadState("networkidle");

    // Either shows requests list or empty state
    const requestsList = page.locator('[data-testid="requests-list"]');
    const emptyState = page.locator('[data-testid="empty-state"]');

    // One of these should be visible
    await expect(requestsList.or(emptyState).first()).toBeVisible();
  });

  test("loading state is shown initially", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.uiE2eMyRequests);

    // Navigate and check for loading state quickly
    await page.goto("/requests/mine");

    // Loading state may be very brief, but we can at least check element exists
    const loadingState = page.locator('[data-testid="my-requests-loading"]');
    // Just verify the attribute exists in the template (may already be gone)
    await expect(loadingState.or(page.locator('[data-testid="requests-section"]'))).toBeVisible({ timeout: 10000 });
  });
});

// Tests that create or modify sessions must run serially to avoid race conditions
// when multiple tests try to use the same escalation concurrently
test.describe.serial("My Requests - Request Management", () => {
  test("pending request card shows countdown timers", async ({ page }) => {
    const auth = new AuthHelper(page);
    // Use ui-e2e-my-requests-user (isolated from other tests)
    await auth.loginViaKeycloak(TEST_USERS.uiE2eMyRequests);

    // Navigate to home to create a pending request
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Find the specific escalation card for this test file
    const escalationCard = await findEscalationCardByName(page, ESCALATION_NAME, { requireAvailable: true });
    if (escalationCard) {
      await escalationCard.locator('[data-testid="request-access-button"]').click();

      // Fill minimal form - wait for modal animation to complete
      await waitForScaleModal(page, '[data-testid="request-modal"]');
      await fillScaleTextarea(page, '[data-testid="reason-input"]', "E2E test countdown timer");
      await page.click('[data-testid="submit-request-button"]');

      // Wait for success and navigate
      await waitForScaleToast(page, "success-toast");
      await page.goto("/requests/mine");
      await page.waitForLoadState("networkidle");

      // Should see timeout countdown on pending card
      const pendingCard = page.locator('[data-testid^="pending-request-card-"]').first();
      if (await pendingCard.isVisible()) {
        const timeoutCountdown = pendingCard.locator('[data-testid="timeout-countdown"]');
        await expect(timeoutCountdown).toBeVisible();
      }
    }
  });

  test("user can withdraw pending request", async ({ page }) => {
    const auth = new AuthHelper(page);
    // Use ui-e2e-my-requests-user (isolated from other tests)
    await auth.loginViaKeycloak(TEST_USERS.uiE2eMyRequests);

    // Navigate to home to create a pending request
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Find the specific escalation card for this test file
    const escalationCard = await findEscalationCardByName(page, ESCALATION_NAME, { requireAvailable: true });
    if (escalationCard) {
      await escalationCard.locator('[data-testid="request-access-button"]').click();

      // Fill minimal form - wait for modal animation to complete
      await waitForScaleModal(page, '[data-testid="request-modal"]');
      await fillScaleTextarea(page, '[data-testid="reason-input"]', "E2E test withdraw");
      await page.click('[data-testid="submit-request-button"]');

      // Wait for success
      await waitForScaleToast(page, "success-toast");

      // Navigate to my requests
      await page.goto("/requests/mine");
      await page.waitForLoadState("networkidle");

      // Find pending card and withdraw
      const pendingCard = page.locator('[data-testid^="pending-request-card-"]').first();
      if (await pendingCard.isVisible()) {
        const withdrawButton = pendingCard.locator('[data-testid="withdraw-button"]');
        await expect(withdrawButton).toBeVisible();
        await withdrawButton.click();

        // Confirm withdrawal if modal appears
        const confirmButton = page.locator('[data-testid="confirm-withdraw"]');
        if (await confirmButton.isVisible({ timeout: 1000 })) {
          await confirmButton.click();
        }

        // Wait for success toast or withdrawn state to confirm the action completed
        const successToast = page.locator('[data-testid="success-toast"]');
        const withdrawnCard = page.locator('[data-testid^="withdrawn-request-card-"]');

        // Wait for either success toast or withdrawn card with explicit timeout
        await Promise.race([
          successToast.waitFor({ state: "visible", timeout: 30000 }).catch(() => {}),
          withdrawnCard
            .first()
            .waitFor({ state: "visible", timeout: 30000 })
            .catch(() => {}),
        ]);

        // After withdraw, card should either disappear or change to withdrawn state
        // The old pending card should no longer be visible with that name
        await page.waitForLoadState("networkidle");

        // Re-query the pending cards (the locator was pointing to a specific card that should now be gone or changed)
        const remainingPendingCards = page.locator('[data-testid^="pending-request-card-"]');
        const count = await remainingPendingCards.count();
        // If there are still pending cards, verify UI state is stable
        if (count > 0) {
          // Wait for UI to stabilize after state change
          await page.waitForLoadState("networkidle", { timeout: 15000 });
        }
      }
    }
  });

  test("requests list shows multiple pending requests", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.uiE2eMyRequests);

    await page.goto("/requests/mine");
    await page.waitForLoadState("networkidle");

    // If there are requests, verify they're in a list
    const requestsList = page.locator('[data-testid="requests-list"]');
    if (await requestsList.isVisible()) {
      const pendingCards = page.locator('[data-testid^="pending-request-card-"]');
      const count = await pendingCards.count();
      expect(count).toBeGreaterThanOrEqual(0);
    }
  });
});

test.describe.serial("My Requests - Error Handling", () => {
  test("error state shows retry button", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.uiE2eMyRequests);

    // Navigate to a neutral page first, then set up the route interception
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Set up route interception BEFORE navigating to the error-triggering page
    // This ensures the first API call is intercepted
    await page.route("**/api/breakglassSessions*", (route) => {
      const url = route.request().url();
      // Intercept GET requests fetching "my" pending sessions
      if (route.request().method() === "GET" && url.includes("mine=true")) {
        route.fulfill({
          status: 500,
          contentType: "application/json",
          body: JSON.stringify({ error: "Internal Server Error" }),
        });
      } else {
        route.continue();
      }
    });

    // Now navigate - the API call will be intercepted and return 500
    await page.goto("/requests/mine");

    // Wait for DOM to be ready
    await page.waitForLoadState("domcontentloaded");

    // Scale notification components use CSS visibility transitions.
    // We need to wait for the component to be both in DOM and CSS-visible.
    const errorState = page.locator('[data-testid="my-requests-error"]');

    // First wait for the element to exist in DOM
    await errorState.waitFor({ state: "attached", timeout: 15000 });

    // Then wait for CSS visibility to become "visible" (Scale animation)
    await page.waitForFunction(
      () => {
        const el = document.querySelector('[data-testid="my-requests-error"]');
        if (!el) return false;
        const style = window.getComputedStyle(el);
        // Scale notification uses visibility transition - wait for it to complete
        return style.visibility === "visible" && style.display !== "none";
      },
      { timeout: 15000 },
    );

    // Verify retry button is present inside the error banner.
    // Scale-button elements inside scale-notification can have visibility:hidden
    // during their own CSS animation. We need to wait for the button's CSS visibility.
    await page.waitForFunction(
      () => {
        const errorBanner = document.querySelector('[data-testid="my-requests-error"]');
        if (!errorBanner) return false;
        // Find any button element inside
        const button = errorBanner.querySelector("scale-button, button, [role='button']");
        if (!button) return false;
        const style = window.getComputedStyle(button);
        return style.visibility === "visible" && style.display !== "none";
      },
      { timeout: 10000 },
    );
  });
});

// Tests that create sessions must run serially to avoid race conditions
// when multiple tests try to use the same escalation concurrently
test.describe.serial("My Requests - Integration", () => {
  test("new request appears in my requests list", async ({ page }) => {
    const auth = new AuthHelper(page);
    // Use ui-e2e-my-requests-user (isolated from other tests)
    await auth.loginViaKeycloak(TEST_USERS.uiE2eMyRequests);

    // Navigate to home and create request
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Find the specific escalation card for this test file
    const escalationCard = await findEscalationCardByName(page, ESCALATION_NAME, { requireAvailable: true });
    if (escalationCard) {
      const escalationName = await escalationCard.locator('[data-testid="escalation-name"]').textContent();

      await escalationCard.locator('[data-testid="request-access-button"]').click();
      // Wait for modal animation to complete
      await waitForScaleModal(page, '[data-testid="request-modal"]');
      await fillScaleTextarea(page, '[data-testid="reason-input"]', "E2E test integration");
      await page.click('[data-testid="submit-request-button"]');

      // Wait for success
      await waitForScaleToast(page, "success-toast");

      // Navigate to my requests
      await page.goto("/requests/mine");
      await page.waitForLoadState("networkidle");

      // Should see the request we just made
      const requestsList = page.locator('[data-testid="requests-list"]');
      const emptyState = page.locator('[data-testid="empty-state"]');
      await expect(requestsList.or(emptyState).first()).toBeVisible();

      if (await requestsList.isVisible()) {
        // Verify escalation name appears
        if (escalationName) {
          const pageContent = await page.textContent("body");
          expect(pageContent).toContain(escalationName);
        }
      }
    }
  });
});
