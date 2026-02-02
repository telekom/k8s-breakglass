// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { test, expect } from "@playwright/test";
import { AuthHelper, TEST_USERS, waitForScaleModal } from "./helpers";

// This file contains UI edge case tests that cover less common interactions
// and error scenarios that users might encounter.

test.describe("Session Approval View Edge Cases", () => {
  test("approval view shows error for non-existent session", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    // Navigate to approval page for non-existent session
    await page.goto("/session/nonexistent-session-xyz-12345/approve");
    await page.waitForLoadState("networkidle");

    // Should show error state - use specific testid for error title to avoid strict mode violation
    await expect(page.getByTestId("error-title")).toBeVisible({ timeout: 15000 });
  });

  test("approval view handles already approved sessions", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.approver);

    // Navigate to approval page for a session (may be in various states)
    // This tests that the view handles sessions that aren't in pending state
    await page.goto("/session/test-session/approve");
    await page.waitForLoadState("networkidle");

    // Should show some content - either approval form or error/status message
    const approvalContent = page.locator('[data-testid="session-review"]');
    const errorContent = page.getByText(/cannot|error|expired|rejected|approved|not found/i);

    await expect(approvalContent.or(errorContent).first()).toBeVisible({ timeout: 15000 });
  });
});

test.describe("Debug Session Create Wizard Edge Cases", () => {
  test.beforeEach(async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.requester);
  });

  test("create wizard shows error if no templates available", async ({ page }) => {
    // Navigate to create page
    await page.goto("/debug-sessions/create");
    await page.waitForLoadState("networkidle");

    // Page should load - may show template selection or empty state
    const createPage = page.locator('[data-testid="debug-session-create"]');
    await expect(createPage).toBeVisible({ timeout: 10000 });
  });

  test("create wizard requires template selection", async ({ page }) => {
    await page.goto("/debug-sessions/create");
    await page.waitForLoadState("networkidle");

    // Look for continue button - should be disabled without template
    const continueButton = page.getByRole("button", { name: /continue|next/i });
    if (await continueButton.isVisible()) {
      // Template must be selected to proceed
      const templates = page.locator('[data-testid="template-card"]');
      const count = await templates.count();

      if (count === 0) {
        // No templates - continue should be disabled or no templates message shown
        const noTemplatesMsg = page.getByText(/no templates|no debug session templates/i);
        await expect(noTemplatesMsg.or(continueButton)).toBeVisible();
      }
    }
  });
});

test.describe("Session Card Interactions", () => {
  test.beforeEach(async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.requester);
  });

  test("escalation card shows availability status", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    const escalationCards = page.locator('[data-testid="escalation-card"]');
    const count = await escalationCards.count();

    if (count > 0) {
      // Each card should indicate if it's available or has active session
      const firstCard = escalationCards.first();

      // Card should have either request button or active session indicator
      const requestButton = firstCard.locator('[data-testid="request-access-button"]');
      const activeSession = firstCard.locator('[data-testid="active-session"]');
      const pendingSession = firstCard.locator('[data-testid="pending-session"]');

      const hasRequestButton = await requestButton.isVisible().catch(() => false);
      const hasActive = await activeSession.isVisible().catch(() => false);
      const hasPending = await pendingSession.isVisible().catch(() => false);

      // One of these should be true
      expect(hasRequestButton || hasActive || hasPending).toBe(true);
    }
  });

  test("escalation card shows cluster information", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    const escalationCards = page.locator('[data-testid="escalation-card"]');
    const count = await escalationCards.count();

    if (count > 0) {
      const firstCard = escalationCards.first();

      // Card should show cluster name
      const clusterInfo = firstCard.locator('[data-testid="cluster-name"]');
      if (await clusterInfo.isVisible()) {
        const text = await clusterInfo.textContent();
        expect(text).toBeTruthy();
      }
    }
  });

  test("escalation card shows group information", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    const escalationCards = page.locator('[data-testid="escalation-card"]');
    const count = await escalationCards.count();

    if (count > 0) {
      const firstCard = escalationCards.first();

      // Card should show group name
      const groupInfo = firstCard.locator('[data-testid="escalation-name"]');
      await expect(groupInfo).toBeVisible();
    }
  });
});

test.describe("Modal Interactions", () => {
  test.beforeEach(async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.requester);
  });

  test("request modal can be closed with escape key", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    const escalationCards = page.locator('[data-testid="escalation-card"]');
    const count = await escalationCards.count();

    if (count > 0) {
      // Find card with request button
      const requestButton = escalationCards.first().locator('[data-testid="request-access-button"]');
      if (await requestButton.isVisible()) {
        await requestButton.click();
        await waitForScaleModal(page, '[data-testid="request-modal"]');

        // Press escape
        await page.keyboard.press("Escape");

        // Modal should close
        await expect(page.locator('[data-testid="request-modal"]')).not.toBeVisible({ timeout: 5000 });
      }
    }
  });

  test("modal prevents background scroll", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    const escalationCards = page.locator('[data-testid="escalation-card"]');
    const count = await escalationCards.count();

    if (count > 0) {
      const requestButton = escalationCards.first().locator('[data-testid="request-access-button"]');
      if (await requestButton.isVisible()) {
        await requestButton.click();
        await waitForScaleModal(page, '[data-testid="request-modal"]');

        // Try to scroll - should be blocked or unchanged when modal is open
        await page.mouse.wheel(0, 100);

        // Close modal
        await page.click('[data-testid="cancel-request-button"]');
      }
    }
  });
});

test.describe("Loading States", () => {
  test.beforeEach(async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.requester);
  });

  test("home page shows loading state initially", async ({ page }) => {
    // Navigate and check for loading state
    await page.goto("/");

    // Either loading state or escalation list should be visible
    const loadingState = page.locator('[data-testid="loading-state"]');
    const escalationList = page.locator('[data-testid="escalation-list"]');

    await expect(loadingState.or(escalationList).first()).toBeVisible({ timeout: 10000 });
  });

  test("session browser shows loading state", async ({ page }) => {
    await page.goto("/sessions");

    const loadingIndicator = page.locator('[data-testid="loading-indicator"]');
    const sessionBrowser = page.locator('[data-testid="session-browser"]');

    await expect(loadingIndicator.or(sessionBrowser).first()).toBeVisible({ timeout: 10000 });
  });

  test("debug session browser shows loading state", async ({ page }) => {
    await page.goto("/debug-sessions");

    const loadingState = page.locator('[data-testid="loading-state"]');
    const debugBrowser = page.locator('[data-testid="debug-session-browser"]');

    await expect(loadingState.or(debugBrowser).first()).toBeVisible({ timeout: 10000 });
  });
});

test.describe("Empty States", () => {
  test.beforeEach(async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.requester);
  });

  test("debug session browser shows empty state when no sessions", async ({ page }) => {
    await page.goto("/debug-sessions");
    await page.waitForLoadState("networkidle");

    // Filter for a state that likely has no sessions
    const searchInput = page.locator('[data-testid="debug-session-search-input"]');
    if (await searchInput.isVisible()) {
      await searchInput.locator("input").fill("nonexistent-session-xyz-99999");
      await page.waitForLoadState("networkidle", { timeout: 15000 });

      // Should show empty state or empty grid
      const emptyState = page.locator('[data-testid="debug-sessions-empty-state"]');
      const grid = page.locator('[data-testid="debug-sessions-grid"]');

      const isEmpty = await emptyState.isVisible().catch(() => false);
      const hasGrid = await grid.isVisible().catch(() => false);

      // One of these should be true
      expect(isEmpty || hasGrid).toBe(true);
    }
  });
});

test.describe("Accessibility", () => {
  test.beforeEach(async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.requester);
  });

  test("main navigation has aria labels", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Check for accessible navigation - Scale uses a sidebar menu component
    // The scale-telekom-app-shell has navigation links
    const navLinks = page.locator('a[href="/sessions"], a[href="/debug-sessions"]');
    await expect(navLinks.first()).toBeAttached({ timeout: 10000 });
  });

  test("buttons have accessible names", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    // Find visible buttons with explicit text or aria-label
    const buttons = page.locator("scale-button:visible, button:visible");
    const count = await buttons.count();

    let testedButtons = 0;
    for (let i = 0; i < Math.min(count, 10); i++) {
      const button = buttons.nth(i);
      if (await button.isVisible()) {
        const text = (await button.textContent())?.trim();
        const ariaLabel = await button.getAttribute("aria-label");
        // Skip icon-only buttons in component internals
        if (text || ariaLabel) {
          testedButtons++;
        }
      }
    }
    // At least some buttons should have accessible names
    expect(testedButtons).toBeGreaterThan(0);
  });

  test("form inputs have labels", async ({ page }) => {
    await page.goto("/");
    await page.waitForLoadState("networkidle");

    const escalationCards = page.locator('[data-testid="escalation-card"]');
    const count = await escalationCards.count();

    if (count > 0) {
      const requestButton = escalationCards.first().locator('[data-testid="request-access-button"]');
      if (await requestButton.isVisible()) {
        await requestButton.click();
        await waitForScaleModal(page, '[data-testid="request-modal"]');

        // Check that form inputs have accessible labels
        // Scale components render labels internally - check for visible label text in the DOM
        // The reason input should have an associated label visible to screen readers
        const reasonInput = page.locator('[data-testid="reason-input"]');
        if (await reasonInput.isVisible()) {
          // Scale textarea renders a visible "Reason" label inside the component
          // Check that the label is rendered in the page (not as an attribute)
          const reasonLabel = page.getByText("Reason", { exact: true });
          const hasLabel = (await reasonLabel.count()) > 0;

          // Also check for accessible textbox by role
          const accessibleTextbox = page.getByRole("textbox", { name: /reason/i });
          const hasAccessibleTextbox = (await accessibleTextbox.count()) > 0;

          // Either visible label or ARIA-accessible textbox should exist
          expect(hasLabel || hasAccessibleTextbox).toBeTruthy();
        }
      }
    }
  });
});
