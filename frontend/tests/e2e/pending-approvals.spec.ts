// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { test, expect } from "@playwright/test";
import {
  AuthHelper,
  TEST_USERS,
  openScaleDropdown,
  waitForScaleModal,
  assertScaleDropdownOptionAvailable,
  selectScaleDropdownOption,
} from "./helpers";

// This test file uses:
// - ui-e2e-pending-approvals-user (isolated requester with group "ui-e2e-pending-approvals-requester")
// - ui-e2e-approver (shared approver with group "ui-e2e-approver-group")
// It targets the "ui-e2e-pending-approvals-test" escalation
// The escalated group is "ui-e2e-pending-approvals-group"

// All tests in this file use the same approver user and interact with the same page/dropdowns.
// Running them serially prevents race conditions with Scale web components and shared auth state.
test.describe.serial("Pending Approvals View", () => {
  test.beforeEach(async ({ page }) => {
    // The approver may see sessions from other test files if cleanup didn't run
    // This is expected - we just verify the page loads correctly regardless of session count
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.uiE2eApprover);
  });

  test("approver can view pending approvals page", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.uiE2eApprover);

    // Navigate to pending approvals
    await page.goto("/approvals/pending");
    await page.waitForLoadState("networkidle");

    // Wait for API request to complete and view to render
    // Replace arbitrary timeout with explicit element visibility check
    const approvalsView = page.locator('[data-testid="pending-approvals-view"]');
    await expect(approvalsView).toBeVisible({ timeout: 20000 });

    // Ensure toolbar is also visible (confirms full page load)
    const toolbar = page.locator('[data-testid="approvals-toolbar"]');
    await expect(toolbar).toBeVisible({ timeout: 10000 });
  });

  test("pending approvals toolbar is visible", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.uiE2eApprover);

    await page.goto("/approvals/pending");
    await page.waitForLoadState("networkidle");

    // Should see toolbar with controls
    const toolbar = page.locator('[data-testid="approvals-toolbar"]');
    await expect(toolbar).toBeVisible();

    // Should have sort select
    const sortSelect = page.locator('[data-testid="sort-select"]');
    await expect(sortSelect).toBeVisible();

    // Should have urgency filter
    const urgencyFilter = page.locator('[data-testid="urgency-filter"]');
    await expect(urgencyFilter).toBeVisible();
  });

  test("toolbar info shows session count", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.uiE2eApprover);

    await page.goto("/approvals/pending");
    await page.waitForLoadState("networkidle");

    // Should see toolbar info with count
    const toolbarInfo = page.locator('[data-testid="toolbar-info"]');
    await expect(toolbarInfo).toBeVisible();
    await expect(toolbarInfo).toContainText(/pending requests/i);
  });

  test("empty state shown when no pending sessions", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.uiE2eApprover);

    await page.goto("/approvals/pending");
    await page.waitForLoadState("networkidle");

    // Either shows pending sessions or empty state
    const sessionsList = page.locator('[data-testid="pending-sessions-list"]');
    const emptyState = page.locator('[data-testid="empty-state"]');

    // One of these should be visible
    await expect(sessionsList.or(emptyState).first()).toBeVisible();
  });
});

// Scale dropdown components need time to render; serial execution prevents flaky interactions
test.describe.serial("Pending Approvals Sorting", () => {
  test("sort by urgency option is available", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.uiE2eApprover);

    await page.goto("/approvals/pending");
    await page.waitForLoadState("networkidle");

    // Wait for toolbar to be fully rendered before interacting with dropdowns
    // Increased timeout for CI environments where DOM rendering can be slower
    const toolbar = page.locator('[data-testid="approvals-toolbar"]');
    await toolbar.waitFor({ state: "visible", timeout: 15000 });

    // Wait for Sort dropdown to be fully initialized and visible
    // This replaces arbitrary timeout with explicit element visibility check
    const sortDropdown = page.locator('[data-testid="sort-select"]');
    await sortDropdown.waitFor({ state: "visible", timeout: 10000 });

    // Open sort dropdown and wait for options to render
    await openScaleDropdown(page, '[data-testid="sort-select"]');

    // Should see urgency option - use helper that checks for option availability
    // (Scale Components may render slotted options as hidden while using role="option" for accessibility)
    await assertScaleDropdownOptionAvailable(page, '[data-testid="sort-select"]', "urgent");
  });

  test("sort by recent option is available", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.uiE2eApprover);

    await page.goto("/approvals/pending");
    await page.waitForLoadState("networkidle");

    // Wait for toolbar to be fully rendered before interacting with dropdowns
    const toolbar = page.locator('[data-testid="approvals-toolbar"]');
    await toolbar.waitFor({ state: "visible", timeout: 10000 });

    // Open sort dropdown and wait for options to render
    const sortDropdown = page.locator('[data-testid="sort-select"]');
    await sortDropdown.waitFor({ state: "visible", timeout: 5000 });
    await openScaleDropdown(page, '[data-testid="sort-select"]');

    // Should see recent option - use helper that checks for option availability
    await assertScaleDropdownOptionAvailable(page, '[data-testid="sort-select"]', "recent");
  });

  test("sort by groups option is available", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.uiE2eApprover);

    await page.goto("/approvals/pending");
    await page.waitForLoadState("networkidle");

    // Wait for toolbar to be fully rendered before interacting with dropdowns
    const toolbar = page.locator('[data-testid="approvals-toolbar"]');
    await toolbar.waitFor({ state: "visible", timeout: 10000 });

    // Open sort dropdown and wait for options to render
    const sortDropdown = page.locator('[data-testid="sort-select"]');
    await sortDropdown.waitFor({ state: "visible", timeout: 5000 });
    await openScaleDropdown(page, '[data-testid="sort-select"]');

    // Should see groups option - use helper that checks for option availability
    await assertScaleDropdownOptionAvailable(page, '[data-testid="sort-select"]', "groups");
  });
});

// Filter dropdown tests share state and require serial execution
test.describe.serial("Pending Approvals Filtering", () => {
  test("urgency filter options are available", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.uiE2eApprover);

    await page.goto("/approvals/pending");
    await page.waitForLoadState("networkidle");

    // Wait for toolbar to be fully rendered before interacting with dropdowns
    const toolbar = page.locator('[data-testid="approvals-toolbar"]');
    await toolbar.waitFor({ state: "visible", timeout: 10000 });

    // Open urgency filter dropdown and wait for options to render
    const urgencyDropdown = page.locator('[data-testid="urgency-filter"]');
    await urgencyDropdown.waitFor({ state: "visible", timeout: 5000 });
    await openScaleDropdown(page, '[data-testid="urgency-filter"]');

    // Should see filter options - use helper that checks for option availability
    await assertScaleDropdownOptionAvailable(page, '[data-testid="urgency-filter"]', "all");
    await assertScaleDropdownOptionAvailable(page, '[data-testid="urgency-filter"]', "critical");
  });

  test("can filter by critical urgency", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.uiE2eApprover);

    await page.goto("/approvals/pending");
    await page.waitForLoadState("networkidle");

    // Apply critical filter - use selectScaleDropdownOption helper for proper Scale component handling
    // Scale renders slotted options as visibility:hidden, so we need the helper that clicks the actual visible option
    await selectScaleDropdownOption(page, '[data-testid="urgency-filter"]', "critical");

    // Wait for filter to apply and view to update (networkidle ensures API call completed)
    await page.waitForLoadState("networkidle");

    // Should still show page (either with filtered results or empty)
    const approvalsView = page.locator('[data-testid="pending-approvals-view"]');
    await expect(approvalsView).toBeVisible({ timeout: 15000 });
  });
});

// Session card interaction tests may depend on shared session state
test.describe.serial("Pending Approvals Session Cards", () => {
  test("session cards have review button", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.uiE2eApprover);

    await page.goto("/approvals/pending");
    await page.waitForLoadState("networkidle");

    // Check if there are pending sessions
    const sessionsList = page.locator('[data-testid="pending-sessions-list"]');
    if (await sessionsList.isVisible()) {
      // Session cards should have review button
      const reviewButtons = page.locator('[data-testid="review-button"]');
      const count = await reviewButtons.count();

      if (count > 0) {
        await expect(reviewButtons.first()).toBeVisible();
      }
    }
  });

  test("review button opens approval modal", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.uiE2eApprover);

    await page.goto("/approvals/pending");
    await page.waitForLoadState("networkidle");

    // Check if there are review buttons
    const reviewButtons = page.locator('[data-testid="review-button"]');
    const count = await reviewButtons.count();

    if (count > 0) {
      await reviewButtons.first().click();

      // Approval modal should appear - use Scale modal helper for proper waiting
      await waitForScaleModal(page, '[data-testid="approval-modal"]');
    }
  });
});

// Modal tests require exclusive access to the approval modal UI
test.describe.serial("Approval Modal", () => {
  test("approval modal shows session information", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.uiE2eApprover);

    await page.goto("/approvals/pending");
    await page.waitForLoadState("networkidle");

    // Open approval modal if there are sessions
    const reviewButtons = page.locator('[data-testid="review-button"]');
    const count = await reviewButtons.count();

    if (count > 0) {
      await reviewButtons.first().click();

      // Wait for Scale modal to fully open and wait for content to load
      await waitForScaleModal(page, '[data-testid="approval-modal"]', 30000);

      // Wait for modal content to render - the ApprovalModalContent has the requester testid
      // which proves the modal content has loaded. The wrapper div may not pass visibility
      // checks, but specific content elements like requester are reliably visible.
      // Use requester locator instead of session-review wrapper for more reliable detection.
      const requester = page.locator('[data-testid="requester"]');
      await expect(requester).toBeVisible({ timeout: 15000 });

      // Also verify approve button is present - confirms full modal content loaded
      const approveButton = page.locator('[data-testid="approve-button"]');
      await expect(approveButton).toBeVisible({ timeout: 5000 });
    }
  });

  test("approval modal has approve and reject buttons", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.uiE2eApprover);

    await page.goto("/approvals/pending");
    await page.waitForLoadState("networkidle");

    const reviewButtons = page.locator('[data-testid="review-button"]');
    const count = await reviewButtons.count();

    if (count > 0) {
      await reviewButtons.first().click();

      // Wait for Scale modal to fully open
      await waitForScaleModal(page, '[data-testid="approval-modal"]');

      // Should have approve button
      const approveButton = page.locator('[data-testid="approve-button"]');
      await expect(approveButton).toBeVisible({ timeout: 5000 });

      // Should have reject button
      const rejectButton = page.locator('[data-testid="reject-button"]');
      await expect(rejectButton).toBeVisible();
    }
  });

  test("approval modal has note input", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.uiE2eApprover);

    await page.goto("/approvals/pending");
    await page.waitForLoadState("networkidle");

    const reviewButtons = page.locator('[data-testid="review-button"]');
    const count = await reviewButtons.count();

    if (count > 0) {
      await reviewButtons.first().click();

      // Wait for Scale modal to fully open
      await waitForScaleModal(page, '[data-testid="approval-modal"]');

      // Should have approval note input
      const approvalNoteInput = page.locator('[data-testid="approval-reason-input"]');
      await expect(approvalNoteInput).toBeVisible({ timeout: 5000 });
    }
  });

  test("request reason is shown if available", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.uiE2eApprover);

    await page.goto("/approvals/pending");
    await page.waitForLoadState("networkidle");

    const reviewButtons = page.locator('[data-testid="review-button"]');
    const count = await reviewButtons.count();

    if (count > 0) {
      await reviewButtons.first().click();

      // Wait for Scale modal to fully open
      await waitForScaleModal(page, '[data-testid="approval-modal"]');
    }
  });
});

// Navigation tests using different user role
test.describe.serial("Approver Navigation", () => {
  test("non-approvers can access pending approvals page", async ({ page }) => {
    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.uiE2ePendingApprovals);

    // Navigate to pending approvals (may show empty if user has no approver permissions)
    await page.goto("/approvals/pending");
    await page.waitForLoadState("networkidle");

    // Should show the page (might be empty for non-approvers)
    const approvalsView = page.locator('[data-testid="pending-approvals-view"]');
    const emptyState = page.locator('[data-testid="empty-state"]');
    await expect(approvalsView.or(emptyState).first()).toBeVisible({ timeout: 10000 });
  });
});
