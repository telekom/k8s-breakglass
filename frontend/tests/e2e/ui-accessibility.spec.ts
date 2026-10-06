// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { test, expect, type Page } from "@playwright/test";
import {
  AuthHelper,
  TEST_USERS,
  AUDIT_THEMES,
  AUDIT_VIEWPORTS,
  expectNoSeriousA11yViolations,
  findEscalationCardByName,
  focusedElementInfo,
  useAuditTheme,
  waitForRouteSettled,
  waitForScaleModal,
  waitForScaleToast,
} from "./helpers";

/**
 * Accessibility checks against the real stack (controller-served UI, Keycloak,
 * MailHog). Every view and dialog is scanned with axe-core at desktop and
 * mobile viewports in light and dark theme; serious/critical violations fail.
 * Keyboard-only operation of the primary request/review/withdraw flows is
 * verified as well (focus moves into dialogs, stays trapped, Escape closes and
 * focus returns to the trigger).
 *
 * Users: ui-e2e-a11y-user (requester, escalation ui-e2e-a11y-test) and the
 * shared ui-e2e-approver.
 */
const ESCALATION_NAME = "ui-e2e-a11y-group";

const REQUESTER_ROUTES = [
  "/",
  "/requests/mine",
  "/approvals/pending",
  "/sessions",
  "/debug-sessions",
  "/debug-sessions/create",
  "/session",
  "/session/ui-e2e-a11y-missing/approve",
  "/does-not-exist",
];

const APPROVER_ROUTES = ["/approvals/pending", "/sessions/review"];

async function openRequestDialogWithKeyboard(page: Page) {
  const card = await findEscalationCardByName(page, ESCALATION_NAME, { requireAvailable: true });
  expect(card, `escalation card ${ESCALATION_NAME} should be requestable`).not.toBeNull();
  // Focus the native button inside the Scale host, then activate it from the keyboard.
  await card!.locator('[data-testid="request-access-button"] button').focus();
  await page.keyboard.press("Enter");
  await waitForScaleModal(page, '[data-testid="request-modal"]');
  return card!;
}

/** Press Tab repeatedly and assert focus never leaves the open dialog. */
async function expectFocusTrappedInDialog(page: Page, presses = 12) {
  for (let i = 0; i < presses; i++) {
    await page.keyboard.press("Tab");
    const focus = await focusedElementInfo(page);
    expect(focus.inModal, `Tab #${i + 1} moved focus out of the dialog (now on ${focus.tag})`).toBe(true);
  }
}

/** Tab forward until the control with the given test id has focus. */
async function tabTo(page: Page, testId: string, maxPresses = 15) {
  for (let i = 0; i < maxPresses; i++) {
    if ((await focusedElementInfo(page)).testId === testId) return;
    await page.keyboard.press("Tab");
  }
  expect((await focusedElementInfo(page)).testId, `keyboard focus should reach ${testId}`).toBe(testId);
}

test.describe("UI accessibility: views", () => {
  for (const [viewportName, viewport] of Object.entries(AUDIT_VIEWPORTS)) {
    for (const theme of AUDIT_THEMES) {
      test(`requester views have no serious axe violations [${viewportName}/${theme}]`, async ({ page }) => {
        test.setTimeout(240_000);
        await page.setViewportSize(viewport);
        await useAuditTheme(page, theme);
        await new AuthHelper(page).loginViaKeycloak(TEST_USERS.uiE2eA11y);

        for (const route of REQUESTER_ROUTES) {
          await page.goto(route);
          await waitForRouteSettled(page);
          await expect(page.locator("html")).toHaveAttribute("data-theme", theme);
          await expectNoSeriousA11yViolations(page, `${route} [${viewportName}/${theme}]`);
        }

        // Header overlays: the mobile navigation flyout or the desktop profile menu.
        await page.goto("/");
        await waitForRouteSettled(page);
        if (viewportName === "mobile") {
          await page.locator("#mobile-nav-trigger").click();
          await expect(page.locator(".mobile-nav-fallback__link, .mobile-flyout-nav a").first()).toBeVisible();
          await expectNoSeriousA11yViolations(page, `mobile navigation [${theme}]`);
        } else {
          await page.locator('[data-testid="user-menu"]').click();
          await expect(page.getByText("Logout").first()).toBeVisible();
          await expectNoSeriousA11yViolations(page, `profile menu [${theme}]`);
        }
      });
    }
  }
});

test.describe.serial("UI accessibility: dialogs and keyboard flows", () => {
  let sessionName = "";

  test("skip link moves keyboard focus to the main content", async ({ page }) => {
    await new AuthHelper(page).loginViaKeycloak(TEST_USERS.uiE2eA11y);
    await page.goto("/");
    await waitForRouteSettled(page);

    // Route changes move focus to the page heading in #main, so walk back to the skip link
    // through the header the way a keyboard user would.
    const skipLink = page.locator("a.skip-link");
    for (let i = 0; i < 20 && !(await skipLink.evaluate((el) => el === document.activeElement)); i++) {
      await page.keyboard.press("Shift+Tab");
    }
    await expect(skipLink).toBeFocused();
    await expect(skipLink).toBeInViewport();

    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(/#main$/);
    const focusInMain = await page.evaluate(() => !!document.activeElement?.closest("#main"));
    expect(focusInMain, "focus should land inside #main after activating the skip link").toBe(true);
  });

  for (const [viewportName, viewport] of Object.entries(AUDIT_VIEWPORTS)) {
    test(`request dialog is keyboard operable and accessible [${viewportName}]`, async ({ page }) => {
      test.setTimeout(120_000);
      await page.setViewportSize(viewport);
      await new AuthHelper(page).loginViaKeycloak(TEST_USERS.uiE2eA11y);
      await page.goto("/");
      await waitForRouteSettled(page);

      await openRequestDialogWithKeyboard(page);
      await expect.poll(async () => (await focusedElementInfo(page)).inModal).toBe(true);
      await expectNoSeriousA11yViolations(page, `request dialog [${viewportName}]`, '[data-testid="request-modal"]');
      await expectFocusTrappedInDialog(page);

      // The submit button stays disabled until a reason is given.
      await page.locator('[data-testid="reason-input"] textarea').fill("");
      await expect(page.locator('[data-testid="submit-request-button"]')).toHaveAttribute("disabled", /.*/);

      await page.keyboard.press("Escape");
      await expect(page.locator('[data-testid="request-modal"]')).toHaveCount(0);
      expect((await focusedElementInfo(page)).testId).toBe("request-access-button");
    });
  }

  test("requester can submit a request using only the keyboard", async ({ page }) => {
    await new AuthHelper(page).loginViaKeycloak(TEST_USERS.uiE2eA11y);
    await page.goto("/");
    await waitForRouteSettled(page);

    const card = await openRequestDialogWithKeyboard(page);
    await expect.poll(async () => (await focusedElementInfo(page)).inModal).toBe(true);
    await tabTo(page, "reason-input");
    await page.keyboard.type("Keyboard-only accessibility check");
    await expect(page.locator('[data-testid="reason-input"] textarea')).toHaveValue(
      "Keyboard-only accessibility check",
    );
    await tabTo(page, "submit-request-button");
    await page.keyboard.press("Enter");

    await waitForScaleToast(page, "success-toast");
    await expectNoSeriousA11yViolations(page, "request success toast");
    await expect(card.locator('[data-testid="withdraw-button"]')).toBeVisible();
    // The list refresh replaces the trigger; keyboard focus must stay anchored in the page.
    await expect
      .poll(() => page.evaluate(() => document.getElementById("main")?.contains(document.activeElement) ?? false))
      .toBe(true);

    await page.goto("/requests/mine");
    await waitForRouteSettled(page);
    const pendingCard = page.locator('[data-testid^="pending-request-card-"]').first();
    await expect(pendingCard).toBeVisible();
    const testId = await pendingCard.getAttribute("data-testid");
    sessionName = (testId ?? "").replace("pending-request-card-", "");
    expect(sessionName).not.toBe("");
  });

  test("approver review dialog and approval link page are accessible", async ({ page }) => {
    expect(sessionName, "previous test must have created a session").not.toBe("");
    await new AuthHelper(page).loginViaKeycloak(TEST_USERS.uiE2eApprover);

    for (const route of APPROVER_ROUTES) {
      await page.goto(route);
      await waitForRouteSettled(page);
      await expectNoSeriousA11yViolations(page, `${route} (approver)`);
    }

    await page.goto("/approvals/pending");
    await waitForRouteSettled(page);
    const reviewButton = page.locator(
      `[data-testid="pending-session-card-${sessionName}"] [data-testid="review-button"] button`,
    );
    await reviewButton.focus();
    await page.keyboard.press("Enter");
    await waitForScaleModal(page, '[data-testid="approval-modal"]');
    await expect.poll(async () => (await focusedElementInfo(page)).inModal).toBe(true);
    await expectNoSeriousA11yViolations(page, "approval dialog", '[data-testid="approval-modal"]');
    await expectFocusTrappedInDialog(page);
    await page.keyboard.press("Escape");
    await expect(page.locator('[data-testid="approval-modal"]')).toHaveCount(0);
    expect((await focusedElementInfo(page)).testId).toBe("review-button");

    // Page reached from the approval e-mail link.
    await page.goto(`/session/${sessionName}/approve`);
    await waitForRouteSettled(page);
    await expect(page.locator("#main")).toContainText(TEST_USERS.uiE2eA11y.email);
    await expect(page.locator("#main")).toContainText("Keyboard-only accessibility check");
    await expectNoSeriousA11yViolations(page, "e-mail approval page");
  });

  test("requester can withdraw the request from the keyboard", async ({ page }) => {
    expect(sessionName, "previous test must have created a session").not.toBe("");
    await new AuthHelper(page).loginViaKeycloak(TEST_USERS.uiE2eA11y);
    await page.goto("/requests/mine");
    await waitForRouteSettled(page);

    const card = page.locator(`[data-testid="pending-request-card-${sessionName}"]`);
    await card.locator('[data-testid="withdraw-button"] button').focus();
    await page.keyboard.press("Enter");
    await waitForScaleModal(page, '[data-testid="withdraw-confirm-modal"]');
    await expect.poll(async () => (await focusedElementInfo(page)).inModal).toBe(true);
    await expectNoSeriousA11yViolations(page, "withdraw dialog", '[data-testid="withdraw-confirm-modal"]');

    await tabTo(page, "withdraw-confirm-btn");
    await page.keyboard.press("Enter");
    await expect(card).toHaveCount(0, { timeout: 15000 });
  });
});
