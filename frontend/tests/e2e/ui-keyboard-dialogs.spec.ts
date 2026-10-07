// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { test, expect, type Locator, type Page } from "@playwright/test";
import {
  AuthHelper,
  TEST_USERS,
  AUDIT_VIEWPORTS,
  findEscalationCardByName,
  waitForRouteSettled,
  waitForScaleToast,
  DEBUG_ACTIVE,
  DEBUG_PENDING,
  mockDebugSessions,
} from "./helpers";

/**
 * Keyboard-only checks for every dialog that uses the shared modal behaviour
 * (useModalBehavior), run against the production bundle served by the
 * controller on kind:
 *  - Enter on the opener opens the dialog and focus moves into it,
 *  - Tab and Shift+Tab cycle inside the dialog (both directions wrap) and reach
 *    controls inside shadow roots: the dialog's own close button and the
 *    native buttons of slotted Scale buttons,
 *  - Escape closes it and focus returns to the opener, or to the visible page
 *    heading when there is no opener (deep link) or the opener was removed.
 * No view opens a dialog on top of another one, so every check also asserts
 * that exactly one dialog is open; stacking is covered by the
 * useModalBehavior unit tests.
 *
 * The same file checks the controls whose accessible name comes from Scale's
 * `inner-aria-label`, and the skip link: names are read from the accessibility
 * tree (getByRole) and Enter must trigger the control's effect.
 *
 * Breakglass dialogs use real sessions (ui-e2e-a11y-user, ui-e2e-approver).
 * The kind fixtures auto-approve debug sessions and never run a debug pod, so
 * debug-session API responses are served by page.route(); the UI under test
 * is still the deployed bundle.
 */
const ESCALATION_NAME = "ui-e2e-a11y-group";
const HEADING_SELECTOR = "#main h1:not(.sr-only), #main h2:not(.sr-only)";
const REASON = "Keyboard dialog verification";
// Scale moves focus into dialogs that are already mounted at the end of its
// 200ms open transition; let that settle before walking the focus order.
const OPEN_TRANSITION_MS = 500;

/**
 * Describes the focused element including shadow roots, for example
 * `scale-modal[request-modal] > button.modal__close-button@close-button`.
 */
async function focusPath(page: Page): Promise<string> {
  return page.evaluate(() => {
    const parts: string[] = [];
    let el: Element | null = document.activeElement;
    while (el) {
      const testId = el.getAttribute("data-testid");
      const cls = typeof el.className === "string" ? el.className.split(" ").find(Boolean) : undefined;
      const part = el.getAttribute("part");
      parts.push(
        `${el.tagName.toLowerCase()}${testId ? `[${testId}]` : ""}${cls ? `.${cls}` : ""}${part ? `@${part}` : ""}`,
      );
      el = el.shadowRoot?.activeElement ?? null;
    }
    return parts.join(" > ");
  });
}

/** True when keyboard focus is on the element or inside it (including its shadow root). */
async function focusIsWithin(target: Locator): Promise<boolean> {
  return target.evaluate((host) => {
    const active = document.activeElement;
    return !!active && (host === active || host.contains(active));
  });
}

async function openDialogCount(page: Page): Promise<number> {
  return page.evaluate(
    () =>
      Array.from(document.querySelectorAll("scale-modal")).filter(
        (m) => (m as HTMLElement & { opened?: boolean }).opened,
      ).length,
  );
}

/** Puts keyboard focus on the native control inside a Scale host and presses Enter. */
async function pressEnterOn(control: Locator) {
  await control.locator("button, a").first().focus();
  await control.page().keyboard.press("Enter");
}

/** Presses the key until focus is back where it started; asserts focus never leaves the dialog. */
async function walkFocusCycle(page: Page, modal: Locator, key: "Tab" | "Shift+Tab"): Promise<string[]> {
  const start = await focusPath(page);
  const visited: string[] = [];
  for (let i = 0; i < 40; i++) {
    await page.keyboard.press(key);
    const path = await focusPath(page);
    expect(await focusIsWithin(modal), `${key} #${i + 1} left the dialog (focus on ${path})`).toBe(true);
    visited.push(path);
    if (path === start) return visited;
  }
  throw new Error(`${key} did not wrap back to ${start} within the dialog: ${visited.join(" | ")}`);
}

/** Focus is inside the dialog, which is the only open one, and it has the expected accessible name. */
async function expectDialogFocused(page: Page, modal: Locator, heading: string) {
  const dialog = modal.getByRole("dialog", { name: heading });
  await expect(dialog).toBeVisible();
  await expect.poll(() => focusIsWithin(modal), "focus should move into the dialog").toBe(true);
  expect(await openDialogCount(page)).toBe(1);
  await page.waitForTimeout(OPEN_TRANSITION_MS);
  expect(await focusIsWithin(modal), "focus should stay in the dialog after its open transition").toBe(true);
  return dialog;
}

/** Tab and Shift+Tab wrap inside the dialog and pass through controls in shadow roots. */
async function expectFocusTrapped(page: Page, modal: Locator) {
  const forward = await walkFocusCycle(page, modal, "Tab");
  const backward = await walkFocusCycle(page, modal, "Shift+Tab");
  expect(new Set(backward), "Shift+Tab should visit the same controls as Tab").toEqual(new Set(forward));
  expect(
    forward.some((p) => p.endsWith("@close-button")),
    `close button not reachable: ${forward.join(" | ")}`,
  ).toBe(true);
  expect(
    forward.some((p) => /^scale-button[^>]* > button/.test(p)),
    `no Scale button reachable: ${forward.join(" | ")}`,
  ).toBe(true);
}

/**
 * Opens a dialog from the keyboard, verifies focus-in and the focus trap,
 * closes it with Escape and checks focus is back on the opener.
 */
async function verifyDialogKeyboardCycle(page: Page, opener: Locator, modal: Locator, heading: string) {
  await expect(opener).toBeVisible();
  await pressEnterOn(opener);
  const dialog = await expectDialogFocused(page, modal, heading);
  await expectFocusTrapped(page, modal);

  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect.poll(() => focusIsWithin(opener), "Escape should return focus to the opener").toBe(true);
  expect(await openDialogCount(page)).toBe(0);
}

/** Focus is on the visible page heading and the heading is inside the viewport. */
async function expectFocusOnVisibleHeading(page: Page) {
  await expect
    .poll(() =>
      page.evaluate((selector) => {
        const active = document.activeElement as HTMLElement | null;
        if (!active?.matches(selector)) return `focus on ${active?.tagName ?? "nothing"}, not the page heading`;
        const r = active.getBoundingClientRect();
        return r.bottom > 0 && r.top < window.innerHeight ? "visible heading" : "heading off-screen";
      }, HEADING_SELECTOR),
    )
    .toBe("visible heading");
}

/** Tabs forward until the control with the test id (or a control inside it) has focus. */
async function tabTo(page: Page, target: Locator, maxPresses = 20) {
  for (let i = 0; i < maxPresses && !(await focusIsWithin(target)); i++) {
    await page.keyboard.press("Tab");
  }
  expect(await focusIsWithin(target), "keyboard focus should reach the control").toBe(true);
}

test.describe.serial("Keyboard verification: breakglass dialogs", () => {
  let sessionName = "";

  test("request dialog traps focus, closes with Escape and submits from the keyboard", async ({ page }) => {
    test.setTimeout(120_000);
    await new AuthHelper(page).loginViaKeycloak(TEST_USERS.uiE2eA11y);
    await page.goto("/");
    await waitForRouteSettled(page);

    const card = await findEscalationCardByName(page, ESCALATION_NAME, { requireAvailable: true });
    expect(card, `escalation card ${ESCALATION_NAME} should be requestable`).not.toBeNull();
    const opener = card!.locator('[data-testid="request-access-button"]');
    const modal = page.locator('[data-testid="request-modal"]');
    await verifyDialogKeyboardCycle(page, opener, modal, "Request breakglass");

    // Reopen and submit without the mouse; the session is used by the following tests.
    await pressEnterOn(opener);
    await expectDialogFocused(page, modal, "Request breakglass");
    await tabTo(page, modal.locator('[data-testid="reason-input"]'));
    await page.keyboard.type(REASON);
    await tabTo(page, modal.locator('[data-testid="submit-request-button"]'));
    await page.keyboard.press("Enter");
    await waitForScaleToast(page, "success-toast");
    await expect(modal).toHaveCount(0);
    // The toast's empty built-in link is hidden through Scale's `styles` prop.
    const toast = page.locator('[data-testid="success-toast"]').first();
    await expect(toast.getByRole("alert")).toBeVisible();
    await expect(toast.getByRole("link")).toHaveCount(0);

    await page.goto("/requests/mine");
    await waitForRouteSettled(page);
    const pendingCard = page.locator('[data-testid^="pending-request-card-"]').first();
    await expect(pendingCard).toBeVisible();
    sessionName = ((await pendingCard.getAttribute("data-testid")) ?? "").replace("pending-request-card-", "");
    expect(sessionName).not.toBe("");
  });

  test("withdraw dialog on My Pending Requests", async ({ page }) => {
    expect(sessionName, "previous test must have created a session").not.toBe("");
    await new AuthHelper(page).loginViaKeycloak(TEST_USERS.uiE2eA11y);
    await page.goto("/requests/mine");
    await waitForRouteSettled(page);

    const card = page.locator(`[data-testid="pending-request-card-${sessionName}"]`);
    await verifyDialogKeyboardCycle(
      page,
      card.locator('[data-testid="withdraw-button"]'),
      page.locator('[data-testid="withdraw-confirm-modal"]'),
      "Withdraw Request",
    );
    await expect(card).toBeVisible();
  });

  test("approval dialog, review dialog and deep-linked review dialog", async ({ page }) => {
    expect(sessionName, "previous test must have created a session").not.toBe("");
    await new AuthHelper(page).loginViaKeycloak(TEST_USERS.uiE2eApprover);

    await page.goto("/approvals/pending");
    await waitForRouteSettled(page);
    const pendingCard = page.locator(`[data-testid="pending-session-card-${sessionName}"]`);
    await verifyDialogKeyboardCycle(
      page,
      pendingCard.locator('[data-testid="review-button"]'),
      page.locator('[data-testid="approval-modal"]'),
      "Review Session",
    );

    // Info buttons named through inner-aria-label reveal their tooltip on keyboard focus.
    const info = pendingCard.getByRole("button", { name: "More info about Duration" });
    await expect(info).toBeVisible();
    await info.focus();
    await expect(pendingCard.getByRole("tooltip")).toHaveText("Maximum requested runtime");

    await page.goto("/sessions/review?approver=true");
    await waitForRouteSettled(page);
    // Pending sessions are hidden by "Active only"; clear it from the keyboard.
    await page.getByRole("checkbox", { name: "Active only" }).focus();
    await page.keyboard.press("Space");
    const reviewCard = page.locator('[data-testid="breakglass-session-card"]').filter({ hasText: sessionName });
    await verifyDialogKeyboardCycle(
      page,
      reviewCard.locator('[data-testid="review-button"]'),
      page.locator('[data-testid="review-modal"]'),
      "Review Session",
    );

    // The e-mail link opens the dialog directly, so there is no opener to return to.
    await page.goto(`/sessions/review?name=${encodeURIComponent(sessionName)}&approver=true`);
    const modal = page.locator('[data-testid="review-modal"]');
    const dialog = await expectDialogFocused(page, modal, "Review Session");
    await expectFocusTrapped(page, modal);
    await page.keyboard.press("Escape");
    await expect(dialog).toBeHidden();
    await expectFocusOnVisibleHeading(page);
  });

  test("Session Browser filter chips and withdraw dialog", async ({ page }) => {
    expect(sessionName, "previous test must have created a session").not.toBe("");
    await new AuthHelper(page).loginViaKeycloak(TEST_USERS.uiE2eA11y);
    await page.goto("/sessions");
    await waitForRouteSettled(page);

    // Pending sessions are not shown by default; include them from the keyboard.
    await page.locator('[data-testid="state-filter-pending"] input').focus();
    await page.keyboard.press("Space");
    await pressEnterOn(page.locator('[data-testid="apply-filters-button"]'));
    const row = page.locator('[data-testid="session-row"]').filter({ hasText: sessionName });
    await expect(row).toBeVisible({ timeout: 15000 });

    for (const field of ["cluster", "group"] as const) {
      const chip = row.getByRole("button", { name: new RegExp(`^Filter by ${field} \\S+$`) });
      await expect(chip).toBeVisible();
      // The visible label is slotted into the Scale host; the name must match it.
      const value = await chip.evaluate((button) =>
        ((button.getRootNode() as ShadowRoot).host?.textContent ?? "").trim(),
      );
      expect(value).not.toBe("");
      await expect(chip).toHaveAccessibleName(`Filter by ${field} ${value}`);
      await chip.focus();
      await page.keyboard.press("Enter");
      await expect(page.locator(`[data-testid="${field}-filter"] input`)).toHaveValue(value);
      await expect(row).toBeVisible();
    }

    const opener = row.locator('[data-testid="action-withdraw"]');
    const modal = page.locator('[data-testid="withdraw-confirm-modal"]');
    await verifyDialogKeyboardCycle(page, opener, modal, "Withdraw Request");

    // Confirming removes the opener, so focus falls back to the page heading.
    await pressEnterOn(opener);
    await expectDialogFocused(page, modal, "Withdraw Request");
    await tabTo(page, modal.locator('[data-testid="withdraw-confirm-btn"]'));
    await page.keyboard.press("Enter");
    await expect(row.locator('[data-testid="action-withdraw"]')).toHaveCount(0, { timeout: 15000 });
    await expectFocusOnVisibleHeading(page);
  });
});

for (const [viewportName, viewport] of Object.entries(AUDIT_VIEWPORTS)) {
  test.describe(`Keyboard verification: debug session dialogs [${viewportName}]`, () => {
    test.use({ viewport, permissions: ["clipboard-read", "clipboard-write"] });

    test.beforeEach(async ({ page }) => {
      await mockDebugSessions(page, TEST_USERS.uiE2eA11y.email);
      await new AuthHelper(page).loginViaKeycloak(TEST_USERS.uiE2eA11y);
    });

    test("renew and reject dialogs on the debug session cards", async ({ page }) => {
      await page.goto("/debug-sessions");
      await waitForRouteSettled(page);

      const refresh = page.getByRole("button", { name: "Refresh debug sessions" });
      await refresh.focus();
      const refreshed = page.waitForRequest((r) => /\/api\/debugSessions(\?|$)/.test(r.url()));
      await page.keyboard.press("Enter");
      await refreshed;

      const active = page.locator(`[data-testid="debug-session-card-${DEBUG_ACTIVE}"]`);
      await verifyDialogKeyboardCycle(
        page,
        active.locator('[data-testid="renew-button"]'),
        active.locator('[data-testid="renew-modal"]'),
        "Renew Debug Session",
      );
      const pending = page.locator(`[data-testid="debug-session-card-${DEBUG_PENDING}"]`);
      await verifyDialogKeyboardCycle(
        page,
        pending.locator('[data-testid="reject-button"]'),
        pending.locator('[data-testid="reject-modal"]'),
        "Reject Debug Session",
      );
    });

    test("renew dialog and copy button on the debug session details page", async ({ page }) => {
      await page.goto(`/debug-sessions/${DEBUG_ACTIVE}`);
      await waitForRouteSettled(page);
      await verifyDialogKeyboardCycle(
        page,
        page.locator('[data-testid="renew-session-button"]'),
        page.locator('[data-testid="renew-session-modal"]'),
        "Renew Session",
      );

      const copy = page.getByRole("button", { name: "Copy kubectl command to clipboard" });
      await copy.focus();
      await page.keyboard.press("Enter");
      await expect(page.getByRole("button", { name: "Command copied to clipboard" })).toBeVisible();
      expect(await page.evaluate(() => navigator.clipboard.readText())).toBe(
        "kubectl exec -it kbd-debug-pod -n breakglass-debug -- /bin/sh",
      );
    });

    test("reject dialog on the debug session details page", async ({ page }) => {
      await page.goto(`/debug-sessions/${DEBUG_PENDING}`);
      await waitForRouteSettled(page);
      await verifyDialogKeyboardCycle(
        page,
        page.locator('[data-testid="reject-session-button"]'),
        page.locator('[data-testid="reject-session-modal"]'),
        "Reject Session",
      );
    });
  });
}

test.describe("Keyboard verification: named icon buttons and skip link", () => {
  test.beforeEach(async ({ page }) => {
    await new AuthHelper(page).loginViaKeycloak(TEST_USERS.uiE2eA11y);
    await page.goto("/");
    await waitForRouteSettled(page);
  });

  test("skip link is named and moves focus to the main content", async ({ page }) => {
    const skipLink = page.getByRole("link", { name: "Skip to content" });
    // Route changes focus the page heading; walk back to the skip link like a keyboard user.
    for (let i = 0; i < 25 && !(await focusIsWithin(skipLink)); i++) {
      await page.keyboard.press("Shift+Tab");
    }
    await expect(skipLink).toBeFocused();
    await expect(skipLink).toBeInViewport();
    await page.keyboard.press("Enter");
    await expect(page).toHaveURL(/#main$/);
    expect(await page.evaluate(() => !!document.activeElement?.closest("#main"))).toBe(true);
  });

  test("header toggles and refresh button are named and work from the keyboard [desktop]", async ({ page }) => {
    await page.setViewportSize(AUDIT_VIEWPORTS.desktop);
    const html = page.locator("html");

    const initialTheme = (await html.getAttribute("data-theme")) === "dark" ? "dark" : "light";
    const nextTheme = initialTheme === "dark" ? "light" : "dark";
    const themeToggle = page.getByRole("button", {
      name: `${initialTheme === "dark" ? "Dark" : "Light"} theme selected. Click to select ${nextTheme} theme.`,
    });
    await themeToggle.focus();
    await page.keyboard.press("Enter");
    await expect(html).toHaveAttribute("data-theme", nextTheme);
    await expect(
      page.getByRole("button", {
        name: `${nextTheme === "dark" ? "Dark" : "Light"} theme selected. Click to select ${initialTheme} theme.`,
      }),
    ).toBeFocused();

    const contrastOff = page.getByRole("button", { name: "High contrast mode disabled. Click to enable." });
    await contrastOff.focus();
    await page.keyboard.press("Enter");
    await expect(html).toHaveAttribute("data-high-contrast", "true");
    const contrastOn = page.getByRole("button", { name: "High contrast mode enabled. Click to disable." });
    await expect(contrastOn).toBeFocused();
    await page.keyboard.press("Enter");
    await expect(html).not.toHaveAttribute("data-high-contrast", "true");

    const refresh = page.getByRole("button", { name: "Refresh escalations" });
    await refresh.focus();
    const refreshed = page.waitForRequest((r) => r.url().includes("/api/breakglassEscalations"));
    await page.keyboard.press("Enter");
    await refreshed;
  });

  test("mobile navigation trigger is named and opens the menu from the keyboard [mobile]", async ({ page }) => {
    await page.setViewportSize(AUDIT_VIEWPORTS.mobile);
    const trigger = page.getByRole("button", { name: "Open navigation menu" });
    await trigger.focus();
    await page.keyboard.press("Enter");
    await expect(page.getByRole("navigation", { name: "Mobile navigation" }).getByRole("link").first()).toBeVisible();
    await expect(page.getByRole("button", { name: "Close navigation menu" })).toBeAttached();
  });
});
