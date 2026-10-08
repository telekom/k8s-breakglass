// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { test, expect, type Locator } from "@playwright/test";
import {
  AuthHelper,
  TEST_USERS,
  expectDisabledWithReason,
  expectFocusOnPageHeading,
  expectModalDialog,
  expectSingleH1,
  expectTabOrderFollowsReadingOrder,
  findEscalationCardByName,
  focusedStop,
  waitForRouteSettled,
} from "./helpers";

/**
 * Screen-reader-equivalent checks on the deployed bundle (kind), read from
 * Playwright's accessibility tree, which includes Scale's shadow DOM. The mock
 * project (screen-reader.a11y.spec.ts) covers every dialog; this file proves
 * the production build behaves the same for the requester's main flow:
 * modal dialog semantics, the disabled-reason description, focus restore,
 * Tab order in reading order and focus on the page h1 after route changes.
 * It creates no sessions, so it does not interfere with the serial suites.
 */
const ESCALATION_NAME = "ui-e2e-a11y-group";

function focusIsWithin(host: Locator): Promise<boolean> {
  return host.evaluate(
    (el) => !!document.activeElement && (el === document.activeElement || el.contains(document.activeElement)),
  );
}

test.describe("Screen reader semantics (deployed UI)", () => {
  test.beforeEach(async ({ page }) => {
    await new AuthHelper(page).loginViaKeycloak(TEST_USERS.uiE2eA11y);
    await page.goto("/");
    await waitForRouteSettled(page);
  });

  test("request dialog is a named modal dialog that explains its disabled submit button", async ({ page }) => {
    const card = await findEscalationCardByName(page, ESCALATION_NAME, { requireAvailable: true });
    expect(card, `escalation card ${ESCALATION_NAME} should be requestable`).not.toBeNull();
    const opener = card!.locator('[data-testid="request-access-button"]');
    const modal = page.locator('[data-testid="request-modal"]');

    await opener.locator("button").focus();
    const openerStop = await focusedStop(page);
    expect(openerStop?.aria).toBe('button "Request access"');
    await page.keyboard.press("Enter");
    const dialog = await expectModalDialog(modal, "Request breakglass");
    await expect(dialog).toMatchAriaSnapshot(`
      - dialog "Request breakglass":
        - heading "Request breakglass" [level=2]
        - button "Close"
        - textbox "Duration"
        - textbox "Reason"
        - button "Cancel"
        - button "Confirm Request" [disabled]
    `);
    await expectDisabledWithReason(modal, "Confirm Request", "Enter a reason to submit the request.");

    await page.keyboard.press("Escape");
    await expect(dialog).toBeHidden();
    await expect.poll(() => focusIsWithin(opener), "Escape should return focus to the opener").toBe(true);
    expect((await focusedStop(page))?.aria).toBe(openerStop?.aria);
  });

  test("main navigation moves focus to the page h1 and each page has one h1", async ({ page }) => {
    for (const [link, heading] of [
      ["My Requests", "My Outstanding Requests"],
      ["Debug", "Debug Sessions"],
      ["Request", "Request access"],
    ]) {
      const item = page.getByRole("link", { name: link, exact: true }).filter({ visible: true }).first();
      await item.focus();
      await page.keyboard.press("Enter");
      await expect(page.getByRole("heading", { level: 1 })).toHaveText(heading);
      await waitForRouteSettled(page);
      await expectSingleH1(page, `${link} link`);
      await expectFocusOnPageHeading(page, `${link} link`);
      // My Requests may be empty depending on the suite order; the other pages always have controls.
      if (link !== "My Requests") await expectTabOrderFollowsReadingOrder(page, `${link} link`, { maxStops: 15 });
    }
  });
});
