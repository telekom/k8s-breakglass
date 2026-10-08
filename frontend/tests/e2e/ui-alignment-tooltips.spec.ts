// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { test, expect, type Page } from "@playwright/test";
import {
  AuthHelper,
  TEST_USERS,
  DEBUG_ACTIVE,
  DEBUG_PENDING,
  LAYOUT_VIEWPORTS,
  expectAlignedActionRows,
  expectTooltipsOnHoverAndFocus,
  findAlignmentProblems,
  findEscalationCardByName,
  mockDebugSessions,
  useAuditTheme,
  waitForRouteSettled,
  waitForScaleModal,
} from "./helpers";

/**
 * Alignment and tooltip audits for every view and dialog at 390, 768, 1280
 * and 1920px, against the production bundle served by the controller on kind:
 *  - buttons in an action row (card, dialog and form footers, toolbars, the
 *    header utilities) share a vertical centre and Scale buttons of the same
 *    size have the same height,
 *  - every icon-only button and every disabled button shows a non-empty Scale
 *    tooltip on hover and on keyboard focus (disabled controls through their
 *    focusable DisabledReason wrapper).
 *
 * User: ui-e2e-a11y-user (escalation ui-e2e-a11y-group). Debug-session
 * responses are mocked as in the keyboard dialog checks so the card and detail
 * dialogs exist.
 */
const ESCALATION_NAME = "ui-e2e-a11y-group";

const ROUTES = [
  "/",
  "/requests/mine",
  "/approvals/pending",
  "/sessions",
  "/sessions/review",
  "/debug-sessions",
  "/debug-sessions/create",
  `/debug-sessions/${DEBUG_ACTIVE}`,
  `/debug-sessions/${DEBUG_PENDING}`,
  "/does-not-exist",
];

type Audit = (page: Page, context: string, scope?: string) => Promise<unknown>;

/** Opens a dialog, runs the audit on it and closes it with Escape. */
async function auditDialog(page: Page, opener: string, modal: string, audit: Audit, context: string) {
  await page.locator(opener).first().click();
  await waitForScaleModal(page, modal);
  await audit(page, context, modal);
  await page.keyboard.press("Escape");
  await expect(page.locator(modal).first()).toBeHidden();
}

/** Every route, then every dialog reachable with the mocked data, through the given audit. */
async function auditViewsAndDialogs(page: Page, viewportName: string, audit: Audit) {
  for (const route of ROUTES) {
    await page.goto(route);
    await waitForRouteSettled(page);
    await audit(page, `${route} [${viewportName}]`);
  }

  await page.goto("/");
  await waitForRouteSettled(page);
  const card = await findEscalationCardByName(page, ESCALATION_NAME, { requireAvailable: true });
  expect(card, `escalation card ${ESCALATION_NAME} should be requestable`).not.toBeNull();
  await card!.locator('[data-testid="request-access-button"]').click();
  await waitForScaleModal(page, '[data-testid="request-modal"]');
  await audit(page, `request dialog [${viewportName}]`, '[data-testid="request-modal"]');
  await page.locator('[data-testid="cancel-request-button"]').click();

  await page.goto("/debug-sessions");
  await waitForRouteSettled(page);
  const active = `[data-testid="debug-session-card-${DEBUG_ACTIVE}"]`;
  const pending = `[data-testid="debug-session-card-${DEBUG_PENDING}"]`;
  await auditDialog(
    page,
    `${active} [data-testid="renew-button"]`,
    `${active} [data-testid="renew-modal"]`,
    audit,
    `debug card renew dialog [${viewportName}]`,
  );
  await auditDialog(
    page,
    `${pending} [data-testid="reject-button"]`,
    `${pending} [data-testid="reject-modal"]`,
    audit,
    `debug card reject dialog [${viewportName}]`,
  );

  await page.goto(`/debug-sessions/${DEBUG_PENDING}`);
  await waitForRouteSettled(page);
  await auditDialog(
    page,
    '[data-testid="reject-session-button"]',
    '[data-testid="reject-session-modal"]',
    audit,
    `debug details reject dialog [${viewportName}]`,
  );
}

test("alignment audit reports off-centre controls and unequal button heights", async ({ page }) => {
  await page.setViewportSize(LAYOUT_VIEWPORTS.laptop);
  await page.setContent(`
    <div class="ui-actions" style="display: flex; align-items: flex-start; gap: 12px">
      <button style="height: 48px">Cancel</button>
      <button style="height: 32px">Confirm</button>
    </div>
    <div class="modal-actions" style="display: flex; align-items: center; gap: 12px">
      <button style="height: 40px">Back</button>
      <button style="height: 40px">Next</button>
    </div>`);
  const problems = await findAlignmentProblems(page);
  expect(problems).toHaveLength(1);
  expect(problems[0]).toContain("div.ui-actions: controls on one line are not vertically centred");
});

for (const [viewportName, viewport] of Object.entries(LAYOUT_VIEWPORTS)) {
  test.describe(`UI alignment and tooltips [${viewportName}]`, () => {
    test.use({ viewport });

    test.beforeEach(async ({ page }) => {
      await useAuditTheme(page, "light");
      await mockDebugSessions(page, TEST_USERS.uiE2eA11y.email);
      await new AuthHelper(page).loginViaKeycloak(TEST_USERS.uiE2eA11y);
    });

    test("buttons in action rows share a vertical centre and height", async ({ page }) => {
      test.setTimeout(240_000);
      await auditViewsAndDialogs(page, viewportName, expectAlignedActionRows);
    });

    test("icon-only and disabled buttons show a tooltip on hover and on focus", async ({ page }) => {
      test.setTimeout(300_000);
      const counts: Record<string, number> = {};
      await auditViewsAndDialogs(page, viewportName, async (p, context, scope) => {
        counts[context] = await expectTooltipsOnHoverAndFocus(p, context, scope);
      });
      // The fixtures guarantee both kinds: refresh/header icon buttons and the
      // reason-gated confirm buttons, which are disabled until a reason is entered.
      expect(counts[`/debug-sessions [${viewportName}]`]).toBeGreaterThan(0);
      expect(counts[`request dialog [${viewportName}]`]).toBeGreaterThan(0);
      expect(counts[`debug card reject dialog [${viewportName}]`]).toBeGreaterThan(0);
    });
  });
}
