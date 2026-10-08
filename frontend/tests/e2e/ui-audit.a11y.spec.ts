// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { test, expect, type Page } from "@playwright/test";
import {
  DEBUG_ACTIVE,
  DEBUG_PENDING,
  LAYOUT_VIEWPORTS,
  expectAlignedActionRows,
  expectTooltipsOnHoverAndFocus,
  mockDebugSessions,
  mockLogin,
  mockNavigate,
  useAuditTheme,
  waitForScaleModal,
  type AuditTheme,
} from "./helpers";

/**
 * Alignment and tooltip audits against the mock dev server (Frontend Tests
 * job). The mock data contains every session state, so this covers more
 * button combinations than the kind fixtures; ui-alignment-tooltips.spec.ts
 * repeats the checks on the deployed bundle.
 */
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
  "/session/req-t-sec-1st-001/approve",
  "/session",
  "/does-not-exist",
];

type Audit = (page: Page, context: string, scope?: string) => Promise<unknown>;

async function auditDialog(page: Page, opener: string, modal: string, audit: Audit, context: string) {
  await page.locator(opener).locator("visible=true").first().click();
  await waitForScaleModal(page, modal);
  await audit(page, context, modal);
  await page.keyboard.press("Escape");
  await expect(page.locator(modal).first()).toBeHidden();
}

async function auditEverything(page: Page, name: string, audit: Audit) {
  for (const route of ROUTES) {
    await mockNavigate(page, route);
    await audit(page, `${route} [${name}]`);
  }

  await mockNavigate(page, "/");
  await auditDialog(
    page,
    '[data-testid="request-access-button"]',
    '[data-testid="request-modal"]',
    audit,
    `request dialog [${name}]`,
  );
  await mockNavigate(page, "/approvals/pending");
  // A request with a mandatory note: its confirm buttons start disabled with a reason.
  await auditDialog(
    page,
    '.approval-card-shell:has(scale-tag:has-text("Note required")) [data-testid="review-button"]',
    '[data-testid="approval-modal"]',
    audit,
    `approval dialog [${name}]`,
  );
  await mockNavigate(page, "/requests/mine");
  await auditDialog(
    page,
    '[data-testid="withdraw-button"]',
    '[data-testid="withdraw-confirm-modal"]',
    audit,
    `withdraw dialog [${name}]`,
  );
  await mockNavigate(page, "/debug-sessions");
  const active = `[data-testid="debug-session-card-${DEBUG_ACTIVE}"]`;
  const pending = `[data-testid="debug-session-card-${DEBUG_PENDING}"]`;
  await auditDialog(
    page,
    `${active} [data-testid="renew-button"]`,
    `${active} [data-testid="renew-modal"]`,
    audit,
    `debug card renew dialog [${name}]`,
  );
  await auditDialog(
    page,
    `${pending} [data-testid="reject-button"]`,
    `${pending} [data-testid="reject-modal"]`,
    audit,
    `debug card reject dialog [${name}]`,
  );
  await mockNavigate(page, `/debug-sessions/${DEBUG_PENDING}`);
  await auditDialog(
    page,
    '[data-testid="reject-session-button"]',
    '[data-testid="reject-session-modal"]',
    audit,
    `debug details reject dialog [${name}]`,
  );
}

async function prepare(page: Page, theme: AuditTheme) {
  await useAuditTheme(page, theme);
  await mockDebugSessions(page, "mock.user@breakglass.dev");
  await mockLogin(page);
}

for (const [viewportName, viewport] of Object.entries(LAYOUT_VIEWPORTS)) {
  test.describe(`UI alignment and tooltips (mock) [${viewportName}]`, () => {
    test.use({ viewport });

    for (const theme of ["light", "dark"] as const) {
      test(`buttons in action rows share a vertical centre and height [${theme}]`, async ({ page }) => {
        test.setTimeout(180_000);
        await prepare(page, theme);
        await auditEverything(page, `${viewportName} ${theme}`, expectAlignedActionRows);
      });
    }

    test("icon-only and disabled buttons show a tooltip on hover and on focus", async ({ page }) => {
      test.setTimeout(300_000);
      await prepare(page, "light");
      const counts: Record<string, number> = {};
      await auditEverything(page, viewportName, async (p, context, scope) => {
        counts[context] = await expectTooltipsOnHoverAndFocus(p, context, scope);
      });
      // Both kinds must be present: header/refresh icon buttons and reason-gated confirm buttons.
      expect(counts[`/debug-sessions [${viewportName}]`]).toBeGreaterThan(0);
      expect(counts[`request dialog [${viewportName}]`]).toBeGreaterThan(0);
      expect(counts[`approval dialog [${viewportName}]`]).toBeGreaterThan(0);
    });
  });
}
