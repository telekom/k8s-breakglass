// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { test, expect, type Page } from "@playwright/test";
import {
  AuthHelper,
  TEST_USERS,
  AUDIT_VIEWPORTS,
  expectCleanLayout,
  fillScaleTextarea,
  findEscalationCardByName,
  useAuditTheme,
  waitForRouteSettled,
  waitForScaleModal,
} from "./helpers";

/**
 * Visibility and functionality checks for every view at desktop (1440x900)
 * and mobile (390x844): each rendered control must fit the viewport, must not
 * be clipped or covered, truncated labels need a tooltip, and the primary
 * controls must be enabled when expected and actually do something.
 *
 * User: ui-e2e-a11y-user (escalation ui-e2e-a11y-test).
 */
const ESCALATION_NAME = "ui-e2e-a11y-group";

const ROUTES = [
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

async function openNavigation(page: Page, viewportName: string) {
  if (viewportName !== "mobile") return;
  const trigger = page.locator("#mobile-nav-trigger");
  await expect(trigger).toBeVisible();
  await trigger.click();
  await expect(trigger).toHaveAttribute("aria-expanded", "true");
}

// Scale's mobile flyout replaces the fallback nav once its custom elements are defined.
async function mobileNavSelector(page: Page): Promise<string> {
  const open = page.locator(".mobile-flyout-nav, #mobile-nav-fallback").locator("visible=true").first();
  await expect(open).toBeVisible();
  return (await open.getAttribute("id")) === "mobile-nav-fallback" ? "#mobile-nav-fallback" : ".mobile-flyout-nav";
}

async function navLink(page: Page, viewportName: string, label: string) {
  const scope =
    viewportName === "mobile" ? page.locator(await mobileNavSelector(page)) : page.locator("scale-telekom-header");
  return scope.getByRole("link", { name: label, exact: true }).locator("visible=true").first();
}

for (const [viewportName, viewport] of Object.entries(AUDIT_VIEWPORTS)) {
  test.describe(`UI layout and controls [${viewportName}]`, () => {
    test.beforeEach(async ({ page }) => {
      await page.setViewportSize(viewport);
      await useAuditTheme(page, "light");
      await new AuthHelper(page).loginViaKeycloak(TEST_USERS.uiE2eA11y);
    });

    test("every view keeps its controls visible, unclipped and unobstructed", async ({ page }) => {
      test.setTimeout(180_000);
      for (const route of ROUTES) {
        await page.goto(route);
        await waitForRouteSettled(page);
        await expectCleanLayout(page, `${route} [${viewportName}]`);
      }

      await page.goto("/");
      await waitForRouteSettled(page);
      await openNavigation(page, viewportName);
      if (viewportName === "mobile") {
        await expectCleanLayout(page, `mobile navigation`, await mobileNavSelector(page));
      }
    });

    test("primary navigation reaches every view", async ({ page }) => {
      const targets: Array<[string, RegExp]> = [
        ["Pending Approvals", /\/approvals\/pending$/],
        ["Review Sessions", /\/sessions\/review$/],
        ["My Requests", /\/requests\/mine$/],
        ["Session Browser", /\/sessions$/],
        ["Debug Sessions", /\/debug-sessions$/],
        ["Request Access", /\/$/],
      ];
      await page.goto("/");
      await waitForRouteSettled(page);

      for (const [label, url] of targets) {
        await openNavigation(page, viewportName);
        const link = await navLink(page, viewportName, label);
        await expect(link).toBeVisible();
        await link.click();
        await expect(page).toHaveURL(url);
        await waitForRouteSettled(page);
        if (viewportName === "mobile") {
          await expect(page.locator("#mobile-nav-trigger")).toHaveAttribute("aria-expanded", "false");
        }
      }
    });

    test("theme and contrast toggles switch the document theme", async ({ page }) => {
      await page.goto("/");
      await waitForRouteSettled(page);
      const html = page.locator("html");
      await expect(html).toHaveAttribute("data-theme", "light");

      await openNavigation(page, viewportName);
      const themeToggle =
        viewportName === "mobile"
          ? page.locator(`${await mobileNavSelector(page)} .mobile-util-btn`).first()
          : page.locator(".theme-toggle-button");
      await expect(themeToggle).toBeVisible();
      await themeToggle.click();
      await expect(html).toHaveAttribute("data-theme", "dark");

      if (viewportName === "mobile" && !(await themeToggle.isVisible())) {
        await openNavigation(page, viewportName);
      }
      await themeToggle.click();
      await expect(html).toHaveAttribute("data-theme", "light");

      if (viewportName !== "mobile") {
        await page.locator(".hc-toggle-button").click();
        await expect(html).toHaveAttribute("data-high-contrast", "true");
        await page.locator(".hc-toggle-button").click();
        await expect(html).not.toHaveAttribute("data-high-contrast", "true");
      }
    });

    test("escalation search, refresh and request dialog controls work", async ({ page }) => {
      await page.goto("/");
      await waitForRouteSettled(page);

      const card = await findEscalationCardByName(page, ESCALATION_NAME, { requireAvailable: true });
      expect(card, `escalation card ${ESCALATION_NAME} should be requestable`).not.toBeNull();

      if (viewportName === "mobile") {
        // Regression: the CTA text must not reserve a 320px tall blank area above the button.
        const cta = card!.locator(".breakglass-card__cta");
        const ctaBox = await cta.boundingBox();
        const textBox = await cta.locator("p").boundingBox();
        expect(ctaBox && textBox && ctaBox.height - textBox.height).toBeLessThan(16);
      }

      const refresh = page.locator('[data-testid="refresh-escalations-button"]');
      await expect(refresh).toBeVisible();
      const refreshed = page.waitForResponse((r) => /\/api\/breakglassEscalations/.test(r.url()) && r.ok());
      await refresh.click();
      await refreshed;

      const requestButton = card!.locator('[data-testid="request-access-button"]');
      await expect(requestButton).toBeVisible();
      await expect(requestButton).toBeEnabled();
      await requestButton.click();
      await waitForScaleModal(page, '[data-testid="request-modal"]');
      await expectCleanLayout(page, `request dialog [${viewportName}]`, '[data-testid="request-modal"]');

      const submit = page.locator('[data-testid="submit-request-button"]');
      await expect(submit).toHaveAttribute("disabled", /.*/);
      await fillScaleTextarea(page, '[data-testid="reason-input"]', "layout check");
      await expect(submit).not.toHaveAttribute("disabled", /.*/);

      await page.locator('[data-testid="cancel-request-button"]').click();
      await expect(page.locator('[data-testid="request-modal"]')).toHaveCount(0);

      const search = page.locator('[data-testid="escalation-search"] input');
      await search.fill("no-escalation-matches-this-query");
      await search.press("Enter");
      await expect(page.locator('[data-testid="toolbar-info"]')).toContainText(/Showing 0 of/);
      await expect(page.locator('[data-testid="escalation-card"]')).toHaveCount(0);
    });

    test("session browser filters apply and reset", async ({ page }) => {
      await page.goto("/sessions");
      await waitForRouteSettled(page);

      const nameFilter = page.locator('[data-testid="name-filter"] input');
      await nameFilter.fill("ui-e2e-a11y-no-such-session");
      await nameFilter.press("Tab");
      const apply = page.locator('[data-testid="apply-filters-button"]');
      await expect(apply).toBeEnabled();
      const fetched = page.waitForResponse((r) => /\/api\/breakglassSessions/.test(r.url()));
      await apply.click();
      await fetched;
      await expect(page.locator('[data-testid="empty-state"]')).toBeVisible();

      await page.locator('[data-testid="reset-filters-button"]').click();
      await expect(nameFilter).toHaveValue("");
    });

    test("debug session toolbar controls work", async ({ page }) => {
      await page.goto("/debug-sessions");
      await waitForRouteSettled(page);

      const refresh = page.locator('[data-testid="refresh-button"]');
      await expect(refresh).toBeVisible();
      const refreshed = page.waitForResponse((r) => /\/api\/debugSessions/.test(r.url()));
      await refresh.click();
      await refreshed;

      const create = page.locator('[data-testid="create-debug-session-button"]');
      await expect(create).toBeEnabled();
      await create.click();
      await expect(page).toHaveURL(/\/debug-sessions\/create$/);
      await waitForRouteSettled(page);
      await expectCleanLayout(page, `debug session create [${viewportName}]`);
    });
  });
}
