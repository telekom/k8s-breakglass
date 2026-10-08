// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { test, expect, type Page, type Route } from "@playwright/test";
import {
  DEBUG_ACTIVE,
  DEBUG_PENDING,
  LAYOUT_VIEWPORTS,
  findAlignmentProblems,
  findLayoutProblems,
  findVisualProblems,
  mockDebugSessions,
  mockLogin,
  mockNavigate,
  useAuditTheme,
  waitForScaleModal,
  type AuditTheme,
} from "./helpers";

/**
 * Generic layout audit against the mock dev server: every route, dialog,
 * menu and list state, at every layout viewport, in light, dark and high
 * contrast. The detectors (overlap, clipped text, horizontal scroll,
 * off-viewport content, row alignment, token gaps, separators, empty boxes,
 * icon sizes, card consistency) are page-agnostic, so new views are covered
 * without new assertions. Axe contrast for all three themes runs in a11y.spec.ts.
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
  "/session/unknown-session",
  "/session",
  "/does-not-exist",
];

const LIST_ROUTES = ["/", "/requests/mine", "/approvals/pending", "/sessions", "/sessions/review", "/debug-sessions"];

const DIALOGS: { name: string; path: string; opener: string; modal: string }[] = [
  {
    name: "request",
    path: "/",
    opener: '[data-testid="request-access-button"]',
    modal: '[data-testid="request-modal"]',
  },
  {
    name: "approval",
    path: "/approvals/pending",
    opener: '[data-testid="review-button"]',
    modal: '[data-testid="approval-modal"]',
  },
  {
    name: "withdraw",
    path: "/requests/mine",
    opener: '[data-testid="withdraw-button"]',
    modal: '[data-testid="withdraw-confirm-modal"]',
  },
  {
    name: "drop",
    path: "/requests/mine",
    opener: '[data-testid="drop-button"]',
    modal: '[data-testid="withdraw-confirm-modal"]',
  },
  {
    name: "debug card renew",
    path: "/debug-sessions",
    opener: `[data-testid="debug-session-card-${DEBUG_ACTIVE}"] [data-testid="renew-button"]`,
    modal: `[data-testid="debug-session-card-${DEBUG_ACTIVE}"] [data-testid="renew-modal"]`,
  },
  {
    name: "debug card reject",
    path: "/debug-sessions",
    opener: `[data-testid="debug-session-card-${DEBUG_PENDING}"] [data-testid="reject-button"]`,
    modal: `[data-testid="debug-session-card-${DEBUG_PENDING}"] [data-testid="reject-modal"]`,
  },
  {
    name: "debug details reject",
    path: `/debug-sessions/${DEBUG_PENDING}`,
    opener: '[data-testid="reject-session-button"]',
    modal: '[data-testid="reject-session-modal"]',
  },
  {
    name: "debug details renew",
    path: `/debug-sessions/${DEBUG_ACTIVE}`,
    opener: '[data-testid="renew-session-button"]',
    modal: '[data-testid="renew-session-modal"]',
  },
];

const MENUS: { name: string; path: string; opener: string; item: string; scope: string; maxWidth?: number }[] = [
  {
    name: "mobile navigation",
    path: "/",
    opener: "#mobile-nav-trigger",
    item: ".mobile-flyout-nav a",
    scope: "#mobile-nav-flyout",
    maxWidth: 1039,
  },
  {
    name: "profile",
    path: "/",
    opener: '[data-testid="user-menu"]',
    item: "text=Logout",
    scope: '[data-testid="user-menu"]',
  },
  {
    name: "approvals sort",
    path: "/approvals/pending",
    opener: '[data-testid="approvals-toolbar"] scale-dropdown-select',
    item: '[role="option"]',
    scope: '[data-testid="approvals-toolbar"]',
  },
  {
    name: "debug template",
    path: "/debug-sessions/create",
    opener: "#main scale-dropdown-select",
    item: '[role="option"]',
    scope: "#main",
  },
];

const API = /\/api\/(breakglassSessions|breakglassEscalations|debugSessions)(\?|$|\/)/;
const STATES: { name: string; handle: (route: Route) => Promise<void> }[] = [
  {
    name: "empty",
    handle: (route) => route.fulfill({ status: 200, contentType: "application/json", body: "[]" }),
  },
  {
    name: "error",
    handle: (route) =>
      route.fulfill({ status: 500, contentType: "application/json", body: '{"error":"Request failed"}' }),
  },
  {
    name: "stress",
    // The mock API repeats its data with long names when asked to scale up.
    handle: (route) => {
      const url = new URL(route.request().url());
      url.searchParams.set("mockScale", "60");
      return route.continue({ url: url.toString() });
    },
  },
];

async function prepare(page: Page, theme: AuditTheme) {
  await useAuditTheme(page, theme);
  await mockDebugSessions(page, "mock.user@breakglass.dev");
  await mockLogin(page);
}

async function audit(page: Page, context: string, scope = "body", ignore?: RegExp) {
  // Stencil keeps new Scale elements invisible until they hydrate; judge the settled UI.
  await page
    .waitForFunction(
      () =>
        // Stencil hydrates asynchronously; an element still waiting has no class attribute yet.
        Array.from(document.querySelectorAll("#app *")).every(
          (el) =>
            !el.tagName.startsWith("SCALE-") ||
            !customElements.get(el.tagName.toLowerCase()) ||
            el.classList.contains("hydrated"),
        ),
      null,
      { timeout: 5000 },
    )
    .catch(() => {}); // findVisualProblems names any element that never hydrates.
  const problems = [
    ...(await findLayoutProblems(page, scope)),
    ...(await findAlignmentProblems(page, scope)),
    ...(await findVisualProblems(page, scope)),
  ].filter((p) => !ignore?.test(p));
  expect.soft(problems, `layout problems on ${context}`).toEqual([]);
}

/** The deepest focused element is the opener or inside it. */
async function focusIsOn(page: Page, selector: string) {
  return page.evaluate((sel) => {
    let active: Element | null = document.activeElement;
    while (active?.shadowRoot?.activeElement) active = active.shadowRoot.activeElement;
    const hosts = Array.from(document.querySelectorAll(sel));
    for (let n = active; n; n = n.parentElement ?? ((n.getRootNode() as ShadowRoot).host || null)) {
      if (hosts.includes(n)) return true;
    }
    return false;
  }, selector);
}

for (const [viewportName, viewport] of Object.entries(LAYOUT_VIEWPORTS)) {
  test.describe(`Generic layout audit (mock) [${viewportName}]`, () => {
    test.use({ viewport });

    for (const theme of ["light", "dark", "hc"] as const) {
      test(`routes, dialogs and menus [${theme}]`, async ({ page }) => {
        test.setTimeout(240_000);
        await prepare(page, theme);
        const tag = `${viewportName} ${theme}`;

        for (const route of ROUTES) {
          await mockNavigate(page, route);
          await audit(page, `${route} [${tag}]`);
        }

        for (const d of DIALOGS) {
          await mockNavigate(page, d.path);
          await page.locator(d.opener).locator("visible=true").first().click();
          await waitForScaleModal(page, d.modal);
          await audit(page, `${d.name} dialog [${tag}]`, d.modal);
          await page.keyboard.press("Escape");
          await expect(page.locator(d.modal).first()).toBeHidden();
        }

        for (const m of MENUS) {
          if (m.maxWidth && viewport.width > m.maxWidth) continue;
          await mockNavigate(page, m.path);
          const opener = page.locator(m.opener).locator("visible=true").first();
          await opener.click();
          const item = page.locator(m.item).locator("visible=true");
          await expect(item.first(), `${m.name} menu opens [${tag}]`).toBeVisible();
          // An open menu covers the content below it by design.
          await audit(page, `${m.name} menu [${tag}]`, m.scope, /covered by (scale-dropdown-select|.*mobile-flyout)/);
          // Scale's flyout ignores keys for a few ms while it finishes opening.
          await page.waitForTimeout(100);
          await page.keyboard.press("Escape");
          await expect(item.first(), `${m.name} menu closes on Escape [${tag}]`).toBeHidden();
          await expect
            .poll(() => focusIsOn(page, m.opener), { message: `${m.name} menu returns focus [${tag}]`, timeout: 2000 })
            .toBe(true);
        }
      });
    }

    test("list pages in empty, error and stress states [light]", async ({ page }) => {
      test.setTimeout(240_000);
      await prepare(page, "light");
      for (const state of STATES) {
        for (const route of LIST_ROUTES) {
          await page.route(API, state.handle);
          // Leave the route first so the list reloads under the new mock.
          await mockNavigate(page, "/does-not-exist");
          await mockNavigate(page, route);
          await audit(page, `${route} ${state.name} [${viewportName}]`);
          await page.unroute(API, state.handle);
        }
      }
    });
  });
}
