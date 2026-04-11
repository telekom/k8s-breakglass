// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { test, expect, Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

/**
 * Accessibility E2E tests using axe-core.
 *
 * Runs automated WCAG 2.1 AA + AAA checks against key pages in four theme modes:
 * - Light mode (default)
 * - Dark mode (prefers-color-scheme: dark)
 * - High Contrast mode (data-high-contrast="true")
 * - High Contrast Dark mode (data-high-contrast="true" + data-theme="dark")
 *
 * Coverage includes:
 * - All primary authenticated pages
 * - Error pages (SessionErrorView, NotFoundView)
 * - Modal dialogs (approval, request, review, withdraw)
 *
 * These tests run against the mock dev server (Vite + mock-api).
 * They are intentionally NOT serial — each test is independent.
 *
 * Known Scale component issues (in shadow DOM, outside our control) are handled
 * with a two-pronged approach:
 *   1. `disableRules()` — suppress specific axe rules triggered by Scale's
 *      internal shadow-DOM rendering patterns (e.g. button-name, aria-prohibited-attr).
 *   2. `isScaleShadowDomNode()` — filter out shadow-DOM violation nodes at
 *      result-processing time so app light-DOM content in the header remains audited.
 */

/** Pages to audit with their paths and human-readable names. */
const PAGES_TO_AUDIT = [
  { path: "/", name: "Home" },
  { path: "/debug-sessions", name: "Debug Sessions" },
  { path: "/approvals/pending", name: "Pending Approvals" },
  { path: "/debug-sessions/create", name: "Debug Session Create" },
  { path: "/sessions", name: "Session Browser" },
  { path: "/requests/mine", name: "My Pending Requests" },
];

/**
 * Error pages — require mock authentication like all other pages because
 * App.vue only renders RouterView when authenticated.
 */
const ERROR_PAGES_TO_AUDIT = [
  { path: "/session", name: "Session Error (missing name)" },
  { path: "/session/test-session", name: "Session Error (incomplete URL)" },
  { path: "/this-page-does-not-exist", name: "Not Found (404)" },
];

/**
 * Modals to audit. Each entry describes how to reach the page containing
 * the modal and how to open it so axe can scan the dialog content.
 */
const MODALS_TO_AUDIT = [
  {
    name: "Approval Modal (Pending Approvals)",
    page: "/approvals/pending",
    openModal: async (page: Page) => {
      const reviewBtn = page.locator('[data-testid="review-button"]').first();
      await reviewBtn.waitFor({ state: "visible", timeout: 5000 });
      await reviewBtn.click();
      await page.waitForSelector('[data-testid="approval-modal"][opened].hydrated', {
        state: "attached",
        timeout: 5000,
      });
      await page.waitForTimeout(500);
    },
  },
  {
    name: "Request Modal (Home)",
    page: "/",
    openModal: async (page: Page) => {
      const requestBtn = page.locator('[data-testid="request-access-button"]').first();
      await requestBtn.waitFor({ state: "visible", timeout: 5000 });
      await requestBtn.click();
      await page.waitForSelector('[data-testid="request-modal"][opened].hydrated', {
        state: "attached",
        timeout: 5000,
      });
      await page.waitForTimeout(500);
    },
  },
  {
    name: "Review Modal (Session Review)",
    page: "/sessions/review",
    openModal: async (page: Page) => {
      // Uncheck "Active only" so pending sessions (with review buttons) appear
      const activeOnly = page.locator('scale-checkbox:has-text("Active only")');
      await activeOnly.waitFor({ state: "visible", timeout: 5000 });
      await activeOnly.click();
      await page.waitForTimeout(1000);
      const reviewBtn = page.locator('[data-testid="review-button"]').first();
      // Require the review button to exist so the modal audit is not silently skipped
      await reviewBtn.waitFor({ state: "visible", timeout: 5000 });
      await reviewBtn.click();
      await page.waitForSelector('[data-testid="review-modal"], [role="dialog"]', {
        state: "attached",
        timeout: 5000,
      });
      await page.waitForTimeout(500);
    },
  },
  {
    name: "Withdraw Modal (My Pending Requests)",
    page: "/requests/mine",
    openModal: async (page: Page) => {
      const withdrawBtn = page.locator('[data-testid="withdraw-button"]').first();
      await withdrawBtn.waitFor({ state: "visible", timeout: 5000 });
      await withdrawBtn.click();
      await page.waitForSelector('[role="dialog"], scale-modal[opened]', {
        state: "attached",
        timeout: 5000,
      });
      await page.waitForTimeout(500);
    },
  },
];

/** Theme modes to test. */
const THEME_MODES: Array<{
  name: string;
  setup: (page: Page) => Promise<void>;
  postLogin?: (page: Page) => Promise<void>;
}> = [
  {
    name: "light",
    setup: async (page: Page) => {
      await page.emulateMedia({ colorScheme: "light" });
    },
  },
  {
    name: "dark",
    setup: async (page: Page) => {
      await page.emulateMedia({ colorScheme: "dark" });
      await page.waitForTimeout(200);
    },
    postLogin: async (page: Page) => {
      await page.evaluate(() => {
        document.documentElement.setAttribute("data-theme", "dark");
        document.documentElement.setAttribute("data-mode", "dark");
      });
      await page.waitForTimeout(200);
    },
  },
  {
    name: "high-contrast",
    setup: async (page: Page) => {
      await page.emulateMedia({ colorScheme: "light" });
    },
    postLogin: async (page: Page) => {
      await page.evaluate(() => {
        document.documentElement.setAttribute("data-high-contrast", "true");
      });
      await page.waitForTimeout(200);
    },
  },
  {
    name: "high-contrast-dark",
    setup: async (page: Page) => {
      await page.emulateMedia({ colorScheme: "dark" });
    },
    postLogin: async (page: Page) => {
      await page.evaluate(() => {
        document.documentElement.setAttribute("data-high-contrast", "true");
        document.documentElement.setAttribute("data-theme", "dark");
        document.documentElement.setAttribute("data-mode", "dark");
      });
      await page.waitForTimeout(200);
    },
  },
];

/**
 * Axe rules disabled globally because they are triggered entirely by Scale's internal
 * shadow DOM structure — not by our application code.
 *
 * WHY GLOBAL DISABLE? We cannot use axe-core's `exclude` API because it would skip
 * auditing the light-DOM children of these components entirely, and we DO want to
 * audit our application's content inside them. Furthermore, some components like
 * `scale-button` are in our `fixableComponents` list for other rules, so we cannot
 * filter them out post-analysis without ignoring fixable violations too.
 *
 * Specific components triggering false positives:
 * - aria-required-children: scale-telekom-nav-list[role="menu"] contains
 *   [role="button"] triggers from Scale's profile-menu, which we cannot fix.
 * - button-name: scale-button[icon-only] renders a shadow-DOM <button>
 *   without propagating the host's aria-label, an upstream Scale limitation.
 * - aria-prohibited-attr: scale-button renders aria-label on elements whose
 *   implicit role forbids it — another Scale internal issue.
 */
const SCALE_DISABLED_RULES = ["aria-required-children", "button-name", "aria-prohibited-attr"];

/**
 * Telekom brand colours that are exempt from the AAA enhanced contrast rule
 * (color-contrast-enhanced, WCAG 2.1 SC 1.4.6, 7:1 ratio).
 *
 * Telekom magenta (#e20074) is the non-negotiable brand colour. On white it
 * achieves 4.68:1 (AA) but only 4.68:1 < 7:1 (fails AAA). This is an
 * explicit product decision: we keep the brand colour intact and accept AA
 * for elements that use it (nav links, primary buttons).
 *
 * All other AAA checks remain fully enforced.
 *
 * Colours are stored lower-cased and without leading '#' for easy matching
 * against axe's `message` strings (which report hex colours in various
 * formats).
 */
const TELEKOM_BRAND_COLORS_HEX = ["e20074", "f61488"];

async function performMockLogin(page: Page) {
  await page.goto("/");
  await page.waitForLoadState("networkidle");

  await page.waitForFunction(() => (window as unknown as Record<string, unknown>).__BREAKGLASS_AUTH !== undefined, {
    timeout: 10000,
  });

  await page.evaluate(() => {
    const auth = (window as unknown as Record<string, unknown>).__BREAKGLASS_AUTH as Record<string, unknown>;
    if (auth && typeof auth.login === "function") {
      auth.login({ path: "/", idpName: "production-keycloak" });
    }
  });

  await page.waitForTimeout(500);
  await page.waitForLoadState("networkidle");
  await page.waitForSelector("#main > :not(.login-gate)", { timeout: 5000 });
}

async function navigateTo(page: Page, path: string) {
  await page.evaluate((targetPath) => {
    const router = (window as unknown as Record<string, unknown>).__VUE_ROUTER__ as Record<string, unknown>;
    if (router && typeof router.push === "function") {
      router.push(targetPath);
    } else {
      window.history.pushState({}, "", targetPath);
      window.dispatchEvent(new PopStateEvent("popstate"));
    }
  }, path);

  await page.waitForTimeout(300);
  await page.waitForLoadState("networkidle");
}

/**
 * Check whether a violation node is inside a Scale shadow DOM subtree
 * that we CANNOT override via CSS.  We suppress these because the
 * rendering is entirely inside Scale's closed shadow DOM.
 *
 * Components we CAN fix (via ::part(base) CSS) are NOT suppressed:
 * scale-tag, scale-button, scale-checkbox, scale-dropdown.
 */
function isScaleShadowDomNode(node: { target: unknown; html: string }): boolean {
  const target = node.target as unknown[];
  const hasShadowSelector = Array.isArray(target) && target.some((t) => Array.isArray(t));
  const hasPartAttribute = node.html.includes('part="');
  if (!hasShadowSelector || !hasPartAttribute) return false;

  // Components we CAN fix via ::part(base) CSS — do NOT suppress these
  const fixableComponents = ["scale-tag", "scale-button", "scale-checkbox", "scale-dropdown"];
  const htmlLower = node.html.toLowerCase();
  if (fixableComponents.some((comp) => htmlLower.includes(comp))) {
    return false;
  }
  return true;
}

/**
 * Check whether a color-contrast-enhanced violation node involves a Telekom
 * brand colour.  Axe reports computed hex values in each check's `message`
 * and in the node's `failureSummary`.  We check both to reliably detect
 * brand-colour elements.
 */
function isBrandColorContrastNode(node: {
  failureSummary?: string;
  any: Array<{ message: string }>;
  all: Array<{ message: string }>;
  none: Array<{ message: string }>;
}): boolean {
  const checks = [...node.any, ...node.all, ...node.none];
  const texts = checks.map((c) => c.message.toLowerCase());
  if (node.failureSummary) texts.push(node.failureSummary.toLowerCase());
  return texts.some((t) => TELEKOM_BRAND_COLORS_HEX.some((hex) => t.includes(hex)));
}

/**
 * Run axe-core analysis and assert no critical/serious violations.
 * Shared by page, error page, and modal tests.
 */
async function assertNoA11yViolations(page: Page, context: string, mode: string) {
  const results = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag2aaa", "wcag22aaa"])
    .disableRules(SCALE_DISABLED_RULES)
    .analyze();

  const significantViolations = results.violations
    .filter((v) => v.impact === "critical" || v.impact === "serious")
    .map((v) => ({
      ...v,
      nodes: v.nodes.filter((n) => {
        if (isScaleShadowDomNode(n)) return false;
        // Exempt Telekom brand colours ONLY from the enhanced contrast rule (AAA)
        // They must still pass standard color-contrast (AA)
        if (v.id === "color-contrast-enhanced" && isBrandColorContrastNode(n)) return false;
        return true;
      }),
    }))
    .filter((v) => v.nodes.length > 0);

  if (significantViolations.length > 0) {
    const details = significantViolations
      .map((v) => {
        const nodes = v.nodes.map((n) => `    - ${n.html.substring(0, 120)}`).join("\n");
        return `  [${v.impact}] ${v.id}: ${v.description}\n${nodes}`;
      })
      .join("\n\n");

    expect(
      significantViolations.map((v) => v.id),
      `Found ${significantViolations.length} critical/serious a11y violation(s) on ${context} (${mode} mode):\n\n${details}`,
    ).toEqual([]);
  }
}

test.describe("Accessibility (axe-core WCAG 2.1 AA + AAA)", () => {
  for (const mode of THEME_MODES) {
    test.describe(`${mode.name} mode`, () => {
      // ── Primary authenticated pages ──────────────────────────────
      for (const pageInfo of PAGES_TO_AUDIT) {
        test(`${pageInfo.name} (${pageInfo.path}) has no critical/serious a11y violations [${mode.name}]`, async ({
          page,
        }) => {
          await mode.setup(page);

          await performMockLogin(page);
          await mode.postLogin?.(page);

          if (pageInfo.path !== "/") {
            await navigateTo(page, pageInfo.path);
          }

          await page.waitForLoadState("networkidle");
          await page.waitForTimeout(500);

          await assertNoA11yViolations(page, pageInfo.path, mode.name);
        });
      }

      // ── Error pages ──────────────────────────────────────────────
      for (const errorPage of ERROR_PAGES_TO_AUDIT) {
        test(`${errorPage.name} (${errorPage.path}) has no critical/serious a11y violations [${mode.name}]`, async ({
          page,
        }) => {
          await mode.setup(page);

          await performMockLogin(page);
          await mode.postLogin?.(page);

          await navigateTo(page, errorPage.path);

          await page.waitForLoadState("networkidle");
          await page.waitForTimeout(500);

          await assertNoA11yViolations(page, errorPage.path, mode.name);
        });
      }

      // ── Modal dialogs ────────────────────────────────────────────
      for (const modal of MODALS_TO_AUDIT) {
        test(`${modal.name} modal has no critical/serious a11y violations [${mode.name}]`, async ({ page }) => {
          await mode.setup(page);

          await performMockLogin(page);
          await mode.postLogin?.(page);

          if (modal.page !== "/") {
            await navigateTo(page, modal.page);
          }

          await page.waitForLoadState("networkidle");
          await page.waitForTimeout(500);

          await modal.openModal(page);
          await page.waitForTimeout(500);

          await assertNoA11yViolations(page, `${modal.name} on ${modal.page}`, mode.name);
        });
      }
    });
  }

  test.describe("High Contrast Toggle", () => {
    test("High contrast toggle persists and applies data attribute", async ({ page }) => {
      await performMockLogin(page);

      const toggleBtn = page.locator(".hc-toggle-button");
      await toggleBtn.waitFor({ state: "visible" });

      let isHighContrast = await page.evaluate(() => document.documentElement.getAttribute("data-high-contrast"));
      expect(isHighContrast).toBeNull();

      await toggleBtn.click();
      isHighContrast = await page.evaluate(() => document.documentElement.getAttribute("data-high-contrast"));
      expect(isHighContrast).toBe("true");

      await page.reload();
      await page.waitForLoadState("networkidle");
      isHighContrast = await page.evaluate(() => document.documentElement.getAttribute("data-high-contrast"));
      expect(isHighContrast).toBe("true");

      const toggleBtnAfterReload = page.locator(".hc-toggle-button");
      await toggleBtnAfterReload.waitFor({ state: "visible" });
      await toggleBtnAfterReload.click();
      isHighContrast = await page.evaluate(() => document.documentElement.getAttribute("data-high-contrast"));
      expect(isHighContrast).toBeNull();
    });
  });
});
