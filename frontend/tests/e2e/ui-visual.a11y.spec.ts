// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { test, expect, type Page } from "@playwright/test";
import {
  DEBUG_ACTIVE,
  DEBUG_PENDING,
  LAYOUT_VIEWPORTS,
  mockDebugSessions,
  mockLogin,
  mockNavigate,
  useAuditTheme,
  waitForRouteSettled,
  waitForScaleModal,
} from "./helpers";

/**
 * Regression checks for the header, toast stack, dialog separators and list
 * filter panels against the mock dev server. Each one measures the rendered
 * geometry, so it fails on the defect itself rather than on a class name.
 */

// --space-md / --space-lg in src/assets/tokens.css
const SPACE_MD = 12;
const SPACE_LG = 16;

async function prepare(page: Page) {
  await useAuditTheme(page, "light");
  await mockDebugSessions(page, "mock.user@breakglass.dev");
  await mockLogin(page);
}

/** Header items with their vertical centre, plus truncated nav labels. */
async function measureHeader(page: Page) {
  return page.evaluate(() => {
    const header = document.querySelector("scale-telekom-header")!;
    const sr = header.shadowRoot!;
    const shown = (el: Element) => {
      const r = el.getBoundingClientRect();
      const s = getComputedStyle(el);
      return r.width > 0 && r.height > 0 && s.visibility !== "hidden" && s.display !== "none";
    };
    const centre = (r: DOMRect) => (r.top + r.bottom) / 2;
    const bar = sr.querySelector("[part~='fixed-wrapper']")!.getBoundingClientRect();
    const items: { name: string; centre: number }[] = [];
    const logo = sr.querySelector("[part~='app-logo']");
    if (logo) items.push({ name: "logo", centre: centre(logo.getBoundingClientRect()) });
    const appName = sr.querySelector("[part~='bottom-app-name'] [part~='app-name-text']");
    if (appName && shown(appName)) items.push({ name: "app name", centre: centre(appName.getBoundingClientRect()) });
    const truncated: string[] = [];
    let navCount = 0;
    for (const link of Array.from(header.querySelectorAll("[slot='main-nav'] scale-telekom-nav-item a"))) {
      if (!shown(link)) continue;
      navCount++;
      const label = (link.textContent || "").trim();
      const range = document.createRange();
      range.selectNodeContents(link);
      items.push({ name: `nav "${label}"`, centre: centre(range.getBoundingClientRect()) });
      const span = link.querySelector("span") ?? link;
      if (link.scrollWidth > link.clientWidth + 1 || span.scrollWidth > span.clientWidth + 1) truncated.push(label);
    }
    let controlCount = 0;
    const functions = header.querySelector("[slot='functions']");
    for (const ctl of Array.from(
      functions?.querySelectorAll(
        "scale-button, .scale-menu-trigger, .user-menu-mobile > button, [data-testid='mobile-menu-trigger']",
      ) ?? [],
    )) {
      if (!shown(ctl)) continue;
      controlCount++;
      const inner = ctl.tagName === "SCALE-BUTTON" ? (ctl.shadowRoot?.querySelector("button") ?? ctl) : ctl;
      const label = ctl.getAttribute("aria-label") || ctl.getAttribute("data-testid") || ctl.tagName.toLowerCase();
      items.push({ name: label, centre: centre(inner.getBoundingClientRect()) });
    }
    return { barCentre: centre(bar), items, truncated, navCount, controlCount };
  });
}

/** Horizontal rules inside an open dialog that do not span the dialog window. */
async function shortDialogSeparators(page: Page, modal: string) {
  return page.evaluate((sel) => {
    const host = document.querySelector(sel)!;
    const win = host.shadowRoot!.querySelector(".modal__window")!;
    const w = win.getBoundingClientRect();
    const ws = getComputedStyle(win);
    const left = w.left + parseFloat(ws.borderLeftWidth);
    const right = w.right - parseFloat(ws.borderRightWidth);
    const nodes: Element[] = [
      ...Array.from(host.shadowRoot!.querySelectorAll("*")),
      ...Array.from(host.querySelectorAll("*")),
    ];
    const problems: string[] = [];
    for (const el of nodes) {
      // Form controls draw their own outlines; only structural rules count.
      if (el.closest("scale-text-field, scale-textarea, scale-dropdown-select, scale-button, scale-checkbox")) continue;
      const s = getComputedStyle(el);
      const r = el.getBoundingClientRect();
      if (r.width === 0 || s.display === "none" || s.visibility === "hidden") continue;
      const sides = parseFloat(s.borderLeftWidth) > 0 || parseFloat(s.borderRightWidth) > 0;
      const rule = (side: "Top" | "Bottom") =>
        parseFloat(s[`border${side}Width`]) > 0 &&
        s[`border${side}Style`] !== "none" &&
        !/rgba\(.*, 0\)$/.test(s[`border${side}Color`]);
      if (sides || !(rule("Top") || rule("Bottom"))) continue;
      if (r.left > left + 1 || r.right < right - 1) {
        problems.push(
          `${el.tagName.toLowerCase()}.${String(el.className)} rule spans ${Math.round(r.left)}..${Math.round(
            r.right,
          )}, window ${Math.round(left)}..${Math.round(right)}`,
        );
      }
    }
    return problems;
  }, modal);
}

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

/** Geometry of every toast in the stack, top to bottom. */
async function measureToasts(page: Page) {
  return page.evaluate(() => {
    const bar = document
      .querySelector("scale-telekom-header")!
      .shadowRoot!.querySelector("[part~='fixed-wrapper']")!
      .getBoundingClientRect();
    // Accept any toast element so the check also measures older toast markup.
    const toasts = Array.from(document.querySelectorAll<HTMLElement>('[data-testid$="-toast"]')).map((t) => {
      const root = t.shadowRoot!;
      const base = (root.querySelector("[part~='base'], .notification-toast") ?? t).getBoundingClientRect();
      const heading = (
        root.querySelector("[part~='heading']") ?? t.querySelector("[slot='header']")!
      ).getBoundingClientRect();
      const body = t.querySelector("[slot='text'], [slot='body']")!;
      const text = body.getBoundingClientRect();
      return {
        top: base.top,
        bottom: base.bottom,
        left: base.left,
        right: base.right,
        padTop: heading.top - base.top,
        padBottom: base.bottom - text.bottom,
        heading: t.getAttribute("heading"),
        text: (body.textContent || "").trim(),
      };
    });
    return { headerBottom: bar.bottom, vw: document.documentElement.clientWidth, toasts };
  });
}

/** Line boxes of a filter panel and the gaps around them. */
async function measureToolbar(page: Page) {
  return page.evaluate(() => {
    const bar = document.querySelector<HTMLElement>("#main .ui-toolbar")!;
    const s = getComputedStyle(bar);
    const r = bar.getBoundingClientRect();
    const innerTop = r.top + parseFloat(s.borderTopWidth) + parseFloat(s.paddingTop);
    const innerBottom = r.bottom - parseFloat(s.borderBottomWidth) - parseFloat(s.paddingBottom);
    const children = Array.from(bar.children).filter((c) => {
      const cr = c.getBoundingClientRect();
      return cr.height > 0 && getComputedStyle(c).display !== "none";
    });
    // Group children into wrapped lines by overlapping vertical extent.
    const lines: { top: number; bottom: number; info: boolean }[] = [];
    for (const c of children.sort((a, b) => a.getBoundingClientRect().top - b.getBoundingClientRect().top)) {
      const cr = c.getBoundingClientRect();
      const info = c.classList.contains("ui-toolbar-info");
      const last = lines[lines.length - 1];
      if (last && cr.top < last.bottom - 1) {
        last.bottom = Math.max(last.bottom, cr.bottom);
        last.info ||= info;
      } else lines.push({ top: cr.top, bottom: cr.bottom, info });
    }
    const gaps = lines.slice(1).map((l, i) => ({ gap: l.top - lines[i].bottom, toInfo: l.info }));
    // Space left inside a field below its own content (a stretched, half-empty field).
    const slack = children.map((c) => {
      const cs = getComputedStyle(c);
      const contentBottom = Math.max(
        ...Array.from(c.querySelectorAll("*"))
          .map((d) => d.getBoundingClientRect())
          .filter((d) => d.height > 0)
          .map((d) => d.bottom),
      );
      const bottom = c.getBoundingClientRect().bottom - parseFloat(cs.paddingBottom) - parseFloat(cs.borderBottomWidth);
      return {
        field: (c.textContent || "").trim().slice(0, 24),
        slack: Number.isFinite(contentBottom) ? bottom - contentBottom : 0,
      };
    });
    return {
      slack,
      lead: lines[0].top - innerTop,
      trail: innerBottom - lines[lines.length - 1].bottom,
      gaps,
      hasInfo: lines.some((l) => l.info),
    };
  });
}

for (const [viewportName, viewport] of Object.entries(LAYOUT_VIEWPORTS)) {
  test.describe(`Visual regressions (mock) [${viewportName}]`, () => {
    test.use({ viewport });

    test("header: logo, app name, nav and controls share one centre; labels are not truncated", async ({ page }) => {
      await prepare(page);
      for (const path of ["/", "/debug-sessions"]) {
        await mockNavigate(page, path);
        // Scrolled and unscrolled header heights differ; both must line up.
        for (const scrolled of [false, true]) {
          await page.evaluate((y) => window.scrollTo(0, y), scrolled ? 400 : 0);
          await page.waitForTimeout(400);
          const m = await measureHeader(page);
          expect(m.controlCount, "header controls").toBeGreaterThanOrEqual(3);
          if (viewport.width >= 1040) expect(m.navCount, "desktop nav items").toBe(6);
          for (const item of m.items) {
            expect
              .soft(Math.abs(item.centre - m.barCentre), `${path} ${item.name} (scrolled=${scrolled})`)
              .toBeLessThanOrEqual(1);
          }
          expect.soft(m.truncated, `${path} truncated nav labels`).toEqual([]);
        }
      }
      if (viewport.width < 1040) {
        await page.evaluate(() => window.scrollTo(0, 0));
        await page.locator("#mobile-nav-trigger").locator("visible=true").first().click();
        const links = page.locator(".mobile-flyout-nav a").locator("visible=true");
        await expect(links).toHaveCount(6);
        const bad = await links.evaluateAll((els) =>
          els
            .filter((a) => {
              const r = a.getBoundingClientRect();
              return a.scrollWidth > a.clientWidth + 1 || r.right > document.documentElement.clientWidth + 1;
            })
            .map((a) => (a.textContent || "").trim()),
        );
        expect(bad, "truncated or clipped mobile menu items").toEqual([]);
      }
    });

    test("theme and contrast switches stay visible after every toggle", async ({ page }) => {
      await prepare(page);
      const html = page.locator("html");
      const mobile = viewport.width < 1040;
      const openMenu = async () => {
        const trigger = page.locator("#mobile-nav-trigger").locator("visible=true").first();
        if ((await trigger.getAttribute("aria-expanded")) !== "true") await trigger.click();
      };
      const toggles = mobile
        ? [".mobile-flyout-nav .mobile-util-btn >> nth=0", ".mobile-flyout-nav .mobile-util-btn--contrast"]
        : [".theme-toggle-button", ".hc-toggle-button"];
      // Light -> dark -> light, then contrast on -> off: each switch must remain clickable.
      for (const [selector, attr, values] of [
        [toggles[0], "data-theme", ["dark", "light"]],
        [toggles[1], "data-high-contrast", ["true", null]],
      ] as const) {
        for (const value of values) {
          if (mobile) await openMenu();
          const toggle = page.locator(selector);
          await expect(toggle, `${selector} before switching ${attr} to ${value}`).toBeVisible();
          await toggle.click();
          if (value === null) await expect(html).not.toHaveAttribute(attr, /.+/);
          else await expect(html).toHaveAttribute(attr, value);
          // Stencil hides Scale elements that lost their hydrated flag.
          const lost = await page.evaluate(() =>
            Array.from(document.querySelectorAll("#app [class]"))
              .filter((el) => el.tagName.startsWith("SCALE-") && !el.classList.contains("hydrated"))
              .map((el) => `${el.tagName.toLowerCase()}.${el.className}`),
          );
          expect(lost, `Scale elements without the hydrated flag after ${attr}=${value}`).toEqual([]);
        }
      }
    });

    test("toasts: one per failure, stacked below the header with token gaps and padding", async ({ page }) => {
      await prepare(page);
      // The interceptor and the view both report this failure; only one toast may show.
      await page.route(/\/api\/debugSessions(\?|$)/, (route) =>
        route.fulfill({ status: 500, contentType: "application/json", body: '{"error":"boom"}' }),
      );
      await mockNavigate(page, "/debug-sessions");
      await expect(page.locator('[data-testid="error-toast"]')).toHaveCount(1);
      await page.route(/\/api\/breakglassEscalations(\?|$)/, (route) =>
        route.fulfill({ status: 503, contentType: "application/json", body: '{"error":"down"}' }),
      );
      await page.evaluate(() =>
        (window as unknown as { __VUE_ROUTER__: { push: (p: string) => void } }).__VUE_ROUTER__.push("/"),
      );
      await waitForRouteSettled(page);
      await expect(page.locator('[data-testid="error-toast"]')).toHaveCount(2);
      await page.waitForTimeout(400);

      const m = await measureToasts(page);
      const texts = m.toasts.map((t) => t.text);
      expect(new Set(texts).size, `duplicate toasts: ${texts.join(" | ")}`).toBe(texts.length);
      expect(m.toasts[0].top - m.headerBottom, "gap below the header").toBeCloseTo(SPACE_LG, 0);
      for (const [i, t] of m.toasts.entries()) {
        expect(t.right, `toast ${i} right edge`).toBeCloseTo(m.vw - SPACE_LG, 0);
        expect(t.left, `toast ${i} left edge`).toBeGreaterThanOrEqual(SPACE_LG - 1);
        expect(t.padBottom, `toast ${i} bottom padding`).toBeGreaterThanOrEqual(12);
        expect(Math.abs(t.padBottom - t.padTop), `toast ${i} top/bottom padding`).toBeLessThanOrEqual(4);
        if (i > 0) expect(t.top - m.toasts[i - 1].bottom, `gap above toast ${i}`).toBeCloseTo(SPACE_MD, 0);
      }
    });

    test("dialogs: header and footer rules span the whole dialog window", async ({ page }) => {
      test.setTimeout(120_000);
      await prepare(page);
      // A short viewport makes the body scroll, which is when Scale draws its rules.
      for (const height of [viewport.height, 420]) {
        await page.setViewportSize({ width: viewport.width, height });
        for (const d of DIALOGS) {
          await mockNavigate(page, d.path);
          await page.locator(d.opener).locator("visible=true").first().click();
          await waitForScaleModal(page, d.modal);
          await page.waitForTimeout(300);
          expect(await shortDialogSeparators(page, d.modal), `${d.name} dialog at height ${height}`).toEqual([]);
          await page.keyboard.press("Escape");
          await expect(page.locator(d.modal).first()).toBeHidden();
        }
      }
    });

    test("filter panels are compact and the result count sits right under the controls", async ({ page }) => {
      await prepare(page);
      for (const path of ["/", "/approvals/pending", "/sessions/review", "/debug-sessions"]) {
        await mockNavigate(page, path);
        const m = await measureToolbar(page);
        expect.soft(m.hasInfo, `${path} result count inside the panel`).toBe(true);
        expect.soft(m.lead, `${path} space above the first row`).toBeLessThanOrEqual(1);
        expect.soft(m.trail, `${path} space below the last row`).toBeLessThanOrEqual(1);
        for (const f of m.slack) {
          expect.soft(f.slack, `${path} empty space inside "${f.field}"`).toBeLessThanOrEqual(1);
        }
        for (const g of m.gaps) {
          expect
            .soft(g.gap, `${path} gap between rows${g.toInfo ? " (result count)" : ""}`)
            .toBeLessThanOrEqual(SPACE_MD + 1);
        }
      }
    });
  });
}
