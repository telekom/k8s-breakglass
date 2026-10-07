// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { expect, type Page } from "@playwright/test";
import AxeBuilder from "@axe-core/playwright";

/** Viewports every UI audit runs at. */
export const AUDIT_VIEWPORTS = {
  desktop: { width: 1440, height: 900 },
  mobile: { width: 390, height: 844 },
} as const;

export type AuditViewport = keyof typeof AUDIT_VIEWPORTS;
export type AuditTheme = "light" | "dark";

export const AUDIT_THEMES: AuditTheme[] = ["light", "dark"];

/**
 * Persist the theme preference before any app script runs and emulate the
 * matching color scheme, so the first paint already uses the requested theme.
 */
export async function useAuditTheme(page: Page, theme: AuditTheme): Promise<void> {
  await page.addInitScript((value) => {
    window.localStorage.setItem("breakglass-theme", value);
    window.localStorage.removeItem("breakglass-high-contrast");
  }, theme);
  await page.emulateMedia({ colorScheme: theme });
}

/** Wait until the app shell has rendered the current route and pending requests settled. */
export async function waitForRouteSettled(page: Page): Promise<void> {
  await page.waitForLoadState("networkidle");
  await expect(page.locator("#main")).toBeVisible();
  // Loading placeholders are replaced by content or empty/error states.
  await expect(page.locator('#main .loading-state, #main [aria-busy="true"]')).toHaveCount(0, { timeout: 15000 });
}

/**
 * Run axe-core (WCAG 2.0/2.1/2.2 A + AA) and fail on serious or critical
 * violations. The report lists rule, impact, help text and offending targets
 * so failures are actionable without re-running locally.
 */
export async function expectNoSeriousA11yViolations(page: Page, context: string, include?: string): Promise<void> {
  let builder = new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21a", "wcag21aa", "wcag22aa"]);
  // Dialog checks are scoped to the dialog: the page behind it is dimmed by the
  // backdrop (aria-modal) and is audited separately without the dialog open.
  if (include) builder = builder.include(include);
  // Opacity transitions (dialog fade-in, toasts) would otherwise skew the contrast checks.
  // document.getAnimations() does not report animations inside shadow roots
  // (Scale modals fade in there), so collect those explicitly.
  await page.evaluate(() => {
    const animations = [...document.getAnimations()];
    const visit = (root: Document | ShadowRoot) => {
      for (const el of root.querySelectorAll("*")) {
        if (el.shadowRoot) {
          animations.push(...el.shadowRoot.getAnimations());
          visit(el.shadowRoot);
        }
      }
    };
    visit(document);
    return Promise.all(
      animations
        .filter((a) => a.playState === "running" && Number.isFinite(a.effect?.getComputedTiming().endTime ?? Infinity))
        .map((a) => a.finished.catch(() => undefined)),
    );
  });
  const results = await builder.analyze();

  const blocking = results.violations.filter((v) => v.impact === "serious" || v.impact === "critical");
  const report = blocking.map((v) => ({
    rule: v.id,
    impact: v.impact,
    help: v.help,
    targets: v.nodes.slice(0, 5).map((n) => JSON.stringify(n.target)),
  }));
  expect.soft(report, `axe serious/critical violations on ${context}`).toEqual([]);
}

/**
 * Audit every rendered interactive control (light DOM, including Scale hosts)
 * and return human-readable problems. A control is reported when it
 *  - cannot be brought fully into the viewport horizontally,
 *  - is clipped by an ancestor with hidden/clip/scroll overflow,
 *  - is covered by another element at its center point,
 *  - or the document itself overflows horizontally.
 * Truncated text (text-overflow: ellipsis that actually overflows) without a
 * title/aria-label tooltip is reported as well.
 *
 * Controls hidden on purpose (display:none, visibility:hidden, zero size,
 * aria-hidden subtrees, .sr-only and the skip link) are ignored.
 */
export async function findLayoutProblems(page: Page, scopeSelector = "body"): Promise<string[]> {
  return page.evaluate((scope) => {
    const problems: string[] = [];
    const root = document.querySelector(scope);
    if (!root) return [`scope ${scope} not found`];

    const vw = document.documentElement.clientWidth;
    const vh = window.innerHeight;
    if (document.documentElement.scrollWidth > vw + 1) {
      problems.push(`document overflows horizontally (${document.documentElement.scrollWidth}px > ${vw}px)`);
    }

    const selector = [
      "a[href]",
      "button",
      "input:not([type=hidden])",
      "select",
      "textarea",
      "[role=button]",
      "[role=link]",
      "[role=tab]",
      "[role=radio]",
      "[role=checkbox]",
      "scale-button",
      "scale-link",
      "scale-checkbox",
      "scale-switch",
      "scale-text-field",
      "scale-textarea",
      "scale-dropdown-select",
      "scale-telekom-profile-menu",
    ].join(",");

    const describe = (el: Element) => {
      const testId = el.getAttribute("data-testid");
      const label =
        el.getAttribute("inner-aria-label") ||
        el.getAttribute("aria-label") ||
        el.getAttribute("label") ||
        (el.textContent || "").trim().replace(/\s+/g, " ").slice(0, 40);
      return `${el.tagName.toLowerCase()}${testId ? `[data-testid=${testId}]` : ""}${label ? ` "${label}"` : ""}`;
    };

    const parentOf = (el: Element): Element | null =>
      el.parentElement ?? ((el.getRootNode() as ShadowRoot).host as Element | undefined) ?? null;

    const isIntentionallyHidden = (el: Element): boolean => {
      for (let node: Element | null = el; node; node = parentOf(node)) {
        const style = getComputedStyle(node);
        if (style.display === "none" || style.visibility === "hidden" || style.visibility === "collapse") return true;
        if (node.getAttribute("aria-hidden") === "true") return true;
        if (node.classList.contains("sr-only") || node.classList.contains("skip-link")) return true;
        if (node.tagName === "SCALE-MODAL" && !(node as HTMLElement & { opened?: boolean }).opened) return true;
      }
      const rect = el.getBoundingClientRect();
      return rect.width === 0 || rect.height === 0;
    };

    // Scale wraps native inputs inside its own components; audit the host instead.
    const insideScaleControl = (el: Element) =>
      !el.tagName.startsWith("SCALE-") &&
      !!el.parentElement?.closest(
        "scale-text-field, scale-textarea, scale-checkbox, scale-switch, scale-dropdown-select, scale-button, scale-link",
      );

    const controls = Array.from(root.querySelectorAll(selector)).filter(
      (el) => !insideScaleControl(el) && !isIntentionallyHidden(el),
    );

    for (const el of controls) {
      (el as HTMLElement).scrollIntoView({ block: "center", inline: "nearest", behavior: "instant" });
      const rect = el.getBoundingClientRect();
      const name = describe(el);

      if (rect.left < -1 || rect.right > vw + 1) {
        problems.push(
          `${name} is outside the viewport horizontally (${Math.round(rect.left)}..${Math.round(rect.right)} of ${vw})`,
        );
        continue;
      }

      let clipped = false;
      for (let anc = parentOf(el); anc && anc !== document.documentElement; anc = parentOf(anc)) {
        const style = getComputedStyle(anc);
        // A fixed container still clips its own content; only its ancestors don't.
        const isFixed = style.position === "fixed";
        const clips = [style.overflowX, style.overflowY].some((o) => o !== "visible");
        if (!clips) {
          if (isFixed) break;
          continue;
        }
        const a = anc.getBoundingClientRect();
        // Each axis is judged separately: overflow on an axis is fine if that axis
        // is visible, or if the container scrolls there and the control fits.
        const outX = style.overflowX !== "visible" && (rect.left < a.left - 1 || rect.right > a.right + 1);
        const outY = style.overflowY !== "visible" && (rect.top < a.top - 1 || rect.bottom > a.bottom + 1);
        const scrollsX =
          ["auto", "scroll"].includes(style.overflowX) && anc.scrollWidth > anc.clientWidth && rect.width <= a.width;
        const scrollsY =
          ["auto", "scroll"].includes(style.overflowY) &&
          anc.scrollHeight > anc.clientHeight &&
          rect.height <= a.height;
        if ((outX && !scrollsX) || (outY && !scrollsY)) {
          problems.push(`${name} is clipped by ${anc.tagName.toLowerCase()}.${(anc as HTMLElement).className || ""}`);
          clipped = true;
          break;
        }
        if (isFixed) break;
      }
      if (clipped) continue;

      if (rect.height <= vh) {
        const cx = Math.min(Math.max(rect.left + rect.width / 2, 0), vw - 1);
        const cy = Math.min(Math.max(rect.top + rect.height / 2, 0), vh - 1);
        const hit = document.elementFromPoint(cx, cy);
        const hitsSelf = hit && (hit === el || el.contains(hit) || (el.shadowRoot && el.shadowRoot.contains(hit)));
        // Labels and wrappers that forward clicks to the control count as the control.
        const hitsAncestorControl = hit && hit.contains(el) && (hit.tagName === "LABEL" || hit.closest("label"));
        if (!hitsSelf && !hitsAncestorControl) {
          problems.push(`${name} is covered by ${hit ? describe(hit) : "nothing (off-screen)"}`);
        }
      }
    }

    for (const el of Array.from(root.querySelectorAll<HTMLElement>("*"))) {
      if (isIntentionallyHidden(el)) continue;
      const style = getComputedStyle(el);
      if (style.textOverflow !== "ellipsis" || el.scrollWidth <= el.clientWidth + 1) continue;
      let hasTooltip = false;
      for (let node: Element | null = el; node && node !== root; node = parentOf(node)) {
        if (node.getAttribute("title") || node.getAttribute("aria-label")) {
          hasTooltip = true;
          break;
        }
      }
      if (!hasTooltip) {
        problems.push(`truncated text without tooltip: ${describe(el)}`);
      }
    }

    window.scrollTo({ top: 0, behavior: "instant" });
    return problems;
  }, scopeSelector);
}

/** Expect the layout audit for the given scope to find nothing. */
export async function expectCleanLayout(page: Page, context: string, scopeSelector = "body"): Promise<void> {
  const problems = await findLayoutProblems(page, scopeSelector);
  expect.soft(problems, `layout problems on ${context}`).toEqual([]);
}

/** Describe the element that currently has keyboard focus, piercing shadow roots. */
export async function focusedElementInfo(
  page: Page,
): Promise<{ testId: string | null; tag: string; inModal: boolean }> {
  return page.evaluate(() => {
    const outer = document.activeElement;
    let inner: Element | null = outer;
    while (inner && (inner as HTMLElement).shadowRoot?.activeElement) {
      inner = (inner as HTMLElement).shadowRoot!.activeElement;
    }
    let testId: string | null = null;
    for (let node: Element | null = outer; node && !testId; node = node.parentElement) {
      testId = node.getAttribute("data-testid");
    }
    return {
      testId,
      tag: (inner ?? outer)?.tagName.toLowerCase() ?? "",
      inModal: !!outer?.closest("scale-modal"),
    };
  });
}
