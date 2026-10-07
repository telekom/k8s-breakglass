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

/** Breakpoints of the alignment and tooltip audits: mobile, tablet, laptop and desktop. */
export const LAYOUT_VIEWPORTS = {
  mobile: { width: 390, height: 844 },
  tablet: { width: 768, height: 1024 },
  laptop: { width: 1280, height: 800 },
  desktop: { width: 1920, height: 1080 },
} as const;

/**
 * Wait until finite CSS transitions/animations have finished and the content of
 * an open dialog has become visible (dialog content fades in after opening).
 */
async function settleAnimations(page: Page): Promise<void> {
  await page
    .waitForFunction(
      () => {
        const running = document
          .getAnimations()
          .some((a) => a.playState === "running" && a.effect?.getTiming().iterations !== Infinity);
        const openModal = Array.from(document.querySelectorAll("scale-modal")).find(
          (m) => (m as HTMLElement & { opened?: boolean }).opened,
        );
        const modalHidden =
          !!openModal && Array.from(openModal.children).some((c) => getComputedStyle(c).visibility === "hidden");
        return !running && !modalHidden;
      },
      null,
      { timeout: 5000 },
    )
    .catch(() => undefined);
}

/**
 * Check every visible row of controls: controls rendered on the same line of a
 * row must share a vertical centre (±1px), and Scale buttons of the same size
 * and kind (text or icon-only) must have the same height (±1px) within a row.
 *
 * Rows are discovered from the layout rather than from class names, so new
 * views are covered automatically: a control's row is the nearest flex-row or
 * grid ancestor that holds at least two controls, reached only through inline
 * wrappers (tooltips, DisabledReason, `display: contents`). Block and
 * column containers end the search, so separate cards are never compared.
 * Sizes are read from the rendered control inside Scale's shadow root, which
 * is what users see; the host element can be taller or shorter than that.
 */
export async function findAlignmentProblems(page: Page, scopeSelector = "body"): Promise<string[]> {
  await settleAnimations(page);
  return page.evaluate((scope) => {
    const problems: string[] = [];
    const root = document.querySelector(scope);
    if (!root) return [`scope ${scope} not found`];

    const parentOf = (el: Element): Element | null =>
      el.parentElement ?? ((el.getRootNode() as ShadowRoot).host as Element | undefined) ?? null;
    const hidden = (el: Element): boolean => {
      for (let node: Element | null = el; node; node = parentOf(node)) {
        const style = getComputedStyle(node);
        if (style.display === "none" || style.visibility === "hidden") return true;
        if (node.getAttribute("aria-hidden") === "true" || node.classList.contains("sr-only")) return true;
        if (node.tagName === "SCALE-MODAL" && !(node as HTMLElement & { opened?: boolean }).opened) return true;
      }
      const r = el.getBoundingClientRect();
      return r.width === 0 || r.height === 0;
    };
    const label = (el: Element) =>
      el.getAttribute("data-testid") ||
      el.getAttribute("inner-aria-label") ||
      el.getAttribute("label") ||
      (el.textContent || "").trim().replace(/\s+/g, " ").slice(0, 30) ||
      el.tagName.toLowerCase();
    const rowName = (row: Element) => {
      const testid = row.getAttribute("data-testid");
      const name = `${row.tagName.toLowerCase()}${testid ? `[data-testid=${testid}]` : ""}${Array.from(row.classList)
        .map((c) => `.${c}`)
        .join("")}`;
      const modal = row.closest("scale-modal");
      return modal ? `${name} in ${modal.getAttribute("data-testid") ?? "dialog"}` : name;
    };
    const isIconOnly = (el: Element) => el.hasAttribute("icon-only") && el.getAttribute("icon-only") !== "false";
    // The box users see: Scale renders the real control inside its shadow or light DOM.
    const box = (el: Element) => {
      const inner =
        el.tagName === "SCALE-BUTTON"
          ? el.shadowRoot?.querySelector("button, a")
          : el.tagName === "SCALE-TEXT-FIELD"
            ? el.querySelector("input")
            : el.tagName === "SCALE-DROPDOWN-SELECT"
              ? el.shadowRoot?.querySelector("[part~='combobox-container']")
              : null;
      return (inner ?? el).getBoundingClientRect();
    };

    const controls = Array.from(
      root.querySelectorAll(
        "scale-button, scale-text-field, scale-dropdown-select, button, a.ui-link-button, a[role='button']",
      ),
    ).filter(
      (el) =>
        !hidden(el) &&
        // Native buttons inside Scale hosts are measured through the host.
        !(el.tagName === "BUTTON" && parentOf(el)?.closest("scale-button, scale-text-field, scale-dropdown-select")),
    );
    const controlSet = new Set(controls);
    const countControls = (el: Element) => controls.filter((c) => c !== el && el.contains(c)).length;

    const rowOf = (control: Element): Element | null => {
      const controlHeight = box(control).height;
      for (let node = parentOf(control); node && node !== document.documentElement; node = parentOf(node)) {
        if (controlSet.has(node)) return null;
        const style = getComputedStyle(node);
        const isRow =
          ((style.display === "flex" || style.display === "inline-flex") && style.flexDirection.startsWith("row")) ||
          style.display === "grid" ||
          style.display === "inline-grid";
        const others = countControls(node);
        if (isRow && others >= 2) return node;
        // Wrappers: inline boxes, display: contents, or a small box (a field
        // wrapper, not a card) that holds no other control.
        const isWrapper =
          style.display === "contents" ||
          style.display.startsWith("inline") ||
          (others <= 1 && node.getBoundingClientRect().height <= 2 * controlHeight + 40);
        if (!isRow && !isWrapper) return null;
      }
      return null;
    };

    const rows = new Map<Element, Element[]>();
    for (const control of controls) {
      const row = rowOf(control);
      if (row) rows.set(row, [...(rows.get(row) ?? []), control]);
    }

    for (const [row, rowControls] of rows) {
      if (rowControls.length < 2) continue;
      const items = rowControls.map((el) => {
        const r = box(el);
        return { el, top: r.top, bottom: r.bottom, center: (r.top + r.bottom) / 2, height: r.height };
      });
      items.sort((a, b) => a.center - b.center);
      const lines: (typeof items)[] = [];
      for (const item of items) {
        const line = lines.find((l) => l.some((o) => item.center > o.top && item.center < o.bottom));
        if (line) line.push(item);
        else lines.push([item]);
      }
      for (const line of lines) {
        if (line.length < 2) continue;
        const centers = line.map((i) => i.center);
        if (Math.max(...centers) - Math.min(...centers) > 1) {
          problems.push(
            `${rowName(row)}: controls on one line are not vertically centred (${line
              .map((i) => `${label(i.el)}@${i.center.toFixed(1)}`)
              .join(", ")})`,
          );
        }
      }

      const groups = new Map<string, typeof items>();
      for (const item of items) {
        if (item.el.tagName !== "SCALE-BUTTON") continue;
        const size = (item.el as HTMLElement & { size?: string }).size || item.el.getAttribute("size") || "large";
        const key = `${size}/${isIconOnly(item.el) ? "icon" : "text"}`;
        groups.set(key, [...(groups.get(key) ?? []), item]);
      }
      for (const [key, group] of groups) {
        const heights = group.map((i) => i.height);
        if (Math.max(...heights) - Math.min(...heights) > 1) {
          problems.push(
            `${rowName(row)}: ${key} buttons differ in height (${group
              .map((i) => `${label(i.el)}=${i.height.toFixed(1)}`)
              .join(", ")})`,
          );
        }
      }
    }

    const buttons = controls.filter((el) => el.tagName === "SCALE-BUTTON");
    // The visible button must fill its host element. A wider host (for example
    // a min-width set on the custom element) leaves the button floating inside
    // an invisible box, so its edges no longer line up with the content.
    for (const el of buttons) {
      const host = el.getBoundingClientRect();
      const inner = box(el);
      if (Math.abs(host.left - inner.left) > 1 || Math.abs(host.right - inner.right) > 1) {
        problems.push(
          `${label(el)}: rendered button (${inner.left.toFixed(1)}-${inner.right.toFixed(1)}) does not fill its host (${host.left.toFixed(1)}-${host.right.toFixed(1)})`,
        );
      }
    }
    // One height per button size on a screen: equivalent actions in different
    // rows or cards must look the same everywhere.
    const bySize = new Map<string, Element[]>();
    for (const el of buttons) {
      if (isIconOnly(el)) continue;
      const size = (el as HTMLElement & { size?: string }).size || el.getAttribute("size") || "large";
      bySize.set(size, [...(bySize.get(size) ?? []), el]);
    }
    for (const [size, group] of bySize) {
      const heights = group.map((el) => box(el).height);
      if (Math.max(...heights) - Math.min(...heights) > 1) {
        problems.push(
          `${size} text buttons differ in height across the screen (${group
            .map((el, i) => `${label(el)}=${heights[i].toFixed(1)}`)
            .join(", ")})`,
        );
      }
    }
    return problems;
  }, scopeSelector);
}

/** Expect no misaligned controls in any action row of the given scope. */
export async function expectAlignedActionRows(page: Page, context: string, scopeSelector = "body"): Promise<void> {
  const problems = await findAlignmentProblems(page, scopeSelector);
  expect.soft(problems, `alignment problems on ${context}`).toEqual([]);
}

/**
 * Every visible icon-only Scale button, disabled button, session status tag,
 * countdown timer and ellipsis-clipped text must explain itself with a Scale tooltip that opens on
 * hover and on keyboard focus. Disabled controls cannot take focus, so their
 * tooltip trigger is the focusable DisabledReason wrapper around them, status
 * tags use the HintTooltip wrapper; timers and clipped text must be focusable
 * themselves.
 */
export async function expectTooltipsOnHoverAndFocus(page: Page, context: string, scopeSelector = "body") {
  await settleAnimations(page);
  const targets = await page.evaluate((scope) => {
    const root = document.querySelector(scope);
    if (!root) return [];
    const parentOf = (el: Element): Element | null =>
      el.parentElement ?? ((el.getRootNode() as ShadowRoot).host as Element | undefined) ?? null;
    const hidden = (el: Element): boolean => {
      for (let node: Element | null = el; node; node = parentOf(node)) {
        const style = getComputedStyle(node);
        if (style.display === "none" || style.visibility === "hidden") return true;
        if (node.getAttribute("aria-hidden") === "true" || node.classList.contains("sr-only")) return true;
        if (node.tagName === "SCALE-MODAL" && !(node as HTMLElement & { opened?: boolean }).opened) return true;
      }
      const r = el.getBoundingClientRect();
      return r.width === 0 || r.height === 0;
    };
    // Controls in a dialog's background are inert while the dialog is open.
    const openModal = Array.from(document.querySelectorAll("scale-modal")).find(
      (m) => (m as HTMLElement & { opened?: boolean }).opened,
    );
    document.querySelectorAll("[data-tooltip-audit]").forEach((el) => el.removeAttribute("data-tooltip-audit"));
    type Kind = "icon-only" | "disabled" | "status" | "timer" | "truncated";
    const sessionStates = new Set(
      "pending pendingapproval approved active rejected withdrawn expired idleexpired approvaltimeout waitingforscheduledtime terminated failed".split(
        " ",
      ),
    );
    const found: { id: string; kind: Kind; name: string }[] = [];
    let n = 0;
    // Repeated instances (one status tag per card, ...) share markup, so one per name is enough.
    const seen = new Set<string>();
    const mark = (el: Element, kind: Kind) => {
      const name =
        el.getAttribute("data-testid") ||
        el.getAttribute("inner-aria-label") ||
        (el.textContent || "").trim().replace(/\s+/g, " ").slice(0, 30) ||
        el.tagName.toLowerCase();
      if (seen.has(`${kind}:${name}`)) return;
      seen.add(`${kind}:${name}`);
      const id = `tooltip-audit-${n++}`;
      el.setAttribute("data-tooltip-audit", id);
      found.push({ id, kind, name });
    };
    for (const el of Array.from(root.querySelectorAll("scale-button, scale-checkbox, button"))) {
      if (el.tagName === "BUTTON" && el.parentElement?.closest("scale-button")) continue;
      if (hidden(el) || (openModal && !openModal.contains(el))) continue;
      const iconOnly =
        el.tagName === "SCALE-BUTTON" && el.hasAttribute("icon-only") && el.getAttribute("icon-only") !== "false";
      const disabled = (el as HTMLButtonElement).disabled === true;
      if (!iconOnly && !disabled) continue;
      mark(el, disabled ? "disabled" : "icon-only");
    }
    for (const el of Array.from(root.querySelectorAll("*"))) {
      if (hidden(el) || (openModal && !openModal.contains(el))) continue;
      const tagText = (el.textContent || "").toLowerCase().replace(/\s+/g, "");
      if (el.tagName === "SCALE-TAG" && sessionStates.has(tagText)) {
        mark(el, "status");
      } else if (el.getAttribute("role") === "timer") {
        mark(el, "timer");
      } else if (getComputedStyle(el).textOverflow === "ellipsis" && el.scrollWidth > el.clientWidth + 1) {
        mark(el, "truncated");
      }
    }
    return found;
  }, scopeSelector);

  const tooltipState = (id: string) =>
    page.evaluate((auditId) => {
      const el = document.querySelector(`[data-tooltip-audit="${auditId}"]`);
      const tooltip = el?.closest("scale-tooltip");
      const bubble = tooltip?.shadowRoot?.querySelector<HTMLElement>("[part~='tooltip']");
      if (!bubble) return "missing";
      const text = (tooltip!.getAttribute("content") || (tooltip as HTMLElement & { content?: string }).content || "")
        .toString()
        .trim();
      const r = bubble.getBoundingClientRect();
      const shown = bubble.getAttribute("aria-hidden") === "false" && r.width > 0 && r.height > 0;
      return shown && text ? "shown" : text ? "hidden" : "empty";
    }, id);

  for (const target of targets) {
    const control = page.locator(`[data-tooltip-audit="${target.id}"]`);
    const trigger =
      target.kind === "disabled"
        ? control.locator("xpath=ancestor::*[@data-testid='disabled-reason'][1]")
        : target.kind === "status"
          ? control.locator("xpath=ancestor::*[@data-hint='true'][1]")
          : target.kind === "icon-only"
            ? control.locator("button").first()
            : control.locator("xpath=self::*[@tabindex='0']");
    const where = `${target.kind} control "${target.name}" on ${context}`;
    if ((await trigger.count()) === 0) {
      const missing = {
        disabled: "no DisabledReason wrapper",
        status: "no HintTooltip wrapper",
        "icon-only": "no button",
      }[target.kind as string];
      expect.soft(missing ?? "not keyboard-focusable", where).toBe("tooltip");
      continue;
    }
    if ((await tooltipState(target.id)) === "missing") {
      expect.soft("no scale-tooltip", where).toBe("tooltip");
      continue;
    }

    await trigger.scrollIntoViewIfNeeded();
    // Re-hover on retry: a pointer move can be swallowed while a neighbouring bubble fades out.
    await expect(async () => {
      await page.mouse.move(0, 0);
      await trigger.hover();
      await expect.poll(() => tooltipState(target.id), { timeout: 1500 }).toBe("shown");
    }, `hover tooltip for ${where}`).toPass({ timeout: 8000 });
    await page.mouse.move(0, 0, { steps: 5 });
    await expect
      .poll(() => tooltipState(target.id), { message: `tooltip hides after hover on ${where}` })
      .toBe("hidden");

    await trigger.focus();
    await expect.poll(() => tooltipState(target.id), { message: `focus tooltip for ${where}` }).toBe("shown");
    await trigger.blur();
    await expect
      .poll(() => tooltipState(target.id), { message: `tooltip hides after blur on ${where}` })
      .toBe("hidden");
  }
  return targets.length;
}
