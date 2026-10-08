// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { expect, type Page } from "@playwright/test";

/**
 * Generic visual audit. Each detector looks for a whole class of layout bug
 * on whatever is rendered, so new views and dialogs are covered without
 * per-page assertions:
 *
 *  - hydration: Scale elements that lost Stencil's hydrated flag (invisible);
 *  - header: logo, app name, nav items and header controls share one vertical
 *    centre (±1px) and nav labels are never truncated;
 *  - overlap: visible text or controls that intersect each other or are
 *    covered by fixed/sticky chrome (header, toasts, floating buttons);
 *  - clipped text: text cut off by its own box (ellipsis or overflow) without
 *    a tooltip/accessible name, or pushed outside the viewport;
 *  - separators: single top/bottom borders that do not span their container;
 *  - empty space: bordered or filled boxes much taller than their content;
 *  - gaps: flex/grid gaps that are not on the spacing token scale;
 *  - icons: icon-only controls in one row with different icon sizes;
 *  - option groups: wrapped checkboxes/radios that do not line up in columns;
 *  - cards: same-type cards with different radii or paddings.
 *
 * Everything runs in the page and pierces open shadow roots, because most of
 * the chrome (header, modal window, notifications) lives inside Scale.
 */
export async function findVisualProblems(page: Page, scopeSelector = "body"): Promise<string[]> {
  return page.evaluate((scope) => {
    const problems: string[] = [];
    const root = document.querySelector(scope);
    if (!root) return [`scope ${scope} not found`];
    const vw = document.documentElement.clientWidth;
    const vh = window.innerHeight;

    // Flat-tree parent: slotted nodes belong to their slot, shadow roots to their host.
    const parentOf = (el: Element): Element | null =>
      el.assignedSlot ?? el.parentElement ?? ((el.getRootNode() as ShadowRoot).host as Element | undefined) ?? null;
    const openModal = Array.from(document.querySelectorAll("scale-modal")).find(
      (m) => (m as HTMLElement & { opened?: boolean }).opened,
    );
    // Decorative graphics are aria-hidden but still drawn, so they opt out of that rule.
    const hidden = (el: Element, decorative = false): boolean => {
      for (let node: Element | null = el; node; node = parentOf(node)) {
        const style = getComputedStyle(node);
        if (style.display === "none" || style.visibility === "hidden" || style.visibility === "collapse") return true;
        if (Number(style.opacity) === 0) return true;
        if (!decorative && node.getAttribute("aria-hidden") === "true" && node.tagName !== "SCALE-TELEKOM-HEADER") {
          return true;
        }
        if (node.classList.contains("sr-only") || node.classList.contains("visually-hidden")) return true;
        if (node.classList.contains("skip-link")) return true;
        if (node.tagName === "SCALE-MODAL" && !(node as HTMLElement & { opened?: boolean }).opened) return true;
      }
      const r = el.getBoundingClientRect();
      return r.width < 1 || r.height < 1;
    };
    const describe = (el: Element) => {
      const testId = el.getAttribute("data-testid");
      const part = el.getAttribute("part");
      const cls = typeof el.className === "string" ? el.className.trim().split(/\s+/)[0] : "";
      const text = (el.textContent || "").trim().replace(/\s+/g, " ").slice(0, 32);
      return `${el.tagName.toLowerCase()}${testId ? `[data-testid=${testId}]` : ""}${part ? `[part=${part}]` : ""}${
        cls ? `.${cls}` : ""
      }${text ? ` "${text}"` : ""}`;
    };
    const px = (v: string) => parseFloat(v) || 0;

    // Every element in scope, including open shadow trees (Scale chrome).
    const all: Element[] = [];
    const walk = (node: Element | ShadowRoot) => {
      for (const child of Array.from(node.children)) {
        all.push(child);
        if (child.shadowRoot) walk(child.shadowRoot);
        walk(child);
      }
    };
    walk(root);
    // A dialog makes the rest of the page inert and covered by the backdrop.
    const inScope = (el: Element) => {
      if (!openModal) return true;
      for (let node: Element | null = el; node; node = parentOf(node)) if (node === openModal) return true;
      return false;
    };
    const visible = all.filter((el) => inScope(el) && !hidden(el));

    // --- Scale hydration ------------------------------------------------------------------------
    // Stencil hides Scale elements until they carry the "hydrated" class. A Vue
    // class binding that changes after mount rewrites the class attribute and
    // drops the flag, so the control silently disappears.
    for (const el of all) {
      if (!el.tagName.startsWith("SCALE-") || el.getRootNode() !== document || !inScope(el)) continue;
      if (!customElements.get(el.tagName.toLowerCase()) || el.classList.contains("hydrated")) continue;
      const parent = parentOf(el);
      if (parent && !hidden(parent, true)) problems.push(`${describe(el)} is hidden: it lost Stencil's hydrated flag`);
    }

    // --- Header ---------------------------------------------------------------------------------
    const header = document.querySelector("scale-telekom-header");
    if (header?.shadowRoot && !openModal && (scope === "body" || root.contains(header))) {
      const sr = header.shadowRoot;
      const bar = sr.querySelector("[part~='fixed-wrapper']")?.getBoundingClientRect();
      const centre = (r: DOMRect) => (r.top + r.bottom) / 2;
      const items: { name: string; rect: DOMRect }[] = [];
      const logo = sr.querySelector("[part~='app-logo']");
      if (logo) items.push({ name: "logo", rect: logo.getBoundingClientRect() });
      const appName = sr.querySelector("[part~='bottom-app-name'] [part~='app-name-text']");
      if (appName && !hidden(appName)) items.push({ name: "app name", rect: appName.getBoundingClientRect() });
      for (const item of Array.from(header.querySelectorAll("[slot='main-nav'] scale-telekom-nav-item a"))) {
        if (hidden(item)) continue;
        // The label's glyph box, not its padded span, is what must line up.
        const range = document.createRange();
        range.selectNodeContents(item);
        const text = item.querySelector("span") ?? item;
        items.push({ name: `nav "${(item.textContent || "").trim()}"`, rect: range.getBoundingClientRect() });
        if (item.scrollWidth > item.clientWidth + 1 || text.scrollWidth > text.clientWidth + 1) {
          problems.push(`header nav label "${(item.textContent || "").trim()}" is truncated`);
        }
      }
      const functions = header.querySelector("[slot='functions']");
      for (const ctl of Array.from(
        functions?.querySelectorAll(
          "scale-button, .scale-menu-trigger, .user-menu-mobile > button, [data-testid='mobile-menu-trigger']",
        ) ?? [],
      )) {
        if (hidden(ctl)) continue;
        const inner = ctl.tagName === "SCALE-BUTTON" ? (ctl.shadowRoot?.querySelector("button") ?? ctl) : ctl;
        items.push({ name: describe(ctl), rect: inner.getBoundingClientRect() });
      }
      if (bar && items.length) {
        const ref = centre(bar);
        for (const { name, rect } of items) {
          if (Math.abs(centre(rect) - ref) > 1) {
            problems.push(
              `header: ${name} is not vertically centred in the header bar (${centre(rect).toFixed(1)} vs ${ref.toFixed(1)})`,
            );
          }
          if (rect.right > vw + 1 || rect.left < -1) problems.push(`header: ${name} is outside the viewport`);
        }
      }
    }

    // --- Text and control overlap ----------------------------------------------------------------
    const isControl = (el: Element) =>
      /^(A|BUTTON|INPUT|SELECT|TEXTAREA)$/.test(el.tagName) ||
      /^SCALE-(BUTTON|LINK|CHECKBOX|SWITCH|TEXT-FIELD|TEXTAREA|DROPDOWN-SELECT|TAG)$/.test(el.tagName);
    const ownText = (el: Element) =>
      Array.from(el.childNodes).some((n) => n.nodeType === Node.TEXT_NODE && (n.textContent || "").trim());
    const textRect = (el: Element) => {
      const range = document.createRange();
      let rect: DOMRect | null = null;
      for (const n of Array.from(el.childNodes)) {
        if (n.nodeType !== Node.TEXT_NODE || !(n.textContent || "").trim()) continue;
        range.selectNodeContents(n);
        const r = range.getBoundingClientRect();
        rect = rect
          ? new DOMRect(
              Math.min(rect.left, r.left),
              Math.min(rect.top, r.top),
              Math.max(rect.right, r.right) - Math.min(rect.left, r.left),
              Math.max(rect.bottom, r.bottom) - Math.min(rect.top, r.top),
            )
          : r;
      }
      return rect ?? el.getBoundingClientRect();
    };
    const insideControl = (el: Element) => {
      for (let n = parentOf(el); n; n = parentOf(n)) if (isControl(n)) return true;
      return false;
    };
    const fixedAncestor = (el: Element) => {
      for (let n: Element | null = el; n; n = parentOf(n)) {
        const p = getComputedStyle(n).position;
        if (p === "fixed" || p === "sticky") return n;
      }
      return null;
    };
    const contentLeaves = visible
      .filter((el) => (isControl(el) && !insideControl(el)) || (ownText(el) && !insideControl(el)))
      .map((el) => ({ el, rect: isControl(el) ? el.getBoundingClientRect() : textRect(el), fixed: fixedAncestor(el) }))
      .filter((b) => b.rect.width > 0 && b.rect.height > 0);
    // The pairwise overlap check is quadratic, so it samples the first 1500
    // leaves; the empty-space check below needs all of them.
    const boxes = contentLeaves.slice(0, 1500);
    const related = (a: Element, b: Element) => {
      for (let n: Element | null = a; n; n = parentOf(n)) if (n === b) return true;
      for (let n: Element | null = b; n; n = parentOf(n)) if (n === a) return true;
      return false;
    };
    for (let i = 0; i < boxes.length; i++) {
      for (let j = i + 1; j < boxes.length; j++) {
        const a = boxes[i];
        const b = boxes[j];
        const w = Math.min(a.rect.right, b.rect.right) - Math.max(a.rect.left, b.rect.left);
        const h = Math.min(a.rect.bottom, b.rect.bottom) - Math.max(a.rect.top, b.rect.top);
        if (w <= 2 || h <= 2 || related(a.el, b.el)) continue;
        // Toasts float over content on purpose; everything else must not overlap.
        const floating = (x: Element | null) => !!x?.closest?.(".toast-region");
        if (floating(a.fixed) || floating(b.fixed)) continue;
        problems.push(`${describe(a.el)} overlaps ${describe(b.el)} (${Math.round(w)}x${Math.round(h)}px)`);
      }
    }
    // Fixed chrome (debug panel, toasts) must not cover the page's controls.
    for (const fixed of visible.filter((el) => getComputedStyle(el).position === "fixed")) {
      if (fixed.tagName === "SCALE-TELEKOM-HEADER" || fixed.closest?.(".toast-region")) continue;
      const fr = fixed.getBoundingClientRect();
      if (fr.width >= vw - 1 && fr.height >= vh - 1) continue; // overlays and backdrops
      if (fixed.matches(".toast-region, scale-modal, [part~='fixed-wrapper'], [part~='modal']")) continue;
      for (const b of boxes) {
        if (b.fixed || related(fixed, b.el)) continue;
        const w = Math.min(fr.right, b.rect.right) - Math.max(fr.left, b.rect.left);
        const h = Math.min(fr.bottom, b.rect.bottom) - Math.max(fr.top, b.rect.top);
        if (w > 2 && h > 2) problems.push(`fixed ${describe(fixed)} covers ${describe(b.el)}`);
      }
    }

    // --- Clipped text and off-viewport content --------------------------------------------------
    const hasName = (el: Element) => {
      for (let n: Element | null = el; n; n = parentOf(n)) {
        if (n.getAttribute("title") || n.getAttribute("aria-label")) return true;
        if (n.tagName === "SCALE-TOOLTIP" || n.getAttribute("data-hint") === "true") return true;
      }
      return false;
    };
    for (const el of visible) {
      if (!ownText(el)) continue;
      const style = getComputedStyle(el);
      const r = textRect(el);
      if (r.right > vw + 1 || r.left < -1) {
        if (!fixedAncestor(el) || r.left < vw) problems.push(`${describe(el)} is outside the viewport horizontally`);
      }
      const clipsX = style.overflowX !== "visible" || style.textOverflow === "ellipsis";
      if (clipsX && el.scrollWidth > el.clientWidth + 1 && !hasName(el)) {
        problems.push(`truncated text without tooltip: ${describe(el)}`);
      }
      if (style.webkitLineClamp !== "none" && style.webkitLineClamp && el.scrollHeight > el.clientHeight + 1) {
        if (!hasName(el)) problems.push(`line-clamped text without tooltip: ${describe(el)}`);
      }
    }

    // --- Separators -----------------------------------------------------------------------------
    const isBox = (el: Element) => {
      const s = getComputedStyle(el);
      const bg = s.backgroundColor;
      const filled = bg !== "rgba(0, 0, 0, 0)" && bg !== "transparent";
      const bordered = ["Top", "Right", "Bottom", "Left"].every(
        (side) => px(s.getPropertyValue(`border-${side.toLowerCase()}-width`)) > 0,
      );
      return filled || bordered || s.boxShadow !== "none";
    };
    const boxAncestor = (el: Element) => {
      for (let n = parentOf(el); n && n !== document.documentElement; n = parentOf(n)) {
        if (isBox(n)) return n;
      }
      return null;
    };
    for (const el of visible) {
      const s = getComputedStyle(el);
      if (s.display.startsWith("table") || isControl(el) || el.tagName === "HR") continue;
      const top = px(s.borderTopWidth) > 0 && s.borderTopStyle !== "none";
      const bottom = px(s.borderBottomWidth) > 0 && s.borderBottomStyle !== "none";
      const sides = px(s.borderLeftWidth) > 0 || px(s.borderRightWidth) > 0;
      if ((!top && !bottom) || sides) continue;
      const colour = top ? s.borderTopColor : s.borderBottomColor;
      if (/rgba\(.*, 0\)$/.test(colour) || colour === "transparent") continue;
      const container = boxAncestor(el);
      if (!container) continue;
      const c = container.getBoundingClientRect();
      const cs = getComputedStyle(container);
      const inner = { left: c.left + px(cs.borderLeftWidth), right: c.right - px(cs.borderRightWidth) };
      const content = { left: inner.left + px(cs.paddingLeft), right: inner.right - px(cs.paddingRight) };
      const r = el.getBoundingClientRect();
      // Short underlines (active tab, links) are indicators, not separators.
      if (r.width < 0.4 * (content.right - content.left)) continue;
      const spans = (a: { left: number; right: number }) => r.left <= a.left + 1 && r.right >= a.right - 1;
      // A divider may run edge to edge or along the content edge of any wrapper
      // up to its box; anything shorter is a separator that stops part-way.
      let ok = spans(inner) || spans(content);
      for (let n = parentOf(el); n && n !== container && !ok; n = parentOf(n)) {
        const nr = n.getBoundingClientRect();
        const ns = getComputedStyle(n);
        const nl = nr.left + px(ns.borderLeftWidth);
        const nrt = nr.right - px(ns.borderRightWidth);
        ok =
          spans({ left: nl, right: nrt }) || spans({ left: nl + px(ns.paddingLeft), right: nrt - px(ns.paddingRight) });
      }
      if (!ok) {
        problems.push(
          `separator ${describe(el)} spans ${Math.round(r.left)}..${Math.round(r.right)} but its container ${describe(
            container,
          )} is ${Math.round(inner.left)}..${Math.round(inner.right)}`,
        );
      }
    }

    // --- Empty space in boxes -------------------------------------------------------------------
    // Content lines are the visible leaves (text, controls, icons). A bordered
    // or filled box must not leave more than 48px (--space-3xl) of empty space
    // above, between or below them. This catches tall wrappers inside a panel
    // as well as boxes with a fixed height.
    const graphics = all.filter(
      (el) =>
        /^(SCALE-ICON-|SVG$|IMG$)/i.test(el.tagName) &&
        el.getRootNode() === document &&
        inScope(el) &&
        !hidden(el, true) &&
        !insideControl(el),
    );
    const leafOwners = [...contentLeaves.map((b) => b.el), ...graphics];
    const leaves = [...contentLeaves.map((b) => b.rect), ...graphics.map((g) => g.getBoundingClientRect())];
    for (const el of visible) {
      if (isControl(el) || el.tagName.startsWith("SCALE-") || el === document.body) continue;
      if (!isBox(el) || getComputedStyle(el).position === "fixed") continue;
      const s = getComputedStyle(el);
      const r = el.getBoundingClientRect();
      if (r.height < 80 || r.height >= vh * 0.95) continue;
      const lines: [number, number][] = [];
      // Nested boxes (sub-cards, callouts) count as content including their padding.
      for (const inner of visible) {
        if (inner === el || !isBox(inner) || inner.tagName.startsWith("SCALE-")) continue;
        for (let n = parentOf(inner); n; n = parentOf(n)) {
          if (n === el) {
            const ir = inner.getBoundingClientRect();
            lines.push([Math.max(ir.top, r.top), Math.min(ir.bottom, r.bottom)]);
            break;
          }
        }
      }
      leafOwners.forEach((leaf, i) => {
        for (let n: Element | null = leaf; n; n = parentOf(n)) {
          if (n === el) {
            lines.push([Math.max(leaves[i].top, r.top), Math.min(leaves[i].bottom, r.bottom)]);
            return;
          }
        }
      });
      if (!lines.length) continue;
      lines.sort((a, b) => a[0] - b[0]);
      const merged: [number, number][] = [];
      for (const line of lines) {
        const last = merged[merged.length - 1];
        if (last && line[0] <= last[1]) last[1] = Math.max(last[1], line[1]);
        else merged.push([...line]);
      }
      const innerTop = r.top + px(s.borderTopWidth) + px(s.paddingTop);
      const innerBottom = r.bottom - px(s.borderBottomWidth) - px(s.paddingBottom);
      // Grid/flex rows stretch shorter siblings to the tallest one on purpose.
      const parent = parentOf(el);
      const stretched =
        !!parent &&
        Array.from(parent.children).some(
          (sib) => sib !== el && Math.abs(sib.getBoundingClientRect().top - r.top) < 1 && !hidden(sib),
        );
      const gaps: [string, number][] = [["above the content", merged[0][0] - innerTop]];
      // A stretched card may push its footer down; only its natural layout is judged.
      if (!stretched) {
        for (let i = 1; i < merged.length; i++) gaps.push(["between content lines", merged[i][0] - merged[i - 1][1]]);
        gaps.push(["below the content", innerBottom - merged[merged.length - 1][1]]);
      }
      for (const [where, gap] of gaps) {
        if (gap > 48.5) problems.push(`${describe(el)} has ${Math.round(gap)}px of empty space ${where}`);
      }
    }

    // --- Gaps on the token scale ----------------------------------------------------------------
    const rootStyle = getComputedStyle(document.documentElement);
    const scale = new Set<number>([0]);
    const probe = document.createElement("div");
    document.body.appendChild(probe);
    for (const name of [
      ...["2xs", "xs", "sm", "md", "lg", "xl", "2xl", "3xl"].map((s) => `--space-${s}`),
      ...Array.from({ length: 19 }, (_, i) => `--telekom-spacing-composition-space-${String(i + 1).padStart(2, "0")}`),
    ]) {
      if (!rootStyle.getPropertyValue(name).trim()) continue;
      probe.style.width = `var(${name})`;
      scale.add(Math.round(px(getComputedStyle(probe).width) * 100) / 100);
    }
    probe.remove();
    const onScale = (v: number) => [...scale].some((s) => Math.abs(s - v) < 0.5);
    for (const el of visible) {
      if (el.getRootNode() !== document) continue; // Scale's own gaps are upstream design
      const s = getComputedStyle(el);
      if (!/flex|grid/.test(s.display)) continue;
      for (const prop of ["rowGap", "columnGap"] as const) {
        const value = s[prop];
        if (value === "normal") continue;
        if (!onScale(px(value))) problems.push(`${describe(el)} uses ${prop} ${value}, which is not a spacing token`);
      }
    }

    // --- Icon sizes in one row ------------------------------------------------------------------
    const iconOnly = visible.filter(
      (el) => el.tagName === "SCALE-BUTTON" && el.hasAttribute("icon-only") && el.getAttribute("icon-only") !== "false",
    );
    const byRow = new Map<Element, { el: Element; size: number }[]>();
    for (const btn of iconOnly) {
      const icon = btn.querySelector("[class*='scale-icon'], svg, scale-icon") ?? btn.firstElementChild;
      if (!icon) continue;
      const svg = icon.shadowRoot?.querySelector("svg") ?? icon;
      const size = Math.round(svg.getBoundingClientRect().height);
      let row: Element | null = parentOf(btn);
      while (row && !/flex|grid/.test(getComputedStyle(row).display)) row = parentOf(row);
      if (!row) continue;
      byRow.set(row, [...(byRow.get(row) ?? []), { el: btn, size }]);
    }
    for (const [row, icons] of byRow) {
      const sizes = icons.map((i) => i.size);
      if (icons.length > 1 && Math.max(...sizes) - Math.min(...sizes) > 1) {
        problems.push(
          `${describe(row)}: icon buttons use different icon sizes (${icons
            .map((i) => `${describe(i.el)}=${i.size}`)
            .join(", ")})`,
        );
      }
    }

    // --- Wrapped option groups align in columns -------------------------------------------------
    // Checkboxes or radios that wrap onto several lines must start on the
    // columns of their widest line, not flow raggedly after an inline label.
    const isOption = (el: Element) =>
      /^SCALE-(CHECKBOX|RADIO-BUTTON)$/.test(el.tagName) ||
      (el.tagName === "INPUT" && /^(checkbox|radio)$/.test((el as HTMLInputElement).type));
    for (const group of visible.filter((el) => el.matches("[role='group'], [role='radiogroup'], fieldset"))) {
      const options = visible.filter((el) => isOption(el) && group.contains(el) && !insideControl(el));
      if (options.length < 3) continue;
      const rows: DOMRect[][] = [];
      for (const rect of options.map((o) => o.getBoundingClientRect()).sort((a, b) => a.top - b.top)) {
        const row = rows.find((r) => Math.abs(r[0].top - rect.top) < 4);
        if (row) row.push(rect);
        else rows.push([rect]);
      }
      if (rows.length < 2) continue;
      const columns = rows.reduce((a, b) => (b.length > a.length ? b : a)).map((r) => r.left);
      const ragged = rows.flat().filter((r) => !columns.some((x) => Math.abs(x - r.left) <= 1));
      if (ragged.length) {
        problems.push(`${describe(group)}: ${ragged.length} wrapped option(s) are not aligned with the option columns`);
      }
    }

    // --- Same-type cards share radius and padding ------------------------------------------------
    const cards = visible.filter(
      (el) =>
        el.getRootNode() === document &&
        typeof el.className === "string" &&
        /(^|\s)[\w-]*(card|panel|tile)(\s|$)/.test(el.className) &&
        isBox(el),
    );
    const groups = new Map<string, Element[]>();
    for (const card of cards) {
      const key = `${card.tagName}.${(card.className.match(/[\w-]*(card|panel|tile)(?=\s|$)/) ?? [""])[0]}`;
      groups.set(key, [...(groups.get(key) ?? []), card]);
    }
    for (const [key, group] of groups) {
      if (group.length < 2) continue;
      const sig = (el: Element) => {
        const s = getComputedStyle(el);
        return `radius ${s.borderTopLeftRadius}, padding ${s.paddingTop} ${s.paddingRight} ${s.paddingBottom} ${s.paddingLeft}`;
      };
      const sigs = new Set(group.map(sig));
      if (sigs.size > 1) problems.push(`${key} cards differ: ${[...sigs].join(" | ")}`);
    }

    return [...new Set(problems)];
  }, scopeSelector);
}

/** Expect the visual audit for the given scope to find nothing. */
export async function expectNoVisualProblems(page: Page, context: string, scopeSelector = "body"): Promise<void> {
  const problems = await findVisualProblems(page, scopeSelector);
  expect.soft(problems, `visual problems on ${context}`).toEqual([]);
}
