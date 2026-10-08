// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { expect, type Locator, type Page } from "@playwright/test";

/**
 * Screen-reader-equivalent checks built on Playwright's accessibility tree
 * (ariaSnapshot / getByRole / toHaveAccessibleDescription). Unlike DOM queries
 * the tree is computed across Scale's shadow roots, so it reflects what
 * assistive technology is given: roles, names, states and descriptions.
 */

const FOCUS_PROBE = "data-sr-focus-probe";

export type FocusStop = {
  /** First line of the focused element's ARIA snapshot, e.g. `button "Refresh"`. */
  aria: string;
  inMain: boolean;
  inViewport: boolean;
};

/** Accessibility-tree view of the focused element, descending into open shadow roots. */
export async function focusedStop(page: Page): Promise<FocusStop | null> {
  const info = await page.evaluate((probe) => {
    // The previous probe may sit in a shadow root, out of reach of querySelectorAll.
    const store = window as unknown as Record<string, Element | undefined>;
    store.__srFocusProbe?.removeAttribute(probe);
    let el: Element | null = document.activeElement;
    while (el?.shadowRoot?.activeElement) el = el.shadowRoot.activeElement;
    if (!el || el === document.body) return null;
    el.setAttribute(probe, "");
    store.__srFocusProbe = el;
    const r = el.getBoundingClientRect();
    let node: Node | null = el;
    let inMain = false;
    while (node) {
      if (node instanceof Element && node.id === "main") inMain = true;
      node = node.parentNode instanceof ShadowRoot ? node.parentNode.host : node.parentNode;
    }
    return { inMain, inViewport: r.bottom > 0 && r.top < window.innerHeight && r.width > 0 && r.height > 0 };
  }, FOCUS_PROBE);
  if (!info) return null;
  const probe = page.locator(`[${FOCUS_PROBE}]`);
  const snapshot = await probe.ariaSnapshot();
  return { ...info, aria: firstAriaLine(snapshot) };
}

function focusedInViewport(page: Page): Promise<boolean> {
  return page.evaluate(() => {
    const el = (window as unknown as Record<string, Element | undefined>).__srFocusProbe;
    const r = el?.getBoundingClientRect();
    return !!r && r.bottom > 0 && r.top < window.innerHeight && r.width > 0 && r.height > 0;
  });
}

function firstAriaLine(snapshot: string): string {
  return ariaEntry(snapshot.split("\n").find((l) => l.trim().startsWith("- ")) ?? "");
}

/** One snapshot line without indentation, list marker, YAML quoting or trailing colon. */
function ariaEntry(line: string): string {
  let entry = line.trim().replace(/^- /, "");
  // Entries containing ": " are YAML single-quoted.
  const quoted = /^'((?:[^']|'')*)'(.*)$/.exec(entry);
  if (quoted) entry = quoted[1].replace(/''/g, "'") + quoted[2];
  return entry.replace(/:$/, "");
}

/** The accessible name inside a snapshot line (`button "Close"` -> `Close`). */
function nameOf(aria: string): string {
  const quoted = /^[a-z]+ "((?:[^"\\]|\\.)*)"/.exec(aria);
  if (quoted) return quoted[1].replace(/\\"/g, '"');
  const text = /^[a-z]+: (.*)$/.exec(aria);
  return text ? text[1] : "";
}

/**
 * Tabs through the scope from `start` and checks every stop the way a screen
 * reader user meets it: it has a role and a non-empty accessible name, it is
 * scrolled into view, and the sequence follows the reading order of the
 * accessibility tree (WCAG 2.4.3 / 4.1.2). Returns the visited stops.
 */
export async function expectTabOrderFollowsReadingOrder(
  page: Page,
  context: string,
  { scope = "#main", maxStops = 30 }: { scope?: string; maxStops?: number } = {},
): Promise<string[]> {
  // Digits are masked: countdowns and relative times tick while tabbing.
  const mask = (text: string) => text.replace(/\d+/g, "#");
  const reading = (await page.locator(scope).ariaSnapshot()).split("\n").map((line) => mask(ariaEntry(line)));
  const stops: string[] = [];
  // Position just after the previous stop. Controls with a role own a snapshot
  // entry, so they are matched by their whole `role "name"` key and the cursor
  // moves past that entry. Focusable text without a role is flattened into its
  // parent's line, so it is matched from the column after the previous stop.
  let cursor = { line: 0, column: 0 };
  for (let i = 0; i < maxStops; i++) {
    await page.keyboard.press("Tab");
    const stop = await focusedStop(page);
    if (!stop?.inMain) break;
    const name = nameOf(stop.aria);
    expect(name.trim(), `${context}: Tab stop #${i + 1} (${stop.aria}) has no accessible name`).not.toBe("");
    // WebKit scrolls the focused element into view a frame or two after the keypress.
    await expect
      .poll(() => (stop.inViewport ? true : focusedInViewport(page)), {
        message: `${context}: Tab stop #${i + 1} (${stop.aria}) is not scrolled into view`,
      })
      .toBe(true);
    const next = nextReadingPosition(reading, cursor, mask(stop.aria), mask(name));
    expect(
      next,
      `${context}: Tab stop #${i + 1} (${stop.aria}) comes before "${reading[cursor.line]}" in reading order` +
        `\nstops: ${stops.join(" | ")}\nreading:\n${reading.join("\n")}`,
    ).not.toBeNull();
    cursor = next!;
    stops.push(stop.aria);
  }
  expect(stops.length, `${context}: Tab never reached a control in ${scope}`).toBeGreaterThan(0);
  return stops;
}

function nextReadingPosition(
  reading: string[],
  from: { line: number; column: number },
  aria: string,
  name: string,
): { line: number; column: number } | null {
  const role = /^[a-z]+ "(?:[^"\\]|\\.)*"/.exec(aria)?.[0];
  if (role) {
    const start = from.column > 0 ? from.line + 1 : from.line;
    for (let line = start; line < reading.length; line++) {
      const entry = reading[line];
      if (entry === role || entry.startsWith(`${role} `) || entry.startsWith(`${role}:`)) {
        return { line: line + 1, column: 0 };
      }
    }
    return null;
  }
  for (let line = from.line; line < reading.length; line++) {
    const column = reading[line].indexOf(name, line === from.line ? from.column : 0);
    if (column >= 0) return { line, column: column + name.length };
  }
  return null;
}

/** Exactly one level-1 heading is exposed, so screen reader heading navigation has one page title. */
export async function expectSingleH1(page: Page, context: string): Promise<void> {
  const h1 = page.getByRole("heading", { level: 1 });
  await expect
    .poll(async () => (await h1.allTextContents()).map((n) => n.trim()), {
      message: `${context}: expected exactly one h1`,
    })
    .toHaveLength(1);
  await expect(h1).toBeVisible();
}

/** After a route change focus lands on the visible page h1 (and screen readers announce it). */
export async function expectFocusOnPageHeading(page: Page, context: string): Promise<void> {
  const heading = page.getByRole("heading", { level: 1 });
  const name = ((await heading.textContent()) ?? "").trim();
  await expect
    .poll(async () => (await focusedStop(page))?.aria, { message: `${context}: focus should move to the page h1` })
    .toBe(`heading "${name}" [level=1]`);
}

/**
 * The Scale dialog is exposed as a modal dialog named after its visible
 * heading, and keyboard focus is inside it.
 */
export async function expectModalDialog(modal: Locator, name: string): Promise<Locator> {
  const dialog = modal.getByRole("dialog", { name, exact: true });
  // The first open lazy-loads the Scale modal bundle, which can be slow under parallel load.
  await expect(dialog).toBeVisible({ timeout: 15_000 });
  await expect(dialog).toHaveAttribute("aria-modal", "true");
  await expect(dialog.getByRole("heading", { name, exact: true })).toBeVisible();
  await expect
    .poll(() => modal.evaluate((host) => !!document.activeElement && host.contains(document.activeElement)), {
      message: `focus should be inside the "${name}" dialog`,
    })
    .toBe(true);
  return dialog;
}

/**
 * A disabled action exposes why it is disabled: the button is disabled in the
 * tree and its focusable DisabledReason wrapper carries the reason as its
 * accessible description, matching the tooltip text.
 */
export async function expectDisabledWithReason(scope: Locator, buttonName: string, reason: string | RegExp) {
  const button = scope.getByRole("button", { name: buttonName, exact: true });
  await expect(button).toBeDisabled();
  const wrapper = scope
    .locator('[data-testid="disabled-reason"]')
    .filter({ has: scope.page().getByRole("button", { name: buttonName, exact: true }) });
  await expect(wrapper).toHaveAttribute("tabindex", "0");
  await expect(wrapper).toHaveAccessibleDescription(reason);
  const tooltip = wrapper.locator("xpath=ancestor::scale-tooltip[1]");
  // Vue sets Scale props as DOM properties, not attributes.
  const content = await tooltip.evaluate((el) => String((el as HTMLElement & { content?: string }).content ?? ""));
  await expect(wrapper).toHaveAccessibleDescription(content);
}

/**
 * Toasts are announced: the polite live region is present before the toast is
 * added (otherwise screen readers ignore the insertion), the toast is rendered
 * inside it, and Scale exposes the toast itself as an alert.
 */
export async function expectToastAnnounced(page: Page, testId: string, text: string | RegExp): Promise<void> {
  const region = page.locator('.toast-region[aria-live="polite"]');
  const toast = region.locator(`[data-testid="${testId}"]`).last();
  await expect(toast).toBeAttached({ timeout: 15000 });
  // The toast text is slotted into Scale's shadow alert, so read it from the accessibility tree.
  await expect.poll(() => toast.ariaSnapshot()).toMatch(/^- alert\b/);
  await expect(toast).toContainText(text);
}
