// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Composable for keyboard navigation within radio-group grids.
 *
 * Provides helper handlers that move focus (and trigger click) on
 * `[role="radio"]` items inside a container, wrapping around at boundaries.
 */
export function useRadioGridNavigation() {
  /**
   * Focus and click the next radio item, wrapping to the first when at the end.
   * Attach to `@keydown.arrow-right.prevent` / `@keydown.arrow-down.prevent` on
   * the `[role="radiogroup"]` container.
   */
  function focusNextRadio(event: KeyboardEvent) {
    const group = event.currentTarget as HTMLElement;
    if (!group) return;
    const items = Array.from(group.querySelectorAll<HTMLElement>('[role="radio"]'));
    const current = (event.target as HTMLElement)?.closest('[role="radio"]') as HTMLElement | null;
    if (!current) return;
    const idx = items.indexOf(current);
    if (idx === -1) return;
    const next = items[(idx + 1) % items.length];
    next?.focus();
    next?.click();
  }

  /**
   * Focus and click the previous radio item, wrapping to the last when at the start.
   * Attach to `@keydown.arrow-left.prevent` / `@keydown.arrow-up.prevent` on
   * the `[role="radiogroup"]` container.
   */
  function focusPrevRadio(event: KeyboardEvent) {
    const group = event.currentTarget as HTMLElement;
    if (!group) return;
    const items = Array.from(group.querySelectorAll<HTMLElement>('[role="radio"]'));
    const current = (event.target as HTMLElement)?.closest('[role="radio"]') as HTMLElement | null;
    if (!current) return;
    const idx = items.indexOf(current);
    if (idx === -1) return;
    const prev = items[(idx - 1 + items.length) % items.length];
    prev?.focus();
    prev?.click();
  }

  return { focusNextRadio, focusPrevRadio };
}
