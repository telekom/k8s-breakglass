// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { Page, Locator, expect } from "@playwright/test";

/**
 * Helper utilities for interacting with Telekom Scale web components.
 * Scale components (scale-input, scale-textarea, etc.) are custom elements
 * that render internal native elements. Playwright's fill() doesn't work
 * directly on the custom element - we need to target the internal native element.
 */
export class ScaleComponentHelper {
  constructor(private page: Page) {}

  /**
   * Fill a scale-textarea component.
   * The internal textarea has class 'textarea__control'.
   * @param selector - The selector for the scale-textarea element (e.g., '[data-testid="reason-input"]')
   * @param value - The text to fill
   */
  async fillTextarea(selector: string, value: string): Promise<void> {
    const scaleTextarea = this.page.locator(selector);
    // Wait for the component to be visible
    await scaleTextarea.waitFor({ state: "visible" });
    // Target the internal native textarea
    const internalTextarea = scaleTextarea.locator("textarea.textarea__control");
    await internalTextarea.fill(value);
  }

  /**
   * Fill a scale-textarea using a locator.
   * @param locator - Locator for the scale-textarea element
   * @param value - The text to fill
   */
  async fillTextareaLocator(locator: Locator, value: string): Promise<void> {
    await locator.waitFor({ state: "visible" });
    const internalTextarea = locator.locator("textarea.textarea__control");
    await internalTextarea.fill(value);
  }

  /**
   * Fill a scale-input or scale-text-field component.
   * In Scale beta.159+ (Stencil 4), scale-text-field uses class 'text-field__control'
   * and scale-input uses class 'input__input'. We find the first <input> element
   * inside the component regardless of class name for maximum compatibility.
   * @param selector - The selector for the scale-input or scale-text-field element
   * @param value - The text to fill
   */
  async fillInput(selector: string, value: string): Promise<void> {
    const scaleInput = this.page.locator(selector);
    await scaleInput.waitFor({ state: "visible" });
    const internalInput = scaleInput.locator("input").first();
    await internalInput.fill(value);
  }

  /**
   * Fill a scale-text-field component.
   * Scale text-field uses a different internal structure - look for input inside.
   * Falls back to trying multiple selector patterns for compatibility.
   * @param selector - The selector for the scale-text-field element
   * @param value - The text to fill
   */
  async fillTextField(selector: string, value: string): Promise<void> {
    const scaleTextField = this.page.locator(selector);
    await scaleTextField.waitFor({ state: "visible" });
    // Try different internal input patterns used by Scale components
    const internalInput = scaleTextField.locator("input").first();
    if ((await internalInput.count()) > 0) {
      await internalInput.fill(value);
    } else {
      // Fallback: try to fill the element directly (may work for native inputs)
      await scaleTextField.fill(value);
    }
  }

  /**
   * Clear and type into a scale-textarea component.
   * Useful when you need keyboard events to trigger.
   * @param selector - The selector for the scale-textarea element
   * @param value - The text to type
   */
  async typeInTextarea(selector: string, value: string): Promise<void> {
    const scaleTextarea = this.page.locator(selector);
    await scaleTextarea.waitFor({ state: "visible" });
    const internalTextarea = scaleTextarea.locator("textarea.textarea__control");
    await internalTextarea.clear();
    await internalTextarea.type(value);
  }

  /**
   * Get the value of a scale-textarea component.
   * @param selector - The selector for the scale-textarea element
   * @returns The current value
   */
  async getTextareaValue(selector: string): Promise<string> {
    const scaleTextarea = this.page.locator(selector);
    const internalTextarea = scaleTextarea.locator("textarea.textarea__control");
    return internalTextarea.inputValue();
  }
}

/**
 * Convenience function to fill a scale-textarea.
 * Can be used directly on a page without creating a helper instance.
 */
export async function fillScaleTextarea(page: Page, selector: string, value: string): Promise<void> {
  const helper = new ScaleComponentHelper(page);
  await helper.fillTextarea(selector, value);
}

/**
 * Convenience function to fill a scale-input.
 */
export async function fillScaleInput(page: Page, selector: string, value: string): Promise<void> {
  const helper = new ScaleComponentHelper(page);
  await helper.fillInput(selector, value);
}

/**
 * Convenience function to fill a scale-text-field.
 */
export async function fillScaleTextField(page: Page, selector: string, value: string): Promise<void> {
  const helper = new ScaleComponentHelper(page);
  await helper.fillTextField(selector, value);
}

/**
 * Wait for a Scale notification toast to appear.
 * Scale's notification toast uses an internal 'opened' state to control visibility.
 * In Stencil 4 (Scale beta.159+) the 'opened' @State() no longer reflects as
 * an HTML attribute, so we check the property value via JS evaluation instead.
 * @param page - Playwright page
 * @param testId - The data-testid of the toast (e.g., 'success-toast' or 'error-toast')
 * @param timeout - Maximum time to wait in milliseconds (default: 20000)
 */
export async function waitForScaleToast(
  page: Page,
  testId: "success-toast" | "error-toast",
  timeout = 20000,
  { waitForAnimation = true }: { waitForAnimation?: boolean } = {},
): Promise<void> {
  // Poll for element existence AND its 'opened' JS property in one shot.
  // page.waitForFunction runs in the browser context and does not require
  // the element to exist before polling starts — unlike locator.evaluateHandle
  // which times out if the locator can't find the element in the DOM.
  // Uses querySelectorAll to handle multiple toasts with the same test id.
  await page.waitForFunction(
    (tid: string) => {
      const elements = document.querySelectorAll(`[data-testid="${tid}"]`);
      for (const el of Array.from(elements)) {
        const toast = el as HTMLElement & { opened?: boolean };
        if (toast.opened === true) {
          return true;
        }
      }
      return false;
    },
    testId,
    { timeout },
  );
  // Additional wait for toast animation to complete and be fully visible
  if (waitForAnimation) {
    await page.waitForTimeout(500);
  }
}

/**
 * Check if a Scale notification toast appeared.
 * This is a soft check that returns true/false instead of throwing.
 * @param page - Playwright page
 * @param testId - The data-testid of the toast
 * @param timeout - Maximum time to wait in milliseconds (default: 5000)
 */
export async function hasScaleToast(
  page: Page,
  testId: "success-toast" | "error-toast",
  timeout = 5000,
): Promise<boolean> {
  try {
    await waitForScaleToast(page, testId, timeout, { waitForAnimation: false });
    return true;
  } catch {
    return false;
  }
}

/**
 * Find an escalation card that has the "Request access" button available.
 * Escalation cards can have different states:
 * - "Available" with "Request access" button
 * - "Pending request" with "Withdraw" button
 *
 * This helper finds a card that's in an available state for new requests.
 * If autoCleanup is true and no available card is found, it will attempt to
 * withdraw any pending sessions and retry.
 *
 * @param page - Playwright page
 * @param options - Options for finding the card
 * @param options.timeout - Maximum time to wait in milliseconds (default: 10000)
 * @param options.autoCleanup - If true, will attempt to withdraw pending sessions and retry (default: true)
 * @returns Locator for an available escalation card, or null if none found
 */
export async function findAvailableEscalationCard(
  page: Page,
  options: { timeout?: number; autoCleanup?: boolean } = {},
): Promise<import("@playwright/test").Locator | null> {
  const timeout = options.timeout ?? 10000;
  const autoCleanup = options.autoCleanup ?? true;

  // Wait for the escalation list to load
  await page.waitForSelector('[data-testid="escalation-list"]', { timeout });

  // Helper function to search for available card
  async function searchForCard(): Promise<import("@playwright/test").Locator | null> {
    const cards = page.locator('[data-testid="escalation-card"]');
    const count = await cards.count();

    // Find a card that has a visible "Request access" button
    for (let i = 0; i < count; i++) {
      const card = cards.nth(i);
      const requestButton = card.locator('[data-testid="request-access-button"]');
      if (await requestButton.isVisible({ timeout: 1000 }).catch(() => false)) {
        return card;
      }
    }
    return null;
  }

  // First attempt
  let card = await searchForCard();
  if (card) return card;

  // If no card found and autoCleanup is enabled, try to clean up pending sessions
  if (autoCleanup) {
    // Dynamically import cleanup helper to avoid circular deps
    const { APICleanupHelper } = await import("./api-cleanup");
    const cleanup = new APICleanupHelper(page);
    const result = await cleanup.cleanupAllSessions();

    if (result.withdrawn > 0 || result.dropped > 0) {
      // Wait a bit for UI to update after cleanup
      await page.waitForTimeout(500);

      // Navigate to home to refresh the escalation list
      await page.goto("/");
      await page.waitForLoadState("networkidle");
      await page.waitForSelector('[data-testid="escalation-list"]', { timeout });

      // Try again after cleanup
      card = await searchForCard();
    }
  }

  return card;
}

/**
 * Get all escalation cards that have the "Request access" button available.
 * Useful when you need to verify multiple cards are in available state.
 * @param page - Playwright page
 * @returns Array of locators for available escalation cards
 */
export async function getAvailableEscalationCards(page: Page): Promise<import("@playwright/test").Locator[]> {
  const cards = page.locator('[data-testid="escalation-card"]');
  const count = await cards.count();
  const availableCards: import("@playwright/test").Locator[] = [];

  for (let i = 0; i < count; i++) {
    const card = cards.nth(i);
    const requestButton = card.locator('[data-testid="request-access-button"]');
    if (await requestButton.isVisible({ timeout: 500 }).catch(() => false)) {
      availableCards.push(card);
    }
  }

  return availableCards;
}

/**
 * Find an escalation card by its escalation name (the group name displayed on the card).
 * This is useful for tests that need to target a specific escalation to avoid conflicts.
 *
 * @param page - Playwright page
 * @param escalationName - The name of the escalation (e.g., "cluster-admin-access")
 * @param options - Options for finding the card
 * @param options.timeout - Maximum time to wait in milliseconds (default: 10000)
 * @param options.requireAvailable - If true, only returns the card if it has "Request access" button (default: false)
 * @param options.autoCleanup - If true and requireAvailable is true, will attempt to withdraw pending sessions (default: true)
 * @returns Locator for the escalation card, or null if not found
 */
export async function findEscalationCardByName(
  page: Page,
  escalationName: string,
  options: { timeout?: number; requireAvailable?: boolean; autoCleanup?: boolean } = {},
): Promise<import("@playwright/test").Locator | null> {
  const timeout = options.timeout ?? 10000;
  const requireAvailable = options.requireAvailable ?? false;
  const autoCleanup = options.autoCleanup ?? true;

  // Wait for the escalation list to load
  await page.waitForSelector('[data-testid="escalation-list"]', { timeout });

  // Helper function to search for card by name
  async function searchForCard(): Promise<import("@playwright/test").Locator | null> {
    const cards = page.locator('[data-testid="escalation-card"]');
    const count = await cards.count();

    for (let i = 0; i < count; i++) {
      const card = cards.nth(i);
      const nameElement = card.locator('[data-testid="escalation-name"]');
      const name = await nameElement.textContent().catch(() => null);

      if (name && name.trim() === escalationName) {
        // If we need the card to be available, check for request button
        if (requireAvailable) {
          const requestButton = card.locator('[data-testid="request-access-button"]');
          if (await requestButton.isVisible({ timeout: 1000 }).catch(() => false)) {
            return card;
          }
          // Card found but not available
          return null;
        }
        return card;
      }
    }
    return null;
  }

  // First attempt
  let card = await searchForCard();
  if (card) return card;

  // If we need an available card and autoCleanup is enabled, try to clean up
  if (requireAvailable && autoCleanup) {
    const { APICleanupHelper } = await import("./api-cleanup");
    const cleanup = new APICleanupHelper(page);
    const result = await cleanup.cleanupAllSessions();

    if (result.withdrawn > 0 || result.dropped > 0) {
      await page.waitForTimeout(500);
      await page.goto("/");
      await page.waitForLoadState("networkidle");
      await page.waitForSelector('[data-testid="escalation-list"]', { timeout });
      card = await searchForCard();
    }
  }

  return card;
}

/**
 * Open a Scale dropdown and wait for it to be ready.
 * Scale dropdowns use web components and may need time to render options.
 * This function ensures the dropdown is actually expanded and options are visible.
 * @param page - Playwright page
 * @param selector - Selector for the scale-dropdown-select element
 * @param waitMs - Additional time to wait after dropdown opens (default: 500ms for CI)
 */
export async function openScaleDropdown(page: Page, selector: string, waitMs = 500): Promise<void> {
  const dropdown = page.locator(selector);
  await dropdown.waitFor({ state: "visible", timeout: 10000 });

  // Click to open the dropdown
  await dropdown.click();

  // Wait for the dropdown animation to complete - CI environments need more time
  await page.waitForTimeout(waitMs);

  // Wait for the combobox to have the 'expanded' attribute (Scale component state)
  // The combobox inside scale-dropdown-select shows [expanded] when open
  const combobox = dropdown.locator('div[role="combobox"]');
  const maxRetries = 5; // Increased for CI
  let expanded = false;

  for (let attempt = 0; attempt < maxRetries && !expanded; attempt++) {
    try {
      await expect(combobox).toHaveAttribute("aria-expanded", "true", { timeout: 3000 });
      expanded = true;
    } catch {
      // If click didn't work, try clicking again
      await dropdown.click();
      await page.waitForTimeout(waitMs);
    }
  }

  if (!expanded) {
    throw new Error(`Failed to expand dropdown ${selector} after ${maxRetries} attempts`);
  }

  // Scale dropdown renders options in a listbox. The original scale-dropdown-select-option
  // elements are slotted and may not be directly visible. Instead, Scale creates a listbox
  // with [role="option"] elements that are the actual visible options.
  // We should wait for the listbox to have visible option elements.
  await page.waitForFunction(
    (sel) => {
      const dropdownEl = document.querySelector(sel);
      if (!dropdownEl) return false;

      // Scale renders a listbox element (either in light DOM or shadow DOM)
      // that contains the actual visible option elements with role="option"
      let listbox = dropdownEl.querySelector('[role="listbox"]');
      if (!listbox && dropdownEl.shadowRoot) {
        listbox = dropdownEl.shadowRoot.querySelector('[role="listbox"]');
      }

      if (!listbox) return false;

      // Check for option elements in the listbox
      const options = listbox.querySelectorAll('[role="option"]');
      if (options.length === 0) return false;

      // Check that at least one option is visible
      const firstOption = options[0];
      if (!firstOption) return false;

      const rect = firstOption.getBoundingClientRect();
      return rect.width > 0 && rect.height > 0;
    },
    selector,
    { timeout: 10000 }, // Increased timeout for CI
  );
}

/**
 * Assert that a Scale dropdown option with the given value exists and is available.
 * Scale Components render slotted scale-dropdown-select-option elements as hidden,
 * while creating visible [role="option"] elements in the listbox. This function
 * checks that either the slotted element exists OR the corresponding role="option"
 * element is visible in the listbox.
 *
 * @param page - Playwright page
 * @param dropdownSelector - Selector for the scale-dropdown-select element
 * @param optionValue - The value attribute of the option to check
 * @param timeout - Maximum time to wait in milliseconds (default: 5000)
 */
export async function assertScaleDropdownOptionAvailable(
  page: Page,
  dropdownSelector: string,
  optionValue: string,
  timeout = 5000,
): Promise<void> {
  // Check that the option is available in the dropdown
  // Scale renders options in two places:
  // 1. The slotted scale-dropdown-select-option (may be visibility:hidden)
  // 2. The [role="option"] elements in the listbox (actually visible)
  await page.waitForFunction(
    ({ sel, val }) => {
      const dropdown = document.querySelector(sel);
      if (!dropdown) return false;

      // Method 1: Check if slotted option exists
      const slottedOption = dropdown.querySelector(`scale-dropdown-select-option[value="${val}"]`);
      if (slottedOption) {
        // The option element exists - that's enough to prove the option is available
        return true;
      }

      // Method 2: Check if role="option" exists in listbox
      let listbox = dropdown.querySelector('[role="listbox"]');
      if (!listbox && dropdown.shadowRoot) {
        listbox = dropdown.shadowRoot.querySelector('[role="listbox"]');
      }
      if (listbox) {
        // Look for an option that contains the value in its data or text
        const options = Array.from(listbox.querySelectorAll('[role="option"]'));
        for (const opt of options) {
          const dataValue = opt.getAttribute("data-value") || opt.getAttribute("value");
          if (dataValue === val) return true;
        }
      }

      return false;
    },
    { sel: dropdownSelector, val: optionValue },
    { timeout },
  );
}

/**
 * Wait for a Scale modal to be fully visible.
 * Scale modals have an animation and may report as 'hidden' even when the `opened` attribute is set.
 * This function waits for both the attribute and actual visibility.
 * @param page - Playwright page
 * @param selector - Selector for the scale-modal element
 * @param timeout - Maximum time to wait in milliseconds (default: 5000)
 */
export async function waitForScaleModal(page: Page, selector: string, timeout = 5000): Promise<void> {
  const modal = page.locator(selector);

  // Wait for the modal element to be attached to the DOM
  await modal.waitFor({ state: "attached", timeout });

  // Wait for the 'opened' attribute to be present.
  // Vue binds `:opened="true"` which renders as `opened="true"` (not `opened=""`).
  // We need to check for the attribute presence, not its exact value.
  await page.waitForFunction(
    (sel) => {
      const el = document.querySelector(sel);
      return el && el.hasAttribute("opened");
    },
    selector,
    { timeout },
  );

  // Wait for the hydrated class (component fully loaded)
  await expect(modal).toHaveClass(/hydrated/, { timeout: 2000 });

  // Wait for CSS visibility to be "visible" - Scale components use CSS visibility transitions
  await page.waitForFunction(
    (sel) => {
      const modalEl = document.querySelector(sel);
      if (!modalEl) return false;
      const style = window.getComputedStyle(modalEl);
      // Check both visibility and display properties
      if (style.visibility !== "visible" || style.display === "none") return false;
      // Also check for any inner modal window/content
      const modalWindow = modalEl.querySelector('.modal__window, .modal, [class*="modal__content"]');
      if (modalWindow) {
        const windowStyle = window.getComputedStyle(modalWindow);
        return windowStyle.visibility === "visible" && windowStyle.display !== "none";
      }
      return true;
    },
    selector,
    { timeout: 3000 },
  );
}

/**
 * Select an option from a Scale dropdown.
 * Opens the dropdown, waits for options, and clicks the specified option.
 * Scale Components render slotted scale-dropdown-select-option as visibility:hidden.
 * The actual visible options are [role="option"] elements in the listbox.
 *
 * @param page - Playwright page
 * @param dropdownSelector - Selector for the scale-dropdown-select element
 * @param optionValue - The value attribute of the option to select (matches scale-dropdown-select-option value)
 */
export async function selectScaleDropdownOption(
  page: Page,
  dropdownSelector: string,
  optionValue: string,
): Promise<void> {
  await openScaleDropdown(page, dropdownSelector);

  const dropdown = page.locator(dropdownSelector);

  // First, get the text content of the slotted option with the matching value.
  // Scale renders slotted options as visibility:hidden, but we can still read their text.
  // Use .first() because Scale may render duplicate option elements during hydration.
  const slottedOption = dropdown.locator(`scale-dropdown-select-option[value="${optionValue}"]`).first();

  // Wait briefly for slotted option to exist
  await slottedOption.waitFor({ state: "attached", timeout: 3000 });
  const optionText = await slottedOption.textContent();

  if (optionText) {
    // Now find the visible [role="option"] in the listbox that has matching text.
    // The listbox options have text content matching the slotted option text.
    const listboxOption = dropdown
      .locator(`[role="listbox"] [role="option"]`)
      .filter({ hasText: optionText.trim() })
      .first();

    if ((await listboxOption.count()) > 0) {
      await listboxOption.waitFor({ state: "visible", timeout: 5000 });
      await listboxOption.click();
      return;
    }
  }

  // Fallback: force click on the slotted option (may work if Scale version differs)
  await slottedOption.click({ force: true });
}
