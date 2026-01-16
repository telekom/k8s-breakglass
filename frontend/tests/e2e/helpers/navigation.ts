// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { Page, expect } from "@playwright/test";

/**
 * Helper class for navigating the Breakglass UI.
 */
export class NavigationHelper {
  constructor(private page: Page) {}

  /**
   * Navigate to the home page (escalation list).
   */
  async goToHome(): Promise<void> {
    await this.page.goto("/");
    await expect(this.page.locator('[data-testid="escalation-list"]')).toBeVisible();
  }

  /**
   * Navigate to the sessions browser.
   */
  async goToSessions(): Promise<void> {
    await this.page.goto("/sessions");
    await expect(this.page.locator('[data-testid="session-list"]')).toBeVisible();
  }

  /**
   * Navigate to the user's own requests.
   */
  async goToMyRequests(): Promise<void> {
    await this.page.goto("/requests/mine");
    await this.page.waitForLoadState("networkidle");
  }

  /**
   * Navigate to pending approvals.
   */
  async goToPendingApprovals(): Promise<void> {
    await this.page.goto("/approvals/pending");
    await this.page.waitForLoadState("networkidle");
  }

  /**
   * Navigate to debug sessions list.
   */
  async goToDebugSessions(): Promise<void> {
    await this.page.goto("/debug-sessions");
    await this.page.waitForLoadState("networkidle");
  }

  /**
   * Click on a navigation menu item by text.
   */
  async clickNavItem(text: string): Promise<void> {
    await this.page.locator(`nav >> text=${text}`).click();
    await this.page.waitForLoadState("networkidle");
  }

  /**
   * Wait for page to fully load.
   */
  async waitForPageLoad(): Promise<void> {
    await this.page.waitForLoadState("networkidle");
  }

  /**
   * Check if a specific route is active.
   */
  async isOnRoute(route: string): Promise<boolean> {
    const url = this.page.url();
    return url.includes(route);
  }

  /**
   * Get the current page title.
   */
  async getPageTitle(): Promise<string> {
    return await this.page.title();
  }
}

/**
 * Helper for waiting on various UI conditions.
 */
export class WaitHelper {
  constructor(private page: Page) {}

  /**
   * Wait for a toast notification to appear.
   */
  async waitForToast(type: "success" | "error" | "info" = "success"): Promise<string> {
    const selector = `[data-testid="${type}-toast"]`;
    const toast = this.page.locator(selector);
    await expect(toast).toBeVisible({ timeout: 10000 });
    return (await toast.textContent()) || "";
  }

  /**
   * Wait for a modal dialog to appear.
   */
  async waitForModal(testId: string): Promise<void> {
    await expect(this.page.locator(`[data-testid="${testId}"]`)).toBeVisible({
      timeout: 10000,
    });
  }

  /**
   * Wait for a modal to close.
   */
  async waitForModalClose(testId: string): Promise<void> {
    await expect(this.page.locator(`[data-testid="${testId}"]`)).not.toBeVisible({
      timeout: 10000,
    });
  }

  /**
   * Wait for loading state to complete.
   */
  async waitForLoading(): Promise<void> {
    // Wait for any loading indicators to disappear
    const loadingIndicator = this.page.locator('[data-testid="loading"]');
    if (await loadingIndicator.isVisible()) {
      await expect(loadingIndicator).not.toBeVisible({ timeout: 30000 });
    }
  }
}
