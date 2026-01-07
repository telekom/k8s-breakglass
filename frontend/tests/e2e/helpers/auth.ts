// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { Page, expect } from "@playwright/test";

/**
 * Test user configuration for E2E tests.
 * These users should be configured in the Keycloak realm.
 */
export interface TestUser {
  username: string;
  password: string;
  displayName: string;
  email: string;
  groups: string[];
}

/**
 * Pre-configured test users matching the Keycloak E2E realm setup.
 */
export interface TestUsers {
  requester: TestUser;
  approver: TestUser;
  admin: TestUser;
}

export const TEST_USERS: TestUsers = {
  requester: {
    username: "bob@example.com",
    password: "bob123",
    displayName: "Bob Developer",
    email: "bob@example.com",
    groups: ["developers", "team-alpha"],
  },
  approver: {
    username: "carol@example.com",
    password: "carol123",
    displayName: "Carol Security",
    email: "carol@example.com",
    groups: ["approvers", "security-team"],
  },
  admin: {
    username: "alice@example.com",
    password: "alice123",
    displayName: "Alice Admin",
    email: "alice@example.com",
    groups: ["platform-admins"],
  },
};

/**
 * Helper class for handling OIDC authentication via Keycloak in E2E tests.
 */
export class AuthHelper {
  constructor(private page: Page) {}

  /**
   * Log in via Keycloak OIDC flow.
   * Navigates to the app, gets redirected to Keycloak, fills credentials,
   * and waits for redirect back to the app.
   */
  async loginViaKeycloak(user: TestUser): Promise<void> {
    // Navigate to app - should redirect to Keycloak
    await this.page.goto("/");

    // Wait for Keycloak login page (may take a moment)
    await this.page.waitForURL(/.*keycloak.*|.*auth.*/, { timeout: 30000 });

    // Fill login form
    await this.page.fill("#username", user.username);
    await this.page.fill("#password", user.password);
    await this.page.click("#kc-login");

    // Wait for redirect back to app
    await this.page.waitForURL(/localhost:5173/, { timeout: 30000 });

    // Verify logged in state - wait for user menu to appear
    await expect(this.page.locator('[data-testid="user-menu"]')).toBeVisible({
      timeout: 10000,
    });
  }

  /**
   * Log out of the application.
   */
  async logout(): Promise<void> {
    await this.page.click('[data-testid="user-menu"]');
    await this.page.click('[data-testid="logout-button"]');
    await this.page.waitForURL(/.*keycloak.*|.*login.*/, { timeout: 15000 });
  }

  /**
   * Check if the user is currently logged in.
   */
  async isLoggedIn(): Promise<boolean> {
    try {
      await this.page.locator('[data-testid="user-menu"]').waitFor({ timeout: 3000 });
      return true;
    } catch {
      return false;
    }
  }

  /**
   * Get the currently logged in user's display name.
   */
  async getCurrentUserName(): Promise<string | null> {
    try {
      const userMenu = this.page.locator('[data-testid="user-menu"]');
      await userMenu.waitFor({ timeout: 3000 });
      return await userMenu.textContent();
    } catch {
      return null;
    }
  }
}
