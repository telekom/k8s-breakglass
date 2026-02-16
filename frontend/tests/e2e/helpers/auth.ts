// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { Page } from "@playwright/test";

/**
 * Test user configuration for E2E tests.
 * These users MUST match the Keycloak realm configuration in:
 *   config/dev/resources/breakglass-e2e-realm.json
 *
 * The usernames and passwords here are synced with the Go E2E test users
 * defined in e2e/helpers/users.go to ensure consistency.
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
 *
 * IMPORTANT: These users MUST match config/dev/resources/breakglass-e2e-realm.json
 * and e2e/helpers/users.go. If you add new users, add them in all three places.
 *
 * Each E2E test should ideally use different users/escalations to avoid
 * session conflicts when tests run in parallel. Use the isolated users
 * (devAlpha, devBeta, debugSessionRequester, etc.) for tests that need isolation.
 */
export interface TestUsers {
  /** Primary requester for session requests - has many groups */
  requester: TestUser;
  /** Primary approver for session approvals */
  approver: TestUser;
  /** Internal approver (different email domain) */
  approverInternal: TestUser;
  /** Developer user with groups: dev, frontend-team, devs-a */
  devAlpha: TestUser;
  /** Developer user with groups: dev, backend-team, database-team, devs-b */
  devBeta: TestUser;
  /** Ops user with groups: ops, monitoring-team, ops-a */
  opsUser: TestUser;
  /** Tenant B user with groups: dev, tenant-b-team, devs-b */
  tenantBUser: TestUser;
  /** Senior approver with groups: approver, senior-ops, emergency-response */
  seniorApprover: TestUser;
  /** Debug session requester - isolated for debug session tests */
  debugSessionRequester: TestUser;
  /** Debug session approver - isolated for debug session tests */
  debugSessionApprover: TestUser;
  /** Bob - developer persona for UI E2E tests */
  bob: TestUser;
  /** Carol - security/approver persona for UI E2E tests */
  carol: TestUser;
  /** Alice - admin persona for UI E2E tests */
  alice: TestUser;
  // === Isolated UI E2E Test Users ===
  // Each test file has its own dedicated user with a unique group
  /** Isolated user for request-session.spec.ts */
  uiE2eReqSession: TestUser;
  /** Isolated user for approve-via-email.spec.ts */
  uiE2eApproveEmail: TestUser;
  /** Isolated user for reject-session.spec.ts */
  uiE2eRejectSession: TestUser;
  /** Isolated user for my-requests.spec.ts */
  uiE2eMyRequests: TestUser;
  /** Isolated user for pending-approvals.spec.ts */
  uiE2ePendingApprovals: TestUser;
  /** Shared approver for all UI E2E tests */
  uiE2eApprover: TestUser;
}

/**
 * Test users that match the Keycloak realm configuration.
 * Passwords are as configured in breakglass-e2e-realm.json.
 */
export const TEST_USERS: TestUsers = {
  requester: {
    username: "test-user",
    password: "test-password",
    displayName: "Test User",
    email: "test-user@example.com",
    groups: ["dev", "ops", "requester", "e2e-test-group"],
  },
  approver: {
    username: "approver-user",
    password: "approver-password",
    displayName: "Approver User",
    email: "approver@example.org",
    groups: ["approver", "senior-ops", "approval-notes"],
  },
  approverInternal: {
    username: "approver-internal",
    password: "approver-internal-password",
    displayName: "Approver Internal",
    email: "approver-internal@example.com",
    groups: ["approver", "senior-ops", "breakglass"],
  },
  devAlpha: {
    username: "dev-user-alpha",
    password: "dev-alpha-password",
    displayName: "Dev User Alpha",
    email: "dev-alpha@example.com",
    groups: ["dev", "frontend-team", "devs-a"],
  },
  devBeta: {
    username: "dev-user-beta",
    password: "dev-beta-password",
    displayName: "Dev User Beta",
    email: "dev-beta@example.com",
    groups: ["dev", "backend-team", "database-team", "devs-b"],
  },
  opsUser: {
    username: "ops-user-gamma",
    password: "ops-gamma-password",
    displayName: "Ops User Gamma",
    email: "ops-gamma@example.com",
    groups: ["ops", "monitoring-team", "ops-a"],
  },
  tenantBUser: {
    username: "tenant-b-user",
    password: "tenant-b-password",
    displayName: "Tenant B User",
    email: "tenant-b-user@example.com",
    groups: ["dev", "tenant-b-team", "devs-b"],
  },
  seniorApprover: {
    username: "senior-approver",
    password: "senior-approver-password",
    displayName: "Senior Approver",
    email: "senior-approver@example.com",
    groups: ["approver", "senior-ops", "emergency-response"],
  },
  debugSessionRequester: {
    username: "debug-session-requester",
    password: "debug-session-requester-password",
    displayName: "Debug Session Requester",
    email: "debug-session-requester@example.com",
    groups: ["debug-session-test-group", "dev"],
  },
  debugSessionApprover: {
    username: "debug-session-approver",
    password: "debug-session-approver-password",
    displayName: "Debug Session Approver",
    email: "debug-session-approver@example.com",
    groups: ["approver", "debug-session-approver"],
  },
  bob: {
    username: "bob@example.com",
    password: "bob123",
    displayName: "Bob Developer",
    email: "bob@example.com",
    groups: ["developers", "team-alpha", "requester", "dev", "ops"],
  },
  carol: {
    username: "carol@example.com",
    password: "carol123",
    displayName: "Carol Security",
    email: "carol@example.com",
    groups: ["approvers", "security-team", "approver", "senior-ops"],
  },
  alice: {
    username: "alice@example.com",
    password: "alice123",
    displayName: "Alice Admin",
    email: "alice@example.com",
    groups: ["platform-admins", "approver", "senior-ops", "emergency-response"],
  },
  // === Isolated UI E2E Test Users ===
  uiE2eReqSession: {
    username: "ui-e2e-req-session-user",
    password: "ui-e2e-req-session-password",
    displayName: "UI E2E Request Session User",
    email: "ui-e2e-req-session@example.com",
    groups: ["ui-e2e-req-session-requester"],
  },
  uiE2eApproveEmail: {
    username: "ui-e2e-approve-email-user",
    password: "ui-e2e-approve-email-password",
    displayName: "UI E2E Approve Email User",
    email: "ui-e2e-approve-email@example.com",
    groups: ["ui-e2e-approve-email-requester"],
  },
  uiE2eRejectSession: {
    username: "ui-e2e-reject-session-user",
    password: "ui-e2e-reject-session-password",
    displayName: "UI E2E Reject Session User",
    email: "ui-e2e-reject-session@example.com",
    groups: ["ui-e2e-reject-session-requester"],
  },
  uiE2eMyRequests: {
    username: "ui-e2e-my-requests-user",
    password: "ui-e2e-my-requests-password",
    displayName: "UI E2E My Requests User",
    email: "ui-e2e-my-requests@example.com",
    groups: ["ui-e2e-my-requests-requester"],
  },
  uiE2ePendingApprovals: {
    username: "ui-e2e-pending-approvals-user",
    password: "ui-e2e-pending-approvals-password",
    displayName: "UI E2E Pending Approvals User",
    email: "ui-e2e-pending-approvals@example.com",
    groups: ["ui-e2e-pending-approvals-requester"],
  },
  uiE2eApprover: {
    username: "ui-e2e-approver",
    password: "ui-e2e-approver-password",
    displayName: "UI E2E Approver",
    email: "ui-e2e-approver@example.com",
    groups: ["ui-e2e-approver-group", "senior-ops"],
  },
};

/**
 * Helper class for handling OIDC authentication via Keycloak in E2E tests.
 */
export class AuthHelper {
  constructor(private page: Page) {}

  /**
   * Check if user is already authenticated by looking for authenticated UI elements.
   * Returns true if authenticated elements are visible, false otherwise.
   */
  async isAuthenticated(): Promise<boolean> {
    // Check for any authenticated UI element (user menu, escalation list, or main content)
    const authIndicators = [
      '[data-testid="user-menu"]',
      '[data-testid="escalation-list"]',
      'h1:has-text("Request access")',
    ];

    for (const selector of authIndicators) {
      const isVisible = await this.page
        .locator(selector)
        .isVisible()
        .catch(() => false);
      if (isVisible) {
        return true;
      }
    }

    // Also check if login button is NOT visible
    const loginButton = this.page.locator('scale-button:has-text("Log In"), button:has-text("Log In")').first();
    const loginVisible = await loginButton.isVisible().catch(() => false);
    return !loginVisible;
  }

  /**
   * Click the login button on the app to initiate OIDC flow.
   * Returns true if login button was found and clicked, false if already on Keycloak.
   */
  async clickLoginButton(): Promise<boolean> {
    // Check if we're already on Keycloak
    const currentUrl = this.page.url();
    if (currentUrl.includes("keycloak") || currentUrl.includes("/auth/")) {
      return false;
    }

    // Look for the login button - it could be a scale-button or regular button
    // Scale buttons are web components that may need special handling
    const loginButton = this.page.locator('scale-button:has-text("Log In"), button:has-text("Log In")').first();

    try {
      await loginButton.waitFor({ state: "visible", timeout: 10000 });
      // Use force click for Scale web components which may have overlay elements
      await loginButton.click({ force: true });
      // Wait a moment for the OIDC redirect to initiate
      await this.page.waitForTimeout(500);
      return true;
    } catch {
      // Button not found - might already be redirecting or authenticated
      return false;
    }
  }

  /**
   * Keycloak redirect timeout (ms). Increased from 30s to 60s because
   * Keycloak in CI (kind cluster) can be slow to respond, especially
   * on the first login when JVM is still warming up.
   */
  private static readonly KEYCLOAK_TIMEOUT = 60_000;

  /**
   * Log in via Keycloak OIDC flow.
   * Navigates to the app, clicks login button, fills Keycloak credentials,
   * and waits for redirect back to the app.
   *
   * @param user - The test user to log in as
   */
  async loginViaKeycloak(user: TestUser): Promise<void> {
    // Navigate to app
    await this.page.goto("/");

    // Wait for page to load completely
    await this.page.waitForLoadState("networkidle");

    // Check if already authenticated by looking for authenticated UI elements
    const isAuthenticated = await this.isAuthenticated();
    if (isAuthenticated) {
      // Already logged in, no need to go through login flow
      return;
    }

    // Click login button to initiate OIDC flow
    const clicked = await this.clickLoginButton();
    if (!clicked) {
      // Check if we're already on Keycloak
      const currentUrl = this.page.url();
      if (!currentUrl.includes("keycloak") && !currentUrl.includes("/auth/")) {
        throw new Error(`Login button not found and not on Keycloak. Current URL: ${currentUrl}`);
      }
    }

    // Wait for Keycloak login page — use generous timeout because Keycloak's
    // JVM can be slow in CI (cold-start on kind cluster runners).
    await this.page.waitForURL(/.*keycloak.*|.*auth.*/, { timeout: AuthHelper.KEYCLOAK_TIMEOUT });

    // Fill login form
    await this.page.fill("#username", user.username);
    await this.page.fill("#password", user.password);
    await this.page.click("#kc-login");

    // Wait for redirect back to app (use regex to match any localhost port)
    await this.page.waitForURL(/localhost:\d+/, { timeout: AuthHelper.KEYCLOAK_TIMEOUT });

    // Verify logged in state - wait for authenticated content to appear
    // The profile menu (data-testid="user-menu") may not be accessible in CI due to
    // Telekom Scale web component Shadow DOM rendering. Instead, verify authentication
    // by checking that the main authenticated content is visible.
    // Try multiple selectors in order of preference:
    // 1. User menu (ideal) - works when Scale components render correctly
    // 2. Escalation list (fallback) - shows when authenticated
    // 3. "Request access" heading (final fallback) - in authenticated view
    const authVerificationSelectors = [
      '[data-testid="user-menu"]',
      '[data-testid="escalation-list"]',
      'h1:has-text("Request access")',
    ];

    let verified = false;
    for (const selector of authVerificationSelectors) {
      try {
        await this.page.locator(selector).waitFor({ state: "visible", timeout: 5000 });
        verified = true;
        break;
      } catch {
        // Try next selector
      }
    }

    if (!verified) {
      throw new Error("Failed to verify authenticated state - no auth indicators found");
    }
  }

  /**
   * Log out of the application.
   * First tries to use the profile menu, falls back to JavaScript-based logout.
   * Scale web components use Shadow DOM, so we need special handling.
   */
  async logout(): Promise<void> {
    // Try clicking on the profile menu to open it
    const userMenu = this.page.locator('[data-testid="user-menu"]');
    const userMenuVisible = await userMenu.isVisible().catch(() => false);

    if (userMenuVisible) {
      await userMenu.click();
      // Wait a bit for the menu to open
      await this.page.waitForTimeout(500);

      // Scale components use Shadow DOM, so we need to use JavaScript to find and click the logout
      // The profile menu has a logoutHandler set that calls the Vue logout function
      const logoutClicked = await this.page.evaluate(() => {
        // Try to find the profile menu element with the logoutHandler
        const profileMenu = document.querySelector('[data-testid="user-menu"]');
        if (profileMenu && (profileMenu as any).logoutHandler) {
          (profileMenu as any).logoutHandler();
          return true;
        }

        // Fallback: try to find logout link/button inside Shadow DOM
        const shadowRoot = profileMenu?.shadowRoot;
        if (shadowRoot) {
          // Scale profile menu renders logout as a link with the configured text
          const logoutLink = shadowRoot.querySelector('a[href="javascript:void(0);"]');
          if (logoutLink) {
            (logoutLink as HTMLElement).click();
            return true;
          }
          // Also try looking for any element with "Logout" text
          const allLinks = Array.from(shadowRoot.querySelectorAll("a, button"));
          for (const link of allLinks) {
            if (link.textContent?.includes("Logout")) {
              (link as HTMLElement).click();
              return true;
            }
          }
        }
        return false;
      });

      if (!logoutClicked) {
        // Fallback to clicking visible logout buttons in the page
        const logoutButton = this.page
          .locator('text=Logout, [data-testid="logout-button"], button:has-text("Logout"), a:has-text("Logout")')
          .first();
        const buttonVisible = await logoutButton.isVisible().catch(() => false);
        if (buttonVisible) {
          await logoutButton.click();
        } else {
          // Final fallback: use JavaScript auth service
          await this.triggerJsLogout();
        }
      }
    } else {
      // Fallback: Use JavaScript to trigger logout via exposed auth service
      await this.triggerJsLogout();
    }

    // Wait for logout to complete (may redirect to Keycloak or show login button)
    await this.page.waitForLoadState("networkidle", { timeout: 15000 });
  }

  /**
   * Trigger logout via JavaScript by calling the exposed auth service.
   * This is a fallback when the profile menu UI interaction fails.
   */
  private async triggerJsLogout(): Promise<void> {
    await this.page.evaluate(() => {
      const auth = (window as any).__BREAKGLASS_AUTH;
      if (auth && auth.logout) {
        auth.logout();
      } else {
        // Clear auth state by removing OIDC storage
        Object.keys(sessionStorage).forEach((key) => {
          if (key.startsWith("oidc.")) sessionStorage.removeItem(key);
        });
        Object.keys(localStorage).forEach((key) => {
          if (key.startsWith("oidc.")) localStorage.removeItem(key);
        });
        // Force reload to clear auth state
        window.location.href = "/";
      }
    });
  }

  /**
   * Check if the user is currently logged in.
   * Uses multiple selectors to handle Shadow DOM visibility issues with Scale components.
   */
  async isLoggedIn(): Promise<boolean> {
    // Try multiple auth indicators
    const authSelectors = [
      '[data-testid="user-menu"]',
      '[data-testid="escalation-list"]',
      'h1:has-text("Request access")',
    ];

    for (const selector of authSelectors) {
      try {
        await this.page.locator(selector).waitFor({ timeout: 2000 });
        return true;
      } catch {
        // Try next selector
      }
    }
    return false;
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
