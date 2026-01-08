// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { Page } from "@playwright/test";

/**
 * Helper class for cleaning up test data via API calls.
 * Uses the authenticated user's OIDC token to make API requests.
 *
 * IMPORTANT: This class extracts the Bearer token from the OIDC storage
 * (sessionStorage/localStorage) and sends it in the Authorization header.
 * The frontend uses OIDC token-based auth, NOT cookies, so we must include
 * the Bearer token explicitly in API calls.
 */
export class APICleanupHelper {
  private baseUrl: string;

  constructor(
    private page: Page,
    baseUrl?: string,
  ) {
    // Use empty string by default to make relative API calls through the page's origin
    this.baseUrl = baseUrl ?? "";
  }

  /**
   * Extract the OIDC access token from browser storage.
   * The oidc-client-ts library stores the user object in sessionStorage or localStorage
   * with a key pattern of "oidc.user:<authority>:<client_id>".
   */
  private async getAccessToken(): Promise<string | null> {
    try {
      const token = await this.page.evaluate(() => {
        // Search for OIDC user data in both sessionStorage and localStorage
        const storages = [window.sessionStorage, window.localStorage];
        for (const storage of storages) {
          for (let i = 0; i < storage.length; i++) {
            const key = storage.key(i);
            if (key && key.startsWith("oidc.user:")) {
              const value = storage.getItem(key);
              if (value) {
                try {
                  const userData = JSON.parse(value);
                  if (userData.access_token) {
                    return userData.access_token;
                  }
                } catch {
                  // ignore parse errors
                }
              }
            }
          }
        }
        return null;
      });
      return token;
    } catch (e) {
      console.warn("Failed to get access token from storage:", e);
      return null;
    }
  }

  /**
   * Get pending sessions for the current user.
   * Makes an authenticated API call using the OIDC Bearer token.
   */
  async getPendingSessions(): Promise<any[]> {
    try {
      const token = await this.getAccessToken();
      if (!token) {
        console.warn("No access token found - user may not be authenticated");
        return [];
      }

      const response = await this.page.evaluate(
        async ({ apiBase, authToken }) => {
          const resp = await fetch(`${apiBase}/api/breakglassSessions?mine=true`, {
            headers: {
              Accept: "application/json",
              Authorization: `Bearer ${authToken}`,
            },
          });
          if (!resp.ok) {
            console.warn(`Failed to fetch sessions: ${resp.status}`);
            return [];
          }
          const data = await resp.json();
          return data.items || data || [];
        },
        { apiBase: this.baseUrl, authToken: token },
      );
      return response;
    } catch (e) {
      console.warn("Failed to get pending sessions:", e);
      return [];
    }
  }

  /**
   * Withdraw a specific session by name.
   */
  async withdrawSession(sessionName: string): Promise<boolean> {
    try {
      const token = await this.getAccessToken();
      if (!token) {
        console.warn("No access token found - cannot withdraw session");
        return false;
      }

      const success = await this.page.evaluate(
        async ({ apiBase, name, authToken }) => {
          const resp = await fetch(`${apiBase}/api/breakglassSessions/${encodeURIComponent(name)}/withdraw`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${authToken}`,
            },
            body: JSON.stringify({}),
          });
          return resp.ok;
        },
        { apiBase: this.baseUrl, name: sessionName, authToken: token },
      );
      return success;
    } catch (e) {
      console.warn(`Failed to withdraw session ${sessionName}:`, e);
      return false;
    }
  }

  /**
   * Withdraw all pending sessions for the current user.
   * This is useful for cleaning up test state before running tests.
   */
  async withdrawAllPendingSessions(): Promise<number> {
    const sessions = await this.getPendingSessions();
    let withdrawnCount = 0;

    for (const session of sessions) {
      const name = session.metadata?.name || session.name;
      const state = session.status?.state || session.state;

      // Only withdraw pending sessions
      if (state === "Pending" && name) {
        const success = await this.withdrawSession(name);
        if (success) {
          withdrawnCount++;
          console.log(`Withdrawn pending session: ${name}`);
        }
      }
    }

    return withdrawnCount;
  }

  /**
   * Drop all active sessions for the current user.
   */
  async dropSession(sessionName: string): Promise<boolean> {
    try {
      const token = await this.getAccessToken();
      if (!token) {
        console.warn("No access token found - cannot drop session");
        return false;
      }

      const success = await this.page.evaluate(
        async ({ apiBase, name, authToken }) => {
          const resp = await fetch(`${apiBase}/api/breakglassSessions/${encodeURIComponent(name)}/drop`, {
            method: "POST",
            headers: {
              "Content-Type": "application/json",
              Authorization: `Bearer ${authToken}`,
            },
            body: JSON.stringify({}),
          });
          return resp.ok;
        },
        { apiBase: this.baseUrl, name: sessionName, authToken: token },
      );
      return success;
    } catch (e) {
      console.warn(`Failed to drop session ${sessionName}:`, e);
      return false;
    }
  }

  /**
   * Clean up all sessions (pending and active) for the current user.
   * Handles various state formats (e.g., "Pending", "pending", "WaitingForApproval", etc.)
   */
  async cleanupAllSessions(): Promise<{ withdrawn: number; dropped: number }> {
    const sessions = await this.getPendingSessions();
    let withdrawn = 0;
    let dropped = 0;

    for (const session of sessions) {
      const name = session.metadata?.name || session.name;
      const state = (session.status?.state || session.state || "").toLowerCase();

      if (!name) continue;

      // Withdraw any pending-like states (Pending, WaitingForApproval, WaitingForScheduledTime, etc.)
      if (state.includes("pending") || state.includes("waiting")) {
        if (await this.withdrawSession(name)) {
          withdrawn++;
        }
      } else if (state === "active" || state === "approved") {
        if (await this.dropSession(name)) {
          dropped++;
        }
      }
    }

    return { withdrawn, dropped };
  }
}

/**
 * Convenience function to clean up all pending sessions for a user.
 * Call this after logging in but before running tests that need clean state.
 */
export async function cleanupPendingSessions(page: Page, baseUrl?: string): Promise<number> {
  const helper = new APICleanupHelper(page, baseUrl);
  return helper.withdrawAllPendingSessions();
}
