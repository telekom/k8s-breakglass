// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { Page, TestInfo } from "@playwright/test";

/**
 * Debug utilities for E2E tests.
 * Provides comprehensive logging and error capture to help diagnose CI failures.
 */

/**
 * Setup page event listeners for debugging.
 * Call this in test.beforeEach() to capture console errors and network failures.
 */
export function setupPageDebugListeners(page: Page, testInfo: TestInfo): void {
  const testName = testInfo.title;

  // Capture console errors
  page.on("console", (msg) => {
    if (msg.type() === "error") {
      console.log(`[${testName}] PAGE CONSOLE ERROR:`, msg.text());
    } else if (msg.type() === "warning") {
      // Only log warnings that might be relevant to test failures
      const text = msg.text();
      if (text.includes("401") || text.includes("403") || text.includes("auth") || text.includes("token")) {
        console.log(`[${testName}] PAGE CONSOLE WARNING:`, text);
      }
    }
  });

  // Capture unhandled page errors (JavaScript exceptions)
  page.on("pageerror", (err) => {
    console.log(`[${testName}] PAGE EXCEPTION:`, err.message);
    if (err.stack) {
      console.log(`[${testName}] PAGE EXCEPTION STACK:`, err.stack.split("\n").slice(0, 5).join("\n"));
    }
  });

  // Capture failed network requests (useful for API debugging)
  page.on("response", (response) => {
    const status = response.status();
    const url = response.url();

    // Log API failures (exclude static assets)
    if (status >= 400 && !url.includes(".js") && !url.includes(".css") && !url.includes(".png")) {
      console.log(`[${testName}] NETWORK FAILURE: ${status} ${response.request().method()} ${url}`);
    }
  });

  // Capture request failures (network errors, not HTTP errors)
  page.on("requestfailed", (request) => {
    const failure = request.failure();
    console.log(`[${testName}] REQUEST FAILED: ${request.method()} ${request.url()}`);
    if (failure) {
      console.log(`[${testName}] FAILURE REASON:`, failure.errorText);
    }
  });
}

/**
 * Log the current authentication state.
 * Useful for diagnosing auth-related test failures.
 */
export async function logAuthState(page: Page, context: string): Promise<void> {
  const authState = await page.evaluate(() => {
    const storages = [window.sessionStorage, window.localStorage];
    const oidcKeys: string[] = [];

    for (const storage of storages) {
      for (let i = 0; i < storage.length; i++) {
        const key = storage.key(i);
        if (key && key.startsWith("oidc.")) {
          oidcKeys.push(key);
        }
      }
    }

    // Check if we have a valid token
    let hasValidToken = false;
    let tokenExpiry: string | null = null;

    for (const storage of storages) {
      for (let i = 0; i < storage.length; i++) {
        const key = storage.key(i);
        if (key && key.startsWith("oidc.user:")) {
          const value = storage.getItem(key);
          if (value) {
            try {
              const userData = JSON.parse(value);
              if (userData.access_token) {
                hasValidToken = true;
                if (userData.expires_at) {
                  const expiryDate = new Date(userData.expires_at * 1000);
                  tokenExpiry = expiryDate.toISOString();
                }
              }
            } catch {
              // ignore parse errors
            }
          }
        }
      }
    }

    return {
      oidcKeys,
      hasValidToken,
      tokenExpiry,
      url: window.location.href,
    };
  });

  console.log(`[AUTH STATE - ${context}]`, JSON.stringify(authState, null, 2));
}

/**
 * Log current page state for debugging.
 * Captures URL, visible elements, and any error banners.
 */
export async function logPageState(page: Page, context: string): Promise<void> {
  const pageState = await page.evaluate(() => {
    const errorBanners = Array.from(document.querySelectorAll('[data-testid*="error"], .error, .scale-notification'))
      .map((el) => el.textContent?.trim())
      .filter(Boolean);

    const loadingIndicators = document.querySelectorAll(
      '[data-testid*="loading"], .loading, scale-loading-spinner',
    ).length;

    const visibleButtons = Array.from(document.querySelectorAll("scale-button, button"))
      .filter((el) => {
        const rect = el.getBoundingClientRect();
        return rect.width > 0 && rect.height > 0;
      })
      .map((el) => el.textContent?.trim())
      .filter(Boolean)
      .slice(0, 10); // Limit to first 10

    return {
      url: window.location.href,
      title: document.title,
      errorBanners,
      loadingIndicators,
      visibleButtons,
    };
  });

  console.log(`[PAGE STATE - ${context}]`, JSON.stringify(pageState, null, 2));
}

/**
 * Wait for a condition with detailed logging on timeout.
 * Unlike standard waitFor, this logs progress and state on failure.
 */
export async function waitForWithLogging(
  page: Page,
  description: string,
  condition: () => Promise<boolean>,
  options: { timeout?: number; pollInterval?: number } = {},
): Promise<void> {
  const timeout = options.timeout ?? 10000;
  const pollInterval = options.pollInterval ?? 500;
  const startTime = Date.now();

  while (Date.now() - startTime < timeout) {
    try {
      if (await condition()) {
        console.log(`[WAIT] ${description} - SUCCESS after ${Date.now() - startTime}ms`);
        return;
      }
    } catch {
      // Condition threw an error, continue waiting
    }
    await page.waitForTimeout(pollInterval);
  }

  // Timeout - log detailed state
  console.log(`[WAIT] ${description} - TIMEOUT after ${timeout}ms`);
  await logPageState(page, `waitFor timeout: ${description}`);
  throw new Error(`Timeout waiting for: ${description}`);
}

/**
 * Take a diagnostic screenshot with a descriptive name.
 * Useful for capturing state at key points in failing tests.
 */
export async function diagnosticScreenshot(page: Page, testInfo: TestInfo, name: string): Promise<void> {
  const safeName = name.replace(/[^a-zA-Z0-9-_]/g, "_");
  const screenshot = await page.screenshot();
  await testInfo.attach(`diagnostic-${safeName}`, {
    body: screenshot,
    contentType: "image/png",
  });
  console.log(`[SCREENSHOT] Captured: diagnostic-${safeName}`);
}

/**
 * Log API response details for debugging.
 * Use this when making direct API calls in tests.
 */
export function logApiResponse(context: string, url: string, status: number, body: unknown): void {
  console.log(`[API ${context}] ${status} ${url}`);
  if (status >= 400) {
    console.log(`[API ${context}] Response body:`, JSON.stringify(body, null, 2));
  }
}
