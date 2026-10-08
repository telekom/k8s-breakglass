// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { expect, type Page } from "@playwright/test";

/** Helpers for the mock dev server (mock-api + VITE_USE_MOCK_AUTH). */

export async function settleMockRoute(page: Page): Promise<void> {
  await page.waitForLoadState("networkidle");
  await expect(page.locator('#main .loading-state, #main [aria-busy="true"]')).toHaveCount(0, { timeout: 15000 });
}

export async function mockLogin(page: Page): Promise<void> {
  await page.goto("/");
  await page.waitForFunction(() => (window as unknown as Record<string, unknown>).__BREAKGLASS_AUTH !== undefined);
  await page.evaluate(() => {
    const auth = (window as unknown as { __BREAKGLASS_AUTH: { login: (o: object) => void } }).__BREAKGLASS_AUTH;
    auth.login({ path: "/", idpName: "production-keycloak" });
  });
  await page.waitForSelector("#main > :not(.login-gate)");
  await settleMockRoute(page);
}

/** Client-side navigation, like following an in-app link. */
export async function mockNavigate(page: Page, path: string): Promise<void> {
  await page.evaluate((target) => {
    (window as unknown as { __VUE_ROUTER__: { push: (p: string) => void } }).__VUE_ROUTER__.push(target);
  }, path);
  await page.waitForURL((url) => url.pathname === path);
  // The router moves focus into #main 150ms after a real navigation; let that
  // happen first so it cannot steal focus from the control under test.
  // Duplicate navigations (same path) never move focus, hence the catch.
  await page
    .waitForFunction(() => document.getElementById("main")?.contains(document.activeElement), null, {
      timeout: 2000,
    })
    .catch(() => undefined);
  await settleMockRoute(page);
}
