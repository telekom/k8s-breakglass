// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { test, expect, type Page } from "@playwright/test";
import { AuthHelper, TEST_USERS } from "./helpers";

type StoredOIDCUser = { access_token: string; id_token?: string; expires_at?: number };

async function storedOIDCUser(page: Page): Promise<StoredOIDCUser | null> {
  return page.evaluate(() => {
    for (const storage of [window.sessionStorage, window.localStorage]) {
      for (let index = 0; index < storage.length; index++) {
        const key = storage.key(index);
        const value = key?.startsWith("oidc.user:") ? storage.getItem(key) : null;
        if (value) return JSON.parse(value) as StoredOIDCUser;
      }
    }
    return null;
  });
}

// Resolves after the check_session_iframe has answered "unchanged" twice, i.e. it sees the
// IdP session and the UI has had a poll to record that.
function waitForConfirmedSession(page: Page, origin: string): Promise<void> {
  return page.evaluate(
    (iframeOrigin) =>
      new Promise<void>((resolve, reject) => {
        setTimeout(
          () => reject(new Error(`no "unchanged" from ${iframeOrigin}: third-party cookies blocked?`)),
          30_000,
        );
        let seen = 0;
        window.addEventListener("message", (event) => {
          if (event.origin === iframeOrigin && event.data === "unchanged" && ++seen >= 2) resolve();
        });
      }),
    origin,
  );
}

test.describe("IdP session end", () => {
  test("ending the Keycloak session signs the UI out; the old token is rejected after its lifetime", async ({
    page,
    request,
  }) => {
    // The second half waits for the access token to expire (5 minutes in the e2e realm).
    test.setTimeout(10 * 60_000);

    const discovery = await (await request.get("/api/oidc/authority/.well-known/openid-configuration")).json();
    const { frontend } = await (await request.get("/api/config")).json();
    expect(frontend.monitorSession).toBe(true);
    expect(discovery.check_session_iframe, "Keycloak publishes check_session_iframe").toBeTruthy();
    const iframeOrigin = new URL(discovery.check_session_iframe).origin;

    const auth = new AuthHelper(page);
    await auth.loginViaKeycloak(TEST_USERS.requester);
    const oidcUser = await storedOIDCUser(page);
    expect(oidcUser?.id_token).toBeTruthy();
    const { access_token: oldToken, id_token: idToken, expires_at: expiresAt } = oidcUser as StoredOIDCUser;

    await expect(page.locator(`iframe[src^="${iframeOrigin}"]`).first()).toBeAttached({ timeout: 30_000 });
    await waitForConfirmedSession(page, iframeOrigin);

    // Sign out at Keycloak in another tab of the same browser, as a user would at the SSO portal.
    const idpTab = await page.context().newPage();
    const logoutURL = new URL(discovery.end_session_endpoint);
    logoutURL.searchParams.set("id_token_hint", idToken as string);
    logoutURL.searchParams.set("client_id", frontend.oidcClientID);
    await idpTab.goto(logoutURL.toString());
    const confirm = idpTab.locator("#kc-logout");
    if (await confirm.isVisible().catch(() => false)) {
      await confirm.click();
      await idpTab.waitForLoadState("networkidle");
    }
    await idpTab.close();

    // The UI notices within the polling interval (2s) plus the prompt=none session query.
    const loginButton = page.locator('scale-button:has-text("Log In"), button:has-text("Log In")').first();
    await expect(loginButton).toBeVisible({ timeout: 30_000 });
    expect(await storedOIDCUser(page)).toBeNull();

    // A reload must not restore the session from browser storage.
    await page.reload();
    await expect(loginButton).toBeVisible({ timeout: 30_000 });
    expect(await storedOIDCUser(page)).toBeNull();

    // The API is stateless: the old access token stays valid until it expires, then it is rejected.
    const callAPI = () =>
      request.get("/api/breakglassSessions?mine=true", { headers: { Authorization: `Bearer ${oldToken}` } });
    expect((await callAPI()).status()).toBe(200);
    const waitMs = (expiresAt as number) * 1000 - Date.now() + 10_000;
    await page.waitForTimeout(Math.max(waitMs, 0));
    expect((await callAPI()).status()).toBe(401);
  });
});
