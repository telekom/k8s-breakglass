import type { Page } from "@playwright/test";

export async function performMockLogin(page: Page) {
  await page.goto("/");
  await page.waitForLoadState("networkidle");

  await page.waitForFunction(() => (window as unknown as Record<string, unknown>).__BREAKGLASS_AUTH !== undefined, {
    timeout: 10000,
  });

  await page.evaluate(() => {
    const auth = (window as unknown as Record<string, unknown>).__BREAKGLASS_AUTH as Record<string, unknown>;
    if (auth && typeof auth.login === "function") {
      auth.login({ path: "/", idpName: "production-keycloak" });
    }
  });

  await page.waitForTimeout(500);
  await page.waitForLoadState("networkidle");
  await page.waitForSelector("#main > :not(.login-gate)", { timeout: 5000 });
}

export async function navigateWithRouter(page: Page, path: string) {
  await page.evaluate((targetPath) => {
    const router = (
      window as unknown as {
        __VUE_ROUTER__?: { push: (target: string) => Promise<unknown> | unknown };
      }
    ).__VUE_ROUTER__;
    if (router && typeof router.push === "function") {
      return router.push(targetPath);
    }
    window.history.pushState({}, "", targetPath);
    window.dispatchEvent(new PopStateEvent("popstate"));
    return undefined;
  }, path);

  await page.waitForTimeout(300);
  await page.waitForLoadState("networkidle");
}
