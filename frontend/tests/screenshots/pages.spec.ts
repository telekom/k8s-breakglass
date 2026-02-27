import { test, expect, Page } from "@playwright/test";

/**
 * UI Screenshot Tests for Breakglass Frontend
 *
 * These tests navigate to each page of the application and capture screenshots
 * in both light and dark mode for visual regression testing and PR review.
 *
 * The app runs with VITE_USE_MOCK_AUTH=true, which uses mock authentication.
 */

// Helper to wait for the page to be fully loaded
async function waitForPageLoad(page: Page) {
  await page.waitForLoadState("networkidle");
  await page.waitForTimeout(500);
}

// Helper to hide dynamic content that changes between runs
async function hideDynamicContent(page: Page) {
  await page.addStyleTag({
    content: `
      [data-testid="timestamp"],
      .timestamp,
      time {
        visibility: hidden !important;
      }
    `,
  });
}

// Helper to perform mock login
async function performMockLogin(page: Page) {
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

// Helper to navigate using Vue Router (preserves mock auth state)
async function navigateTo(page: Page, path: string) {
  await page.evaluate((targetPath) => {
    const router = (window as unknown as Record<string, unknown>).__VUE_ROUTER__ as Record<string, unknown>;
    if (router && typeof router.push === "function") {
      router.push(targetPath);
    } else {
      window.history.pushState({}, "", targetPath);
      window.dispatchEvent(new PopStateEvent("popstate"));
    }
  }, path);

  await page.waitForTimeout(300);
  await page.waitForLoadState("networkidle");
}

// Helper to set theme (light or dark) using Playwright's color scheme emulation
// This triggers the app's prefers-color-scheme media query handling
async function setTheme(page: Page, theme: "light" | "dark") {
  await page.emulateMedia({ colorScheme: theme });
  // Also set the attribute directly to ensure immediate effect
  await page.evaluate((t) => {
    document.documentElement.setAttribute("data-theme", t);
  }, theme);
  await page.waitForTimeout(200);
}

// Page definitions for screenshot capture
const pages = [
  { name: "home", path: "/", title: "Home - Request Access" },
  { name: "sessions", path: "/sessions", title: "Session Browser" },
  { name: "pending-approvals", path: "/approvals/pending", title: "Pending Approvals" },
  { name: "my-requests", path: "/requests/mine", title: "My Pending Requests" },
  { name: "session-review", path: "/sessions/review", title: "Session Review" },
  { name: "debug-sessions", path: "/debug-sessions", title: "Debug Sessions" },
  { name: "debug-session-create", path: "/debug-sessions/create", title: "Create Debug Session" },
  { name: "not-found", path: "/nonexistent-page", title: "404 Not Found" },
];

// Generate tests for each page in both themes
for (const pageInfo of pages) {
  for (const theme of ["light", "dark"] as const) {
    test(`${pageInfo.title} - ${theme} mode`, async ({ page }) => {
      // Set color scheme BEFORE loading page so app initializes with correct theme
      await page.emulateMedia({ colorScheme: theme });
      await page.setViewportSize({ width: 1280, height: 720 });
      await performMockLogin(page);

      // Navigate to the page (home is already loaded after login)
      if (pageInfo.path !== "/") {
        await navigateTo(page, pageInfo.path);
      }

      await setTheme(page, theme);
      await waitForPageLoad(page);
      await hideDynamicContent(page);

      await expect(page).toHaveScreenshot(`${pageInfo.name}-${theme}.png`, {
        fullPage: true,
      });
    });
  }
}

// Responsive tests - mobile and tablet views
const responsiveTests = [
  { name: "home-mobile", path: "/", width: 375, height: 667 },
  { name: "home-tablet", path: "/", width: 768, height: 1024 },
  { name: "sessions-mobile", path: "/sessions", width: 375, height: 667 },
];

for (const responsive of responsiveTests) {
  for (const theme of ["light", "dark"] as const) {
    test(`Responsive: ${responsive.name} - ${theme} mode`, async ({ page }) => {
      // Set color scheme BEFORE loading page so app initializes with correct theme
      await page.emulateMedia({ colorScheme: theme });
      await performMockLogin(page);
      await page.setViewportSize({ width: responsive.width, height: responsive.height });

      if (responsive.path !== "/") {
        await navigateTo(page, responsive.path);
      }

      await setTheme(page, theme);
      await waitForPageLoad(page);
      await hideDynamicContent(page);

      await expect(page).toHaveScreenshot(`${responsive.name}-${theme}.png`, {
        fullPage: true,
      });
    });
  }
}
