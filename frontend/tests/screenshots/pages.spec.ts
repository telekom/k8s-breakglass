import { test, expect, Page } from "@playwright/test";

/**
 * UI Screenshot Tests for Breakglass Frontend
 *
 * These tests navigate to each page of the application and capture screenshots
 * in light, dark, and high-contrast mode for visual regression testing and PR review.
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

// Helper to catch mobile layouts that accidentally widen the document.
async function expectNoHorizontalOverflow(page: Page, context: string) {
  const dimensions = await page.evaluate(() => ({
    documentClientWidth: document.documentElement.clientWidth,
    documentScrollWidth: document.documentElement.scrollWidth,
    bodyClientWidth: document.body.clientWidth,
    bodyScrollWidth: document.body.scrollWidth,
  }));

  expect(dimensions.documentScrollWidth, `${context}: document should not overflow horizontally`).toBeLessThanOrEqual(
    dimensions.documentClientWidth + 1,
  );
  expect(dimensions.bodyScrollWidth, `${context}: body should not overflow horizontally`).toBeLessThanOrEqual(
    dimensions.bodyClientWidth + 1,
  );
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

/** Theme mode type for screenshot tests. */
type ThemeMode = "light" | "dark" | "high-contrast" | "high-contrast-dark";

// Helper to set theme (light, dark, or high-contrast) using Playwright's color scheme emulation
// This triggers the app's prefers-color-scheme media query handling
async function setTheme(page: Page, theme: ThemeMode) {
  if (theme === "high-contrast") {
    await page.emulateMedia({ colorScheme: "light" });
    await page.evaluate(() => {
      document.documentElement.setAttribute("data-theme", "light");
      document.documentElement.setAttribute("data-mode", "light");
      document.documentElement.setAttribute("data-high-contrast", "true");
    });
  } else if (theme === "high-contrast-dark") {
    await page.emulateMedia({ colorScheme: "dark" });
    await page.evaluate(() => {
      document.documentElement.setAttribute("data-theme", "dark");
      document.documentElement.setAttribute("data-mode", "dark");
      document.documentElement.setAttribute("data-high-contrast", "true");
    });
  } else {
    await page.emulateMedia({ colorScheme: theme });
    await page.evaluate((t) => {
      document.documentElement.setAttribute("data-theme", t);
      document.documentElement.setAttribute("data-mode", t);
      document.documentElement.removeAttribute("data-high-contrast");
    }, theme);
  }
  await page.waitForTimeout(200);
}

// Page definitions for screenshot capture
const pages = [
  { name: "home", path: "/", title: "Request Access" },
  { name: "sessions", path: "/sessions", title: "Session Browser" },
  { name: "pending-approvals", path: "/approvals/pending", title: "Pending Approvals" },
  { name: "my-requests", path: "/requests/mine", title: "My Pending Requests" },
  { name: "session-review", path: "/sessions/review", title: "Session Review" },
  { name: "debug-sessions", path: "/debug-sessions", title: "Debug Sessions" },
  { name: "debug-session-create", path: "/debug-sessions/create", title: "Create Debug Session" },
  { name: "not-found", path: "/nonexistent-page", title: "404 Not Found" },
];

// Generate tests for each page in all theme modes
for (const pageInfo of pages) {
  for (const theme of ["light", "dark", "high-contrast", "high-contrast-dark"] as const) {
    test(`${pageInfo.title} - ${theme} mode`, async ({ page }) => {
      // Set color scheme BEFORE loading page so app initializes with correct theme
      await page.emulateMedia({
        colorScheme: theme === "high-contrast" ? "light" : theme === "high-contrast-dark" ? "dark" : theme,
      });
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
  {
    name: "debug-sessions-mobile",
    path: "/debug-sessions",
    width: 375,
    height: 667,
    readySelector: '[data-testid="debug-session-browser"]',
    assertNoHorizontalOverflow: true,
  },
  {
    name: "debug-session-details-mobile",
    path: "/debug-sessions/debug-network-001",
    width: 375,
    height: 667,
    readySelector: '[data-testid="debug-session-details"]',
    assertNoHorizontalOverflow: true,
  },
];

for (const responsive of responsiveTests) {
  for (const theme of ["light", "dark", "high-contrast", "high-contrast-dark"] as const) {
    test(`Responsive: ${responsive.name} - ${theme} mode`, async ({ page }) => {
      // Set color scheme BEFORE loading page so app initializes with correct theme
      await page.emulateMedia({
        colorScheme: theme === "high-contrast" ? "light" : theme === "high-contrast-dark" ? "dark" : theme,
      });
      await performMockLogin(page);
      await page.setViewportSize({ width: responsive.width, height: responsive.height });

      if (responsive.path !== "/") {
        await navigateTo(page, responsive.path);
      }

      await setTheme(page, theme);
      await waitForPageLoad(page);
      if (responsive.readySelector) {
        await page.waitForSelector(responsive.readySelector, { timeout: 5000 });
      }
      await hideDynamicContent(page);
      if (responsive.assertNoHorizontalOverflow) {
        await expectNoHorizontalOverflow(page, `${responsive.name} ${theme}`);
      }

      await expect(page).toHaveScreenshot(`${responsive.name}-${theme}.png`, {
        fullPage: true,
      });
    });
  }
}

async function routeDebugTemplateLoadFailure(page: Page) {
  await page.route("**/api/debugSessions/templates", async (route) => {
    await route.fulfill({
      status: 500,
      contentType: "application/json",
      body: JSON.stringify({ error: "debug session template service unavailable" }),
    });
  });
}

async function captureDebugTemplateErrorState(
  page: Page,
  theme: ThemeMode,
  viewport: { width: number; height: number },
  screenshotName: string,
) {
  await routeDebugTemplateLoadFailure(page);
  await page.emulateMedia({ colorScheme: theme === "dark" || theme === "high-contrast-dark" ? "dark" : "light" });
  await page.setViewportSize(viewport);
  await performMockLogin(page);
  await navigateTo(page, "/debug-sessions/create");
  await setTheme(page, theme);
  await waitForPageLoad(page);
  await hideDynamicContent(page);

  await expect(page.getByTestId("debug-session-template-error-state")).toBeVisible();
  await expect(page.getByRole("button", { name: "Retry" })).toBeVisible();
  await page.addStyleTag({
    content: `
      .toast-region,
      .toast-wrapper,
      scale-notification-toast,
      [data-testid="error-toast"],
      [data-testid="success-toast"] {
        display: none !important;
        visibility: hidden !important;
      }
    `,
  });
  await page.evaluate(() => {
    if (document.activeElement instanceof HTMLElement) {
      document.activeElement.blur();
    }
  });

  await expect(page).toHaveScreenshot(screenshotName, {
    fullPage: true,
  });
}

test("Debug session create template error - light mode", async ({ page }) => {
  await captureDebugTemplateErrorState(
    page,
    "light",
    { width: 1280, height: 720 },
    "debug-session-create-template-error-light.png",
  );
});

test("Debug session create template error - mobile dark mode", async ({ page }) => {
  await captureDebugTemplateErrorState(
    page,
    "dark",
    { width: 390, height: 844 },
    "debug-session-create-template-error-mobile-dark.png",
  );
});
