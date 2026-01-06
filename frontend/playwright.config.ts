import { defineConfig, devices } from "@playwright/test";

/**
 * Playwright configuration for UI screenshot testing.
 *
 * This runs the mock API server and Vite dev server, then captures
 * screenshots of all pages for visual regression testing.
 */
export default defineConfig({
  testDir: "./tests/screenshots",

  // Run tests in parallel
  fullyParallel: true,

  // Fail the build on CI if you accidentally left test.only in the source code
  forbidOnly: !!process.env.CI,

  // Retry on CI only
  retries: process.env.CI ? 2 : 0,

  // Opt out of parallel tests on CI for consistent screenshots
  workers: process.env.CI ? 1 : undefined,

  // Reporter to use
  reporter: [["html", { outputFolder: "playwright-report" }], ["list"]],

  // Snapshot settings - use platform-agnostic names for CI
  snapshotPathTemplate: "{testDir}/__screenshots__/{arg}{ext}",

  // Shared settings for all the projects below
  use: {
    // Base URL for the frontend
    baseURL: "http://localhost:5173",

    // Collect trace when retrying the failed test
    trace: "on-first-retry",

    // Screenshot settings
    screenshot: "on",

    // Viewport size for consistent screenshots
    viewport: { width: 1280, height: 720 },
  },

  // Configure projects for major browsers
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
    // Optionally add more browsers:
    // {
    //   name: 'firefox',
    //   use: { ...devices['Desktop Firefox'] },
    // },
    // {
    //   name: 'webkit',
    //   use: { ...devices['Desktop Safari'] },
    // },
  ],

  // Run local dev server before starting the tests
  webServer: [
    {
      // Start the mock API server
      command: "node mock-api/server.mjs",
      port: 8080,
      reuseExistingServer: !process.env.CI,
      env: {
        MOCK_API_PORT: "8080",
      },
    },
    {
      // Start the Vite dev server with mock auth
      command: "npm run dev",
      port: 5173,
      reuseExistingServer: !process.env.CI,
      env: {
        VITE_USE_MOCK_AUTH: "true",
      },
    },
  ],

  // Output directory for screenshots
  outputDir: "test-results",

  // Expect settings for screenshot comparison
  expect: {
    // Threshold for pixel difference (0-1, where 0 is exact match)
    toHaveScreenshot: {
      maxDiffPixelRatio: 0.05,
    },
  },
});
