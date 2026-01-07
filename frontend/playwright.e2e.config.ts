// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { defineConfig, devices } from "@playwright/test";

/**
 * Playwright configuration for UI E2E testing.
 *
 * Unlike screenshot tests, these tests run against a real backend
 * (kind cluster with Keycloak, MailHog, etc.) and validate full
 * user workflows including OIDC authentication and email notifications.
 */
export default defineConfig({
  testDir: "./tests/e2e",

  // Enable parallel execution - E2E tests should be independent
  fullyParallel: true,

  // Reduce retries - if tests are flaky, fix them instead
  retries: process.env.CI ? 1 : 0,

  // Use 2 workers for faster execution while maintaining stability
  workers: process.env.CI ? 2 : 1,

  // Fail the build on CI if you accidentally left test.only in the source code
  forbidOnly: !!process.env.CI,

  // Reasonable timeouts - not overly generous
  timeout: 30000,
  expect: {
    timeout: 5000,
  },

  reporter: [["html", { outputFolder: "playwright-report-e2e" }], ["list"]],

  use: {
    // Real backend URL (not mock)
    baseURL: process.env.BREAKGLASS_UI_URL || "http://localhost:5173",

    // Capture traces and screenshots on failure
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",

    // Standard viewport
    viewport: { width: 1280, height: 720 },

    // Reasonable action timeout
    actionTimeout: 10000,

    // Accept self-signed certificates for Keycloak
    ignoreHTTPSErrors: true,
  },

  projects: [
    {
      name: "chromium-e2e",
      use: { ...devices["Desktop Chrome"] },
    },
  ],

  // No webServer - E2E tests run against existing kind cluster
});
