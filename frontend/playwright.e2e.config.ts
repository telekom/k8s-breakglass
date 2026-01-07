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

  // Sequential execution for stateful tests
  fullyParallel: false,

  // More retries for E2E due to timing sensitivity
  retries: process.env.CI ? 3 : 1,

  // Single worker to ensure test isolation
  workers: 1,

  // Fail the build on CI if you accidentally left test.only in the source code
  forbidOnly: !!process.env.CI,

  // Longer timeouts for E2E
  timeout: 60000,
  expect: {
    timeout: 10000,
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

    // Slower actions for reliability
    actionTimeout: 15000,

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
