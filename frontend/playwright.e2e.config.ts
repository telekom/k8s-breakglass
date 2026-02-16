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

  // These E2E tests run against a shared kind cluster with fixed users/escalations.
  // Run serially to avoid cross-test interference.
  fullyParallel: false,

  // Retry once on CI to handle transient issues (Keycloak cold-start,
  // network jitter on kind cluster runners).
  retries: process.env.CI ? 2 : 0,

  // Keep a single worker to avoid collisions in shared backend state.
  workers: 1,

  // Fail the build on CI if you accidentally left test.only in the source code
  forbidOnly: !!process.env.CI,

  // Reasonable timeouts for CI environment with potentially slower backend
  timeout: 60000,
  expect: {
    timeout: 10000,
  },

  reporter: [["html", { outputFolder: "playwright-report-e2e" }], ["list"]],

  use: {
    // Real backend URL - use controller-served UI on port 8080 (not Vite dev server)
    baseURL: process.env.BREAKGLASS_UI_URL || "http://localhost:8080",

    // Capture traces and screenshots on failure
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",

    // Standard viewport
    viewport: { width: 1280, height: 720 },

    // Action timeout increased for CI - Scale components can be slow to respond
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
