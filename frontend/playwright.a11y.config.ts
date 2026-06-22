// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { defineConfig, devices } from "@playwright/test";

const defaultMockApiPort = 8080;
const parseMockApiPort = (value: string | undefined): number => {
  if (!value?.trim()) {
    return defaultMockApiPort;
  }

  const parsedPort = Number(value);
  return Number.isInteger(parsedPort) && parsedPort > 0 ? parsedPort : defaultMockApiPort;
};

const mockApiPort = parseMockApiPort(process.env.MOCK_API_PORT);
const reuseExistingServer = process.env.PLAYWRIGHT_REUSE_EXISTING_SERVER === "true";

export default defineConfig({
  testDir: "./tests/e2e",
  testMatch: "a11y.spec.ts",

  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: process.env.CI ? 1 : undefined,
  timeout: 60000,

  reporter: [["html", { outputFolder: "playwright-report-a11y" }], ["list"]],

  use: {
    baseURL: "http://localhost:5173",
    trace: "on-first-retry",
    viewport: { width: 1280, height: 720 },
  },

  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] },
    },
  ],

  webServer: [
    {
      command: "node mock-api/server.mjs",
      port: mockApiPort,
      reuseExistingServer,
      env: {
        MOCK_API_PORT: String(mockApiPort),
      },
    },
    {
      command: "npm run dev",
      port: 5173,
      reuseExistingServer,
      env: {
        MOCK_API_PORT: String(mockApiPort),
        VITE_USE_MOCK_AUTH: "true",
      },
    },
  ],

  outputDir: "test-results-a11y",
});
