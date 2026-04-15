// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Tests for App component
 *
 * Covers:
 * - High-contrast toggle button aria-label and visual state reflect toggle state
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mount, VueWrapper } from "@vue/test-utils";
import { createRouter, createMemoryHistory } from "vue-router";
import App from "@/App.vue";
import { AuthKey, BrandingKey } from "@/keys";

// Stub heavy Scale web components so the test doesn't depend on custom element registrations.
const SCALE_STUBS = {
  "scale-telekom-app-shell": { template: "<div><slot name='header'/><slot/></div>" },
  "scale-telekom-header": { template: "<div><slot name='main-nav'/><slot name='functions'/></div>" },
  "scale-telekom-nav-list": { template: "<div><slot/></div>" },
  "scale-telekom-nav-item": { template: "<div><slot/></div>" },
  "scale-telekom-profile-menu": true,
  "scale-telekom-nav-flyout": true,
  "scale-telekom-mobile-flyout-canvas": true,
  "scale-telekom-mobile-menu": true,
  "scale-telekom-mobile-menu-item": true,
  "scale-icon-action-eye": true,
  "scale-icon-action-menu": true,
  "scale-button": true,
  ErrorToasts: true,
  AutoLogoutWarning: true,
  DebugPanel: true,
  ErrorBoundary: { template: "<div><slot/></div>" },
  RouterView: true,
  IDPSelector: true,
};

function createMockRouter() {
  const stub = { template: "<div/>" };
  return createRouter({
    history: createMemoryHistory(),
    routes: [
      { path: "/", name: "home", component: stub },
      { path: "/approvals/pending", name: "pendingApprovals", component: stub },
      { path: "/sessions/review", name: "breakglassSessionReview", component: stub },
      { path: "/requests/mine", name: "myPendingRequests", component: stub },
      { path: "/sessions", name: "sessionBrowser", component: stub },
      { path: "/debug-sessions", name: "debugSessionBrowser", component: stub },
      { path: "/debug-sessions/create", name: "debugSessionCreate", component: stub },
      { path: "/debug-sessions/:name", name: "debugSessionDetails", component: stub },
    ],
  });
}

function createMockAuth() {
  return {
    getAccessToken: vi.fn().mockResolvedValue(null),
    login: vi.fn(),
    logout: vi.fn(),
  };
}

describe("App — high-contrast toggle", () => {
  let wrapper: VueWrapper | null = null;

  beforeEach(() => {
    localStorage.clear();
    vi.spyOn(console, "warn").mockImplementation(() => {});
  });

  afterEach(() => {
    wrapper?.unmount();
    wrapper = null;
    vi.restoreAllMocks();
    localStorage.clear();
  });

  function mountApp() {
    const router = createMockRouter();
    return mount(App, {
      global: {
        plugins: [router],
        provide: {
          [AuthKey as symbol]: createMockAuth(),
          [BrandingKey as symbol]: "Test",
        },
        stubs: SCALE_STUBS,
      },
    });
  }

  it("shows disabled aria-label and no hc-active class when high contrast is off", () => {
    localStorage.setItem("breakglass-high-contrast", "false");
    wrapper = mountApp();

    const btn = wrapper.find(".hc-toggle-button");
    expect(btn.exists()).toBe(true);
    expect(btn.attributes("aria-label")).toBe("High contrast mode disabled. Click to enable.");
    expect(btn.classes()).not.toContain("hc-active");
  });

  it("shows enabled aria-label and hc-active class when high contrast is on", () => {
    localStorage.setItem("breakglass-high-contrast", "true");
    wrapper = mountApp();

    const btn = wrapper.find(".hc-toggle-button");
    expect(btn.attributes("aria-label")).toBe("High contrast mode enabled. Click to disable.");
    expect(btn.classes()).toContain("hc-active");
  });

  it("toggles aria-label and hc-active class when the hc-toggle button is clicked", async () => {
    localStorage.setItem("breakglass-high-contrast", "false");
    wrapper = mountApp();

    const btn = wrapper.find(".hc-toggle-button");
    expect(btn.attributes("aria-label")).toBe("High contrast mode disabled. Click to enable.");
    expect(btn.classes()).not.toContain("hc-active");

    await btn.trigger("click");

    expect(btn.attributes("aria-label")).toBe("High contrast mode enabled. Click to disable.");
    expect(btn.classes()).toContain("hc-active");
  });
});
