// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Tests for App component
 *
 * Covers:
 * - Theme/high-contrast toggle buttons expose aria labels and pressed states
 * - Theme toggle button aria-label, persistence, and high-contrast interaction
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
  "scale-icon-action-light-dark-mode": true,
  "scale-icon-action-visibility": true,
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

describe("App — high-contrast and theme toggles", () => {
  let wrapper: VueWrapper | null = null;

  beforeEach(() => {
    localStorage.clear();
    document.documentElement.removeAttribute("data-theme");
    document.documentElement.removeAttribute("data-mode");
    document.documentElement.removeAttribute("data-high-contrast");
    vi.spyOn(console, "warn").mockImplementation(() => {});
  });

  afterEach(() => {
    wrapper?.unmount();
    wrapper = null;
    vi.restoreAllMocks();
    localStorage.clear();
    document.documentElement.removeAttribute("data-theme");
    document.documentElement.removeAttribute("data-mode");
    document.documentElement.removeAttribute("data-high-contrast");
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
    expect(btn.attributes("aria-pressed")).toBe("false");
    expect(btn.classes()).not.toContain("hc-active");
  });

  it("shows enabled aria-label and hc-active class when high contrast is on", () => {
    localStorage.setItem("breakglass-theme", "light");
    localStorage.setItem("breakglass-high-contrast", "true");
    wrapper = mountApp();

    const btn = wrapper.find(".hc-toggle-button");
    expect(btn.attributes("aria-label")).toBe("High contrast mode enabled. Click to disable.");
    expect(btn.attributes("aria-pressed")).toBe("true");
    expect(btn.classes()).toContain("hc-active");

    const themeBtn = wrapper.find(".theme-toggle-button");
    expect(themeBtn.attributes("aria-label")).toBe(
      "High contrast mode is displaying dark theme. Click to select dark theme preference.",
    );
    expect(themeBtn.classes()).toContain("theme-dark");
  });

  it("toggles aria-label and hc-active class when the hc-toggle button is clicked", async () => {
    localStorage.setItem("breakglass-high-contrast", "false");
    wrapper = mountApp();

    const btn = wrapper.find(".hc-toggle-button");
    expect(btn.attributes("aria-label")).toBe("High contrast mode disabled. Click to enable.");
    expect(btn.attributes("aria-pressed")).toBe("false");
    expect(btn.classes()).not.toContain("hc-active");

    await btn.trigger("click");

    expect(btn.attributes("aria-label")).toBe("High contrast mode enabled. Click to disable.");
    expect(btn.attributes("aria-pressed")).toBe("true");
    expect(btn.classes()).toContain("hc-active");
  });

  it("shows the selected theme and persists manual theme changes", async () => {
    localStorage.setItem("breakglass-theme", "light");
    wrapper = mountApp();

    const btn = wrapper.find(".theme-toggle-button");
    expect(btn.exists()).toBe(true);
    expect(btn.attributes("aria-label")).toBe("Light theme selected. Click to select dark theme.");
    expect(btn.attributes("aria-pressed")).toBe("false");
    expect(btn.classes()).not.toContain("theme-dark");
    expect(document.documentElement.getAttribute("data-theme")).toBe("light");

    await btn.trigger("click");

    expect(btn.attributes("aria-label")).toBe("Dark theme selected. Click to select light theme.");
    expect(btn.attributes("aria-pressed")).toBe("true");
    expect(btn.classes()).toContain("theme-dark");
    expect(localStorage.getItem("breakglass-theme")).toBe("dark");
    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
  });

  it("keeps high contrast on the dark canvas until high contrast is disabled", async () => {
    localStorage.setItem("breakglass-theme", "dark");
    localStorage.setItem("breakglass-high-contrast", "true");
    wrapper = mountApp();

    expect(document.documentElement.getAttribute("data-high-contrast")).toBe("true");
    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
    expect(wrapper.find(".theme-toggle-button").attributes("aria-label")).toBe(
      "High contrast mode is displaying dark theme. Click to select light theme preference.",
    );

    await wrapper.find(".theme-toggle-button").trigger("click");

    expect(localStorage.getItem("breakglass-theme")).toBe("light");
    expect(document.documentElement.getAttribute("data-theme")).toBe("dark");
    expect(wrapper.find(".theme-toggle-button").attributes("aria-label")).toBe(
      "High contrast mode is displaying dark theme. Click to select dark theme preference.",
    );
    expect(wrapper.find(".theme-toggle-button").classes()).toContain("theme-dark");

    await wrapper.find(".hc-toggle-button").trigger("click");

    expect(document.documentElement.hasAttribute("data-high-contrast")).toBe(false);
    expect(document.documentElement.getAttribute("data-theme")).toBe("light");
  });
});
