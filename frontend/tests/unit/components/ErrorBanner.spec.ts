/**
 * Tests for ErrorBanner component
 *
 * Covers:
 * - Message and details rendering
 * - Variant types (danger, warning, info)
 * - Dismiss event emission
 * - Retry button rendering and click event
 * - Custom retry label
 * - Actions slot rendering
 * - Default slot (body content)
 */

import { describe, it, expect } from "vitest";
import { mount } from "@vue/test-utils";
import ErrorBanner from "@/components/common/ErrorBanner.vue";

describe("ErrorBanner", () => {
  function mountBanner(props: Record<string, unknown> = {}, slots: Record<string, string> = {}) {
    return mount(ErrorBanner, { props: { message: "Something failed", ...props }, slots });
  }

  describe("message rendering", () => {
    it("passes message as heading to scale-notification", () => {
      const wrapper = mountBanner();
      const notification = wrapper.find("scale-notification");
      expect(notification.attributes("heading")).toBe("Something failed");
    });

    it("renders details paragraph when details prop is provided", () => {
      const wrapper = mountBanner({ details: "Check your connection" });
      expect(wrapper.find(".error-banner__details").exists()).toBe(true);
      expect(wrapper.text()).toContain("Check your connection");
    });

    it("does not render details paragraph when details is empty", () => {
      const wrapper = mountBanner();
      expect(wrapper.find(".error-banner__details").exists()).toBe(false);
    });
  });

  describe("variants", () => {
    it("defaults to danger variant", () => {
      const wrapper = mountBanner();
      const notification = wrapper.find("scale-notification");
      expect(notification.attributes("variant")).toBe("danger");
    });

    it("applies warning variant", () => {
      const wrapper = mountBanner({ variant: "warning" });
      expect(wrapper.find("scale-notification").attributes("variant")).toBe("warning");
    });

    it("applies info variant", () => {
      const wrapper = mountBanner({ variant: "info" });
      expect(wrapper.find("scale-notification").attributes("variant")).toBe("info");
    });
  });

  describe("dismiss", () => {
    it("is not dismissible by default", () => {
      const wrapper = mountBanner();
      const notification = wrapper.find("scale-notification");
      // Vue renders boolean false as attribute string "false" for custom elements
      expect(notification.attributes("dismissible")).toBe("false");
    });

    it("passes dismissible attribute when true", () => {
      const wrapper = mountBanner({ dismissible: true });
      const notification = wrapper.find("scale-notification");
      expect(notification.attributes("dismissible")).toBeTruthy();
    });

    it("emits dismiss event when scale-close fires", async () => {
      const wrapper = mountBanner({ dismissible: true });
      const notification = wrapper.find("scale-notification");
      await notification.trigger("scale-close");
      expect(wrapper.emitted("dismiss")).toHaveLength(1);
    });
  });

  describe("retry button", () => {
    it("does not show retry button by default", () => {
      const wrapper = mountBanner();
      expect(wrapper.find("scale-button").exists()).toBe(false);
    });

    it("shows retry button when showRetry is true", () => {
      const wrapper = mountBanner({ showRetry: true });
      expect(wrapper.find("scale-button").exists()).toBe(true);
      expect(wrapper.text()).toContain("Retry");
    });

    it("uses custom retry label", () => {
      const wrapper = mountBanner({ showRetry: true, retryLabel: "Try Again" });
      expect(wrapper.text()).toContain("Try Again");
    });

    it("emits retry event when retry button is clicked", async () => {
      const wrapper = mountBanner({ showRetry: true });
      await wrapper.find("scale-button").trigger("click");
      expect(wrapper.emitted("retry")).toHaveLength(1);
    });
  });

  describe("slots", () => {
    it("renders default slot content", () => {
      const wrapper = mountBanner({}, { default: "<span class='custom'>Details here</span>" });
      expect(wrapper.html()).toContain("Details here");
    });

    it("renders actions slot content", () => {
      const wrapper = mountBanner({}, { actions: "<button>Custom Action</button>" });
      expect(wrapper.find(".error-banner__actions").exists()).toBe(true);
      expect(wrapper.text()).toContain("Custom Action");
    });

    it("shows actions area when showRetry is true even without actions slot", () => {
      const wrapper = mountBanner({ showRetry: true });
      expect(wrapper.find(".error-banner__actions").exists()).toBe(true);
    });
  });
});
