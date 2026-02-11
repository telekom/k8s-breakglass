/**
 * Tests for LoadingState component
 *
 * Covers:
 * - Default rendering with message and spinner
 * - Custom message prop
 * - Size variants (small, medium, large)
 * - Inline mode
 * - Accessibility attributes (role, aria-live)
 */

import { describe, it, expect } from "vitest";
import { mount } from "@vue/test-utils";
import LoadingState from "@/components/common/LoadingState.vue";

describe("LoadingState", () => {
  function mountLoading(props: Record<string, unknown> = {}) {
    return mount(LoadingState, { props });
  }

  describe("default rendering", () => {
    it("renders default 'Loading...' message", () => {
      const wrapper = mountLoading();
      expect(wrapper.text()).toContain("Loading...");
    });

    it("renders a spinner element", () => {
      const wrapper = mountLoading();
      expect(wrapper.find("scale-loading-spinner").exists()).toBe(true);
    });
  });

  describe("custom message", () => {
    it("renders custom message", () => {
      const wrapper = mountLoading({ message: "Fetching sessions..." });
      expect(wrapper.text()).toContain("Fetching sessions...");
    });

    it("hides message span when message is empty string", () => {
      const wrapper = mountLoading({ message: "" });
      expect(wrapper.find(".loading-state__message").exists()).toBe(false);
    });
  });

  describe("size variants", () => {
    it("applies medium size class by default", () => {
      const wrapper = mountLoading();
      const root = wrapper.find(".loading-state");
      expect(root.classes()).toContain("loading-state--medium");
    });

    it("applies small size class", () => {
      const wrapper = mountLoading({ size: "small" });
      expect(wrapper.find(".loading-state--small").exists()).toBe(true);
    });

    it("applies large size class", () => {
      const wrapper = mountLoading({ size: "large" });
      expect(wrapper.find(".loading-state--large").exists()).toBe(true);
    });
  });

  describe("inline mode", () => {
    it("does not have inline class by default", () => {
      const wrapper = mountLoading();
      expect(wrapper.find(".loading-state--inline").exists()).toBe(false);
    });

    it("applies inline class when inline prop is true", () => {
      const wrapper = mountLoading({ inline: true });
      expect(wrapper.find(".loading-state--inline").exists()).toBe(true);
    });
  });

  describe("accessibility", () => {
    it("has role='status'", () => {
      const wrapper = mountLoading();
      const root = wrapper.find(".loading-state");
      expect(root.attributes("role")).toBe("status");
    });

    it("has aria-live='polite'", () => {
      const wrapper = mountLoading();
      const root = wrapper.find(".loading-state");
      expect(root.attributes("aria-live")).toBe("polite");
    });
  });
});
