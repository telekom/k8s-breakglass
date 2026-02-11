/**
 * Tests for EmptyState component
 *
 * Covers:
 * - Default rendering (title, description)
 * - Variant-based styling (default, search, error, success)
 * - Custom icon prop
 * - Compact mode
 * - Actions slot rendering
 * - Description slot rendering
 */

import { describe, it, expect } from "vitest";
import { mount } from "@vue/test-utils";
import EmptyState from "@/components/common/EmptyState.vue";

describe("EmptyState", () => {
  function mountEmptyState(props: Record<string, unknown> = {}, slots: Record<string, string> = {}) {
    return mount(EmptyState, { props, slots });
  }

  describe("default rendering", () => {
    it("renders with default title when no props given", () => {
      const wrapper = mountEmptyState();
      expect(wrapper.text()).toContain("No items found");
    });

    it("renders custom title", () => {
      const wrapper = mountEmptyState({ title: "Nothing here" });
      expect(wrapper.text()).toContain("Nothing here");
    });

    it("renders description when provided", () => {
      const wrapper = mountEmptyState({ description: "Try adjusting filters" });
      expect(wrapper.text()).toContain("Try adjusting filters");
    });

    it("does not render description paragraph when not provided", () => {
      const wrapper = mountEmptyState();
      expect(wrapper.find(".empty-state__description").exists()).toBe(false);
    });

    it("has data-testid", () => {
      const wrapper = mountEmptyState();
      expect(wrapper.find("[data-testid='empty-state']").exists()).toBe(true);
    });
  });

  describe("variants", () => {
    it("defaults to 'default' variant", () => {
      const wrapper = mountEmptyState();
      expect(wrapper.find("[data-variant='default']").exists()).toBe(true);
    });

    it("sets data-variant for search", () => {
      const wrapper = mountEmptyState({ variant: "search" });
      expect(wrapper.find("[data-variant='search']").exists()).toBe(true);
    });

    it("sets data-variant for error", () => {
      const wrapper = mountEmptyState({ variant: "error" });
      expect(wrapper.find("[data-variant='error']").exists()).toBe(true);
    });

    it("sets data-variant for success", () => {
      const wrapper = mountEmptyState({ variant: "success" });
      expect(wrapper.find("[data-variant='success']").exists()).toBe(true);
    });
  });

  describe("compact mode", () => {
    it("does not have compact class by default", () => {
      const wrapper = mountEmptyState();
      expect(wrapper.find(".empty-state--compact").exists()).toBe(false);
    });

    it("applies compact class when compact prop is true", () => {
      const wrapper = mountEmptyState({ compact: true });
      expect(wrapper.find(".empty-state--compact").exists()).toBe(true);
    });
  });

  describe("slots", () => {
    it("renders actions slot content", () => {
      const wrapper = mountEmptyState({}, { actions: "<button>Retry</button>" });
      expect(wrapper.find(".empty-state__actions").exists()).toBe(true);
      expect(wrapper.text()).toContain("Retry");
    });

    it("hides actions container when no actions slot", () => {
      const wrapper = mountEmptyState();
      expect(wrapper.find(".empty-state__actions").exists()).toBe(false);
    });

    it("renders description slot", () => {
      const wrapper = mountEmptyState({}, { description: "<em>Custom description</em>" });
      expect(wrapper.html()).toContain("Custom description");
    });
  });

  describe("icon", () => {
    it("renders icon area", () => {
      const wrapper = mountEmptyState();
      expect(wrapper.find(".empty-state__icon").exists()).toBe(true);
    });

    it("icon area is aria-hidden", () => {
      const wrapper = mountEmptyState();
      expect(wrapper.find(".empty-state__icon").attributes("aria-hidden")).toBe("true");
    });

    it("renders custom icon when icon prop is provided", () => {
      const wrapper = mountEmptyState({ icon: "content-lock" });
      // When a custom icon is provided, the corresponding scale-icon-* element is rendered
      expect(wrapper.find("scale-icon-content-lock").exists()).toBe(true);
    });

    it("renders variant-specific icon by default", () => {
      const wrapper = mountEmptyState({ variant: "search" });
      expect(wrapper.find("scale-icon-action-search").exists()).toBe(true);
    });
  });
});
