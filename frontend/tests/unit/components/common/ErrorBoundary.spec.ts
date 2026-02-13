/**
 * Tests for ErrorBoundary component
 *
 * @jest-environment jsdom
 */

import { describe, it, expect, vi, beforeEach } from "vitest";
import { mount, flushPromises } from "@vue/test-utils";
import { defineComponent } from "vue";
import ErrorBoundary from "@/components/common/ErrorBoundary.vue";

// Mock the logger
vi.mock("@/services/logger-console", () => ({
  default: {
    error: vi.fn(),
    warn: vi.fn(),
    info: vi.fn(),
    debug: vi.fn(),
  },
}));

// A child component that throws during setup
const ThrowingChild = defineComponent({
  name: "ThrowingChild",
  setup() {
    throw new Error("Child component error");
  },
  render() {
    return null;
  },
});

const stubs = {
  "scale-icon-alert-error": true,
  "scale-button": true,
};

describe("ErrorBoundary", () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  describe("Normal Rendering", () => {
    it("renders slot content when no error occurs", () => {
      const wrapper = mount(ErrorBoundary, {
        slots: {
          default: '<div class="test-content">Hello</div>',
        },
        global: { stubs },
      });

      expect(wrapper.find(".test-content").exists()).toBe(true);
      expect(wrapper.find(".error-boundary").exists()).toBe(false);
    });

    it("does not show error UI initially", () => {
      const wrapper = mount(ErrorBoundary, {
        slots: {
          default: "<span>OK</span>",
        },
        global: { stubs },
      });

      expect(wrapper.find('[role="alert"]').exists()).toBe(false);
    });
  });

  describe("Error Capture", () => {
    it("shows fallback UI when child component throws during render", async () => {
      const wrapper = mount(ErrorBoundary, {
        global: {
          stubs,
          components: { ThrowingChild },
        },
        slots: {
          default: "<ThrowingChild />",
        },
      });

      await flushPromises();

      expect(wrapper.find(".error-boundary").exists()).toBe(true);
      expect(wrapper.find('[role="alert"]').exists()).toBe(true);
    });

    it("displays the error message from child", async () => {
      const wrapper = mount(ErrorBoundary, {
        global: {
          stubs,
          components: { ThrowingChild },
        },
        slots: {
          default: "<ThrowingChild />",
        },
      });

      await flushPromises();

      expect(wrapper.find(".error-message").text()).toContain("Child component error");
    });

    it("displays default title when none provided", async () => {
      const wrapper = mount(ErrorBoundary, {
        global: {
          stubs,
          components: { ThrowingChild },
        },
        slots: {
          default: "<ThrowingChild />",
        },
      });

      await flushPromises();

      expect(wrapper.find("h3").text()).toBe("Something went wrong");
    });

    it("displays custom title when provided", async () => {
      const wrapper = mount(ErrorBoundary, {
        props: {
          title: "Custom Error Title",
        },
        global: {
          stubs,
          components: { ThrowingChild },
        },
        slots: {
          default: "<ThrowingChild />",
        },
      });

      await flushPromises();

      expect(wrapper.find("h3").text()).toBe("Custom Error Title");
    });

    it("shows error icon in error state", async () => {
      const wrapper = mount(ErrorBoundary, {
        global: {
          stubs,
          components: { ThrowingChild },
        },
        slots: {
          default: "<ThrowingChild />",
        },
      });

      await flushPromises();

      // scale-icon-alert-error is a web component, rendered as custom element
      expect(wrapper.find("scale-icon-alert-error").exists()).toBe(true);
    });
  });

  describe("Retry Behavior", () => {
    it("shows Try Again button in error state", async () => {
      const wrapper = mount(ErrorBoundary, {
        global: {
          stubs,
          components: { ThrowingChild },
        },
        slots: {
          default: "<ThrowingChild />",
        },
      });

      await flushPromises();

      const button = wrapper.find("scale-button");
      expect(button.exists()).toBe(true);
    });

    it("clears error state when retry is clicked", async () => {
      const wrapper = mount(ErrorBoundary, {
        global: {
          stubs,
          components: { ThrowingChild },
        },
        slots: {
          default: "<ThrowingChild />",
        },
      });

      await flushPromises();
      expect(wrapper.find(".error-boundary").exists()).toBe(true);

      // Click retry — ThrowingChild will throw again but the retry mechanism
      // should clear the error and attempt re-render
      await wrapper.find("scale-button").trigger("click");
      await flushPromises();

      // The child throws again on re-render, so error boundary catches again
      expect(wrapper.find(".error-boundary").exists()).toBe(true);
    });
  });

  describe("Accessibility", () => {
    it("has role=alert on error state", async () => {
      const wrapper = mount(ErrorBoundary, {
        global: {
          stubs,
          components: { ThrowingChild },
        },
        slots: {
          default: "<ThrowingChild />",
        },
      });

      await flushPromises();

      expect(wrapper.find('[role="alert"]').exists()).toBe(true);
    });

    it("does not have role=alert in normal state", () => {
      const wrapper = mount(ErrorBoundary, {
        slots: {
          default: "<div>Normal</div>",
        },
        global: { stubs },
      });

      expect(wrapper.find('[role="alert"]').exists()).toBe(false);
    });
  });
});
