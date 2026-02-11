/**
 * Tests for ErrorToasts component
 *
 * Covers:
 * - Toast rendering from error store
 * - Heading text for error/success variants
 * - Variant mapping (success vs error)
 * - Auto-hide duration logic
 * - Vertical offset stacking calculation
 * - Toast dismissal via events
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mount } from "@vue/test-utils";
import ErrorToasts from "@/components/ErrorToasts.vue";
import { useErrors, pushError, pushSuccess } from "@/services/toast";

describe("ErrorToasts", () => {
  const store = useErrors();

  beforeEach(() => {
    vi.useFakeTimers();
    vi.spyOn(Math, "random").mockReturnValue(0.5);
    store.errors.splice(0, store.errors.length);
  });

  afterEach(() => {
    vi.runOnlyPendingTimers();
    vi.useRealTimers();
    vi.restoreAllMocks();
  });

  function mountToasts() {
    return mount(ErrorToasts);
  }

  describe("rendering", () => {
    it("renders no toasts when error store is empty", () => {
      const wrapper = mountToasts();
      expect(wrapper.findAll("scale-notification-toast")).toHaveLength(0);
    });

    it("renders a toast for each error in the store", () => {
      pushError("Error 1");
      pushError("Error 2");

      const wrapper = mountToasts();
      expect(wrapper.findAll("scale-notification-toast")).toHaveLength(2);
    });

    it("renders error message in toast body", () => {
      pushError("Something went wrong");

      const wrapper = mountToasts();
      expect(wrapper.text()).toContain("Something went wrong");
    });

    it("renders correlation id when present", () => {
      pushError("fail", 500, "abc-123");

      const wrapper = mountToasts();
      expect(wrapper.text()).toContain("abc-123");
    });

    it("does not render cid span when absent", () => {
      pushError("fail");

      const wrapper = mountToasts();
      expect(wrapper.find(".cid").exists()).toBe(false);
    });
  });

  describe("heading logic", () => {
    it("shows 'Success' heading for success toasts", () => {
      pushSuccess("All good");

      const wrapper = mountToasts();
      expect(wrapper.text()).toContain("Success");
    });

    it("shows 'Error [status]' heading when status is present", () => {
      pushError("bad request", 400);

      const wrapper = mountToasts();
      expect(wrapper.text()).toContain("Error [400]");
    });

    it("shows 'Error' heading when no status is present", () => {
      pushError("generic fail");

      const wrapper = mountToasts();
      expect(wrapper.text()).toContain("Error");
      // Should not contain brackets
      expect(wrapper.text()).not.toMatch(/Error \[\d+\]/);
    });
  });

  describe("variant mapping", () => {
    it("maps success type to success variant", () => {
      pushSuccess("done");

      const wrapper = mountToasts();
      const toast = wrapper.find("scale-notification-toast");
      expect(toast.attributes("variant")).toBe("success");
    });

    it("maps error type to error variant", () => {
      pushError("failed");

      const wrapper = mountToasts();
      const toast = wrapper.find("scale-notification-toast");
      expect(toast.attributes("variant")).toBe("error");
    });
  });

  describe("data-testid", () => {
    it("sets success-toast testid for success toasts", () => {
      pushSuccess("win");

      const wrapper = mountToasts();
      const toast = wrapper.find("[data-testid='success-toast']");
      expect(toast.exists()).toBe(true);
    });

    it("sets error-toast testid for error toasts", () => {
      pushError("fail");

      const wrapper = mountToasts();
      const toast = wrapper.find("[data-testid='error-toast']");
      expect(toast.exists()).toBe(true);
    });
  });

  describe("aria attributes", () => {
    it("has aria-live polite on toast region", () => {
      const wrapper = mountToasts();
      const region = wrapper.find(".toast-region");
      expect(region.attributes("aria-live")).toBe("polite");
    });

    it("has aria-atomic true on toast region", () => {
      const wrapper = mountToasts();
      const region = wrapper.find(".toast-region");
      expect(region.attributes("aria-atomic")).toBe("true");
    });
  });

  describe("auto-hide duration", () => {
    it("passes default 10000ms auto-hide for error toasts", () => {
      pushError("error msg");

      const wrapper = mountToasts();
      const toast = wrapper.find("scale-notification-toast");
      expect(toast.attributes("auto-hide-duration")).toBe("10000");
    });

    it("passes default 6000ms auto-hide for success toasts", () => {
      pushSuccess("ok");

      const wrapper = mountToasts();
      const toast = wrapper.find("scale-notification-toast");
      expect(toast.attributes("auto-hide-duration")).toBe("6000");
    });

    it("enables auto-hide on all toasts", () => {
      pushError("err");

      const wrapper = mountToasts();
      const toast = wrapper.find("scale-notification-toast");
      expect(toast.attributes("auto-hide")).toBeTruthy();
    });
  });

  describe("dismiss events", () => {
    it("removes toast from store on scale-close event", async () => {
      pushError("will be dismissed");
      const wrapper = mountToasts();

      expect(store.errors).toHaveLength(1);
      const toast = wrapper.find("scale-notification-toast");
      await toast.trigger("scale-close");

      // After scale-close, the toast should be removed from the store
      expect(store.errors).toHaveLength(0);
    });
  });

  describe("vertical stacking", () => {
    it("offsets toasts vertically based on index", () => {
      pushError("Error 1");
      pushError("Error 2");
      pushError("Error 3");

      const wrapper = mountToasts();
      const toasts = wrapper.findAll("scale-notification-toast");

      // BASE_VERTICAL_OFFSET = 16, STACK_SPACING = 108
      expect(toasts[0]?.attributes("position-vertical")).toBe("16");
      expect(toasts[1]?.attributes("position-vertical")).toBe("124");
      expect(toasts[2]?.attributes("position-vertical")).toBe("232");
    });
  });
});
