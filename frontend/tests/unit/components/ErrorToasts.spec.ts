/**
 * Tests for ErrorToasts component
 *
 * Covers:
 * - Toast rendering from error store
 * - Heading text for error/success variants
 * - Variant mapping (success vs error)
 * - Auto-hide duration logic
 * - Deduplication of identical concurrent errors
 * - Toast dismissal via events
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mount } from "@vue/test-utils";
import ErrorToasts from "@/components/ErrorToasts.vue";
import { useErrors, pushError, pushSuccess, reportError } from "@/services/toast";
import { handleAxiosError } from "@/services/logger";

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

  // Vue sets Scale props as properties on the real element and as attributes on the test stub.
  function prop(el: Element | undefined, name: "heading" | "delay") {
    const value = (el as unknown as Record<string, unknown>)?.[name] ?? el?.getAttribute(name);
    return name === "delay" ? Number(value) : value;
  }

  describe("rendering", () => {
    it("renders no toasts when error store is empty", () => {
      const wrapper = mountToasts();
      expect(wrapper.findAll("scale-notification")).toHaveLength(0);
    });

    it("renders a toast for each error in the store", () => {
      pushError("Error 1");
      pushError("Error 2");

      const wrapper = mountToasts();
      expect(wrapper.findAll("scale-notification")).toHaveLength(2);
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
      expect(prop(wrapper.find("scale-notification").element, "heading")).toBe("Success");
    });

    it("shows 'Error [status]' heading when status is present", () => {
      pushError("bad request", 400);

      const wrapper = mountToasts();
      expect(prop(wrapper.find("scale-notification").element, "heading")).toBe("Error [400]");
    });

    it("shows 'Error' heading when no status is present", () => {
      pushError("generic fail");

      const wrapper = mountToasts();
      expect(prop(wrapper.find("scale-notification").element, "heading")).toBe("Error");
    });
  });

  describe("variant mapping", () => {
    it("maps success type to success variant", () => {
      pushSuccess("done");

      const wrapper = mountToasts();
      const toast = wrapper.find("scale-notification");
      expect(toast.attributes("variant")).toBe("success");
    });

    it("maps error type to danger variant", () => {
      pushError("failed");

      const wrapper = mountToasts();
      const toast = wrapper.find("scale-notification");
      expect(toast.attributes("variant")).toBe("danger");
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
      const toast = wrapper.find("scale-notification");
      expect(prop(toast.element, "delay")).toBe(10000);
    });

    it("passes default 6000ms auto-hide for success toasts", () => {
      pushSuccess("ok");

      const wrapper = mountToasts();
      const toast = wrapper.find("scale-notification");
      expect(prop(toast.element, "delay")).toBe(6000);
    });

    it("renders Scale toasts that can be dismissed", () => {
      pushError("err");

      const wrapper = mountToasts();
      const toast = wrapper.find("scale-notification");
      expect(toast.attributes("type")).toBe("toast");
      expect(toast.attributes("dismissible")).toBeDefined();
    });
  });

  describe("dismiss events", () => {
    it("removes toast from store on scale-close event", async () => {
      pushError("will be dismissed");
      const wrapper = mountToasts();

      expect(store.errors).toHaveLength(1);
      const toast = wrapper.find("scale-notification");
      await toast.trigger("scale-close");

      // After scale-close, the toast should be removed from the store
      expect(store.errors).toHaveLength(0);
    });
  });

  describe("stacking", () => {
    it("renders toasts in one flow region instead of fixed offsets", () => {
      pushError("Error 1");
      pushError("Error 2");

      const wrapper = mountToasts();
      const region = wrapper.find(".toast-region");
      expect(region.findAll("scale-notification")).toHaveLength(2);
      expect(region.find("[position-vertical]").exists()).toBe(false);
    });

    it("shows identical concurrent errors once", () => {
      pushError("Request failed with status code 500");
      pushError("Request failed with status code 500", 500);

      const wrapper = mountToasts();
      const toasts = wrapper.findAll("scale-notification");
      expect(toasts).toHaveLength(1);
      expect(prop(toasts[0]?.element, "heading")).toBe("Error [500]");
    });

    it("does not re-toast an error the service already reported", () => {
      vi.spyOn(console, "error").mockImplementation(() => {});
      const err = Object.assign(new Error("Request failed with status code 500"), {
        response: { status: 500, data: { error: "boom" } },
      });
      handleAxiosError("Service.load", err, "Failed to load");
      reportError(err, "Failed to load");
      reportError(new Error("other failure"), "Failed to load");

      const toasts = mountToasts().findAll(".toast");
      expect(toasts.map((t) => t.text())).toEqual(["boom", "other failure"]);
    });
  });
});
