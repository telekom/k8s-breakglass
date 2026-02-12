/**
 * Tests for StatusTag component
 *
 * Covers:
 * - Display label formatting (camelCase → spaced, uppercase toggle)
 * - Tone computation from status string via statusToneFor
 * - Custom tone override
 * - Icon display for known statuses
 * - Size variants
 * - Unknown/empty status handling
 */

import { describe, it, expect } from "vitest";
import { mount } from "@vue/test-utils";
import StatusTag from "@/components/common/StatusTag.vue";

describe("StatusTag", () => {
  function mountTag(props: Record<string, unknown> = {}) {
    return mount(StatusTag, { props });
  }

  describe("display label", () => {
    it("converts camelCase status to spaced uppercase by default", () => {
      const wrapper = mountTag({ status: "waitingForScheduledTime" });
      expect(wrapper.text()).toContain("WAITING FOR SCHEDULED TIME");
    });

    it("shows 'Unknown' when status is empty", () => {
      const wrapper = mountTag({ status: "" });
      expect(wrapper.text()).toContain("Unknown");
    });

    it("shows 'Unknown' when status is not provided", () => {
      const wrapper = mountTag();
      expect(wrapper.text()).toContain("Unknown");
    });

    it("does not uppercase when uppercase prop is false", () => {
      const wrapper = mountTag({ status: "Approved", uppercase: false });
      expect(wrapper.text()).toContain("Approved");
      expect(wrapper.text()).not.toContain("APPROVED");
    });

    it("handles underscored statuses", () => {
      const wrapper = mountTag({ status: "approval_timeout" });
      expect(wrapper.text()).toContain("APPROVAL TIMEOUT");
    });
  });

  describe("tone computation", () => {
    it("maps 'Approved' to success tone class", () => {
      const wrapper = mountTag({ status: "Approved" });
      expect(wrapper.find(".status-tag--success").exists()).toBe(true);
    });

    it("maps 'Pending' to warning tone class", () => {
      const wrapper = mountTag({ status: "Pending" });
      expect(wrapper.find(".status-tag--warning").exists()).toBe(true);
    });

    it("maps 'Rejected' to danger tone class", () => {
      const wrapper = mountTag({ status: "Rejected" });
      expect(wrapper.find(".status-tag--danger").exists()).toBe(true);
    });

    it("maps 'Expired' to muted tone class", () => {
      const wrapper = mountTag({ status: "Expired" });
      expect(wrapper.find(".status-tag--muted").exists()).toBe(true);
    });

    it("maps unknown statuses to neutral tone", () => {
      const wrapper = mountTag({ status: "CustomStatus" });
      expect(wrapper.find(".status-tag--neutral").exists()).toBe(true);
    });
  });

  describe("tone override", () => {
    it("uses custom tone instead of computed tone", () => {
      const wrapper = mountTag({ status: "Approved", tone: "danger" });
      expect(wrapper.find(".status-tag--danger").exists()).toBe(true);
      expect(wrapper.find(".status-tag--success").exists()).toBe(false);
    });
  });

  describe("size variants", () => {
    it("defaults to medium size", () => {
      const wrapper = mountTag({ status: "Active" });
      expect(wrapper.find(".status-tag--medium").exists()).toBe(true);
    });

    it("applies small size class", () => {
      const wrapper = mountTag({ status: "Active", size: "small" });
      expect(wrapper.find(".status-tag--small").exists()).toBe(true);
    });
  });

  describe("icon display", () => {
    it("does not render icon by default", () => {
      const wrapper = mountTag({ status: "Approved" });
      expect(wrapper.find(".status-tag__icon").exists()).toBe(false);
    });

    it("renders icon when showIcon is true and status has known icon", () => {
      const wrapper = mountTag({ status: "Approved", showIcon: true });
      expect(wrapper.find(".status-tag__icon").exists()).toBe(true);
    });

    it("does not render icon for unknown statuses even with showIcon", () => {
      const wrapper = mountTag({ status: "CustomUnknown", showIcon: true });
      expect(wrapper.find(".status-tag__icon").exists()).toBe(false);
    });
  });

  describe("tag variant mapping", () => {
    it("maps success tone to success variant on scale-tag", () => {
      const wrapper = mountTag({ status: "Active" });
      expect(wrapper.find("scale-tag").attributes("variant")).toBe("success");
    });

    it("maps danger tone to danger variant on scale-tag", () => {
      const wrapper = mountTag({ status: "Rejected" });
      expect(wrapper.find("scale-tag").attributes("variant")).toBe("danger");
    });

    it("maps muted/neutral tones to neutral variant on scale-tag", () => {
      const wrapper = mountTag({ status: "Expired" });
      expect(wrapper.find("scale-tag").attributes("variant")).toBe("neutral");
    });
  });
});
