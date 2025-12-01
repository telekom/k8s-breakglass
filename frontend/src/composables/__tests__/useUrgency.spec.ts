/**
 * Tests for useUrgency composable
 */

import { vi } from "vitest";
import {
  getTimeRemaining,
  getUrgency,
  getUrgencyLabel,
  getUrgencyLabelString,
  getUrgencyDescription,
  isExpired,
  isFuture,
} from "@/composables/useUrgency";

describe("useUrgency", () => {
  // Use fixed dates for predictable testing
  const NOW = new Date("2025-12-01T12:00:00Z").getTime();

  beforeEach(() => {
    vi.useFakeTimers();
    vi.setSystemTime(NOW);
  });

  afterEach(() => {
    vi.useRealTimers();
  });

  describe("getTimeRemaining", () => {
    it("returns seconds until expiry", () => {
      // 1 hour in the future
      const future = new Date(NOW + 3600 * 1000).toISOString();
      expect(getTimeRemaining(future)).toBe(3600);
    });

    it("returns 0 for past dates", () => {
      const past = new Date(NOW - 3600 * 1000).toISOString();
      expect(getTimeRemaining(past)).toBe(0);
    });

    it("returns Infinity for null/undefined", () => {
      expect(getTimeRemaining(null)).toBe(Infinity);
      expect(getTimeRemaining(undefined)).toBe(Infinity);
    });

    it("handles Date objects", () => {
      const future = new Date(NOW + 1800 * 1000);
      expect(getTimeRemaining(future)).toBe(1800);
    });
  });

  describe("getUrgency", () => {
    it("returns 'critical' for < 1 hour", () => {
      const future = new Date(NOW + 30 * 60 * 1000).toISOString(); // 30 min
      expect(getUrgency(future)).toBe("critical");
    });

    it("returns 'high' for < 6 hours", () => {
      const future = new Date(NOW + 3 * 3600 * 1000).toISOString(); // 3 hours
      expect(getUrgency(future)).toBe("high");
    });

    it("returns 'normal' for >= 6 hours", () => {
      const future = new Date(NOW + 8 * 3600 * 1000).toISOString(); // 8 hours
      expect(getUrgency(future)).toBe("normal");
    });

    it("returns 'normal' for null/undefined", () => {
      expect(getUrgency(null)).toBe("normal");
      expect(getUrgency(undefined)).toBe("normal");
    });

    it("returns 'critical' for expired", () => {
      const past = new Date(NOW - 3600 * 1000).toISOString();
      expect(getUrgency(past)).toBe("critical");
    });

    it("respects custom thresholds", () => {
      const customConfig = {
        criticalThreshold: 600, // 10 minutes
        highThreshold: 1800, // 30 minutes
      };

      const future15min = new Date(NOW + 15 * 60 * 1000).toISOString();
      expect(getUrgency(future15min, customConfig)).toBe("high");

      const future5min = new Date(NOW + 5 * 60 * 1000).toISOString();
      expect(getUrgency(future5min, customConfig)).toBe("critical");
    });
  });

  describe("getUrgencyLabel", () => {
    it("returns structured label objects with icon, text, and ariaLabel", () => {
      expect(getUrgencyLabel("critical")).toEqual({
        icon: "⚠️",
        text: "Critical",
        ariaLabel: "Critical urgency",
      });
      expect(getUrgencyLabel("high")).toEqual({
        icon: "⏱️",
        text: "High",
        ariaLabel: "High urgency",
      });
      expect(getUrgencyLabel("normal")).toEqual({
        icon: "🕓",
        text: "Normal",
        ariaLabel: "Normal urgency",
      });
    });

    it("provides backwards compatible string via getUrgencyLabelString", () => {
      expect(getUrgencyLabelString("critical")).toBe("⚠️ Critical");
      expect(getUrgencyLabelString("high")).toBe("⏱️ High");
      expect(getUrgencyLabelString("normal")).toBe("🕓 Normal");
    });
  });

  describe("getUrgencyDescription", () => {
    it("returns correct descriptions", () => {
      expect(getUrgencyDescription("critical")).toBe("Less than 1 hour remaining");
      expect(getUrgencyDescription("high")).toBe("Less than 6 hours remaining");
      expect(getUrgencyDescription("normal")).toBe("More than 6 hours remaining");
    });
  });

  describe("isExpired", () => {
    it("returns true for past dates", () => {
      const past = new Date(NOW - 1000).toISOString();
      expect(isExpired(past)).toBe(true);
    });

    it("returns false for future dates", () => {
      const future = new Date(NOW + 1000).toISOString();
      expect(isExpired(future)).toBe(false);
    });

    it("returns false for null/undefined", () => {
      expect(isExpired(null)).toBe(false);
      expect(isExpired(undefined)).toBe(false);
    });
  });

  describe("isFuture", () => {
    it("returns true for future dates", () => {
      const future = new Date(NOW + 1000).toISOString();
      expect(isFuture(future)).toBe(true);
    });

    it("returns false for past dates", () => {
      const past = new Date(NOW - 1000).toISOString();
      expect(isFuture(past)).toBe(false);
    });

    it("returns false for null/undefined", () => {
      expect(isFuture(null)).toBe(false);
      expect(isFuture(undefined)).toBe(false);
    });
  });
});
