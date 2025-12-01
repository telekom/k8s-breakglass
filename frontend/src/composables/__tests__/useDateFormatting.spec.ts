/**
 * Tests for useDateFormatting composable
 */

import { vi } from "vitest";
import {
  formatDateTime,
  formatDateOnly,
  formatTimeOnly,
  formatTimeCompact,
  formatRelativeTime,
  isValidDate,
  nowISO,
} from "@/composables/useDateFormatting";

describe("useDateFormatting", () => {
  describe("formatDateTime", () => {
    it("formats ISO string", () => {
      const result = formatDateTime("2025-12-01T14:30:45Z");
      // The exact format depends on locale, but should contain date and time parts
      expect(result).not.toBe("—");
      expect(result.length).toBeGreaterThan(10);
    });

    it("handles Date objects", () => {
      const date = new Date("2025-12-01T14:30:45Z");
      const result = formatDateTime(date);
      expect(result).not.toBe("—");
    });

    it("handles timestamps", () => {
      const timestamp = new Date("2025-12-01T14:30:45Z").getTime();
      const result = formatDateTime(timestamp);
      expect(result).not.toBe("—");
    });

    it("returns dash for null/undefined", () => {
      expect(formatDateTime(null)).toBe("—");
      expect(formatDateTime(undefined)).toBe("—");
    });
  });

  describe("formatDateOnly", () => {
    it("formats date without time", () => {
      const result = formatDateOnly("2025-12-01T14:30:45Z");
      expect(result).not.toBe("—");
      // Should not contain seconds
      expect(result).not.toMatch(/:\d{2}:\d{2}/);
    });

    it("returns dash for null", () => {
      expect(formatDateOnly(null)).toBe("—");
    });
  });

  describe("formatTimeOnly", () => {
    it("formats time with seconds", () => {
      const result = formatTimeOnly("2025-12-01T14:30:45Z");
      expect(result).not.toBe("—");
      // Should contain time with seconds
      expect(result).toMatch(/\d{1,2}:\d{2}:\d{2}/);
    });

    it("returns dash for null", () => {
      expect(formatTimeOnly(null)).toBe("—");
    });
  });

  describe("formatTimeCompact", () => {
    it("formats time without seconds", () => {
      const result = formatTimeCompact("2025-12-01T14:30:45Z");
      expect(result).not.toBe("—");
      // Should contain HH:mm format
      expect(result).toMatch(/\d{1,2}:\d{2}/);
    });

    it("returns dash for null", () => {
      expect(formatTimeCompact(null)).toBe("—");
    });
  });

  describe("formatRelativeTime", () => {
    const NOW = new Date("2025-12-01T12:00:00Z").getTime();

    beforeEach(() => {
      vi.useFakeTimers();
      vi.setSystemTime(NOW);
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it("formats seconds ago", () => {
      const past = new Date(NOW - 30 * 1000).toISOString();
      expect(formatRelativeTime(past)).toBe("30s ago");
    });

    it("formats minutes ago", () => {
      const past = new Date(NOW - 5 * 60 * 1000).toISOString();
      expect(formatRelativeTime(past)).toBe("5m ago");
    });

    it("formats hours ago", () => {
      const past = new Date(NOW - 3 * 3600 * 1000).toISOString();
      expect(formatRelativeTime(past)).toBe("3h ago");
    });

    it("formats days ago", () => {
      const past = new Date(NOW - 2 * 24 * 3600 * 1000).toISOString();
      expect(formatRelativeTime(past)).toBe("2d ago");
    });

    it("formats future times", () => {
      const future = new Date(NOW + 5 * 60 * 1000).toISOString();
      expect(formatRelativeTime(future)).toBe("in 5m");
    });

    it("returns dash for null", () => {
      expect(formatRelativeTime(null)).toBe("—");
    });
  });

  describe("isValidDate", () => {
    it("returns true for valid ISO strings", () => {
      expect(isValidDate("2025-12-01T14:30:45Z")).toBe(true);
      expect(isValidDate("2025-12-01")).toBe(true);
    });

    it("returns true for Date objects", () => {
      expect(isValidDate(new Date())).toBe(true);
    });

    it("returns true for timestamps", () => {
      expect(isValidDate(Date.now())).toBe(true);
    });

    it("returns false for invalid values", () => {
      expect(isValidDate(null)).toBe(false);
      expect(isValidDate(undefined)).toBe(false);
      expect(isValidDate("not a date")).toBe(false);
    });
  });

  describe("nowISO", () => {
    it("returns current time as ISO string", () => {
      const result = nowISO();
      expect(result).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}/);
    });
  });
});
