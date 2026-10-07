/**
 * Tests for date formatting utilities
 */

import { vi } from "vitest";
import { formatDateTime, formatRelativeTime } from "@/composables/useDateFormatting";

describe("date formatting utilities", () => {
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
});
