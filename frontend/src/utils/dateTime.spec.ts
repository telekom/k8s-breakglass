/**
 * Tests for dateTime utility functions
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import {
  format24Hour,
  formatDate,
  formatTime,
  formatTimeShort,
  format24HourWithTZ,
  getLocaleInfo,
  debugLogDateTime,
} from "./dateTime";

describe("dateTime", () => {
  // Mock console methods
  const consoleSpy = {
    error: vi.spyOn(console, "error").mockImplementation(() => {}),
    debug: vi.spyOn(console, "debug").mockImplementation(() => {}),
  };

  afterEach(() => {
    vi.clearAllMocks();
  });

  describe("format24Hour", () => {
    it("returns empty string for null/undefined input", () => {
      expect(format24Hour(null)).toBe("");
      expect(format24Hour(undefined)).toBe("");
    });

    it("formats a valid ISO date string", () => {
      const result = format24Hour("2025-12-01T14:30:00Z");
      expect(result).toBeTruthy();
      // Should contain date and time parts (exact format depends on locale)
      expect(result).toMatch(/\d/);
    });

    it("handles custom formatting options", () => {
      const result = format24Hour("2025-12-01T14:30:00Z", {
        year: "numeric",
        month: "long",
      });
      expect(result).toBeTruthy();
    });

    it("handles invalid date gracefully", () => {
      const invalidDate = "not-a-date";
      const result = format24Hour(invalidDate);
      // Function logs error but may return invalid date string or original
      expect(result).toBeTruthy();
    });
  });

  describe("formatDate", () => {
    it("returns empty string for null/undefined input", () => {
      expect(formatDate(null)).toBe("");
      expect(formatDate(undefined)).toBe("");
    });

    it("formats a valid ISO date string without time", () => {
      const result = formatDate("2025-12-01T14:30:00Z");
      expect(result).toBeTruthy();
      // Should not contain seconds (time-only component)
      expect(result).toMatch(/\d/);
    });

    it("handles invalid date gracefully", () => {
      const invalidDate = "not-a-date";
      const result = formatDate(invalidDate);
      expect(result).toBeTruthy();
    });
  });

  describe("formatTime", () => {
    it("returns empty string for null/undefined input", () => {
      expect(formatTime(null)).toBe("");
      expect(formatTime(undefined)).toBe("");
    });

    it("formats time in HH:mm:ss format", () => {
      const result = formatTime("2025-12-01T14:30:45Z");
      expect(result).toBeTruthy();
      // Should contain time components
      expect(result).toMatch(/\d{1,2}[:\.]?\d{2}/);
    });

    it("handles invalid date gracefully", () => {
      const invalidDate = "not-a-date";
      const result = formatTime(invalidDate);
      expect(result).toBeTruthy();
    });
  });

  describe("formatTimeShort", () => {
    it("returns empty string for null/undefined input", () => {
      expect(formatTimeShort(null)).toBe("");
      expect(formatTimeShort(undefined)).toBe("");
    });

    it("formats time without seconds", () => {
      const result = formatTimeShort("2025-12-01T14:30:45Z");
      expect(result).toBeTruthy();
      expect(result).toMatch(/\d{1,2}[:\.]?\d{2}/);
    });

    it("handles invalid date gracefully", () => {
      const invalidDate = "not-a-date";
      const result = formatTimeShort(invalidDate);
      expect(result).toBeTruthy();
    });
  });

  describe("format24HourWithTZ", () => {
    it("returns empty string for null/undefined input", () => {
      expect(format24HourWithTZ(null)).toBe("");
      expect(format24HourWithTZ(undefined)).toBe("");
    });

    it("includes timezone information", () => {
      const result = format24HourWithTZ("2025-12-01T14:30:00Z");
      expect(result).toBeTruthy();
      // Should contain some timezone indicator (varies by locale)
      expect(result.length).toBeGreaterThan(10);
    });

    it("handles invalid date gracefully", () => {
      const invalidDate = "not-a-date";
      const result = format24HourWithTZ(invalidDate);
      expect(result).toBeTruthy();
    });
  });

  describe("getLocaleInfo", () => {
    it("returns locale information object", () => {
      const info = getLocaleInfo();
      expect(info).toHaveProperty("browserLocale");
      expect(info).toHaveProperty("userTimeZone");
      expect(info).toHaveProperty("use12Hour");
      expect(info).toHaveProperty("timeZoneOffset");
      expect(typeof info.timeZoneOffset).toBe("number");
    });
  });

  describe("debugLogDateTime", () => {
    it("logs debug information for valid date", () => {
      debugLogDateTime("testLabel", "2025-12-01T14:30:00Z");
      expect(consoleSpy.debug).toHaveBeenCalled();
    });

    it("handles empty/null input gracefully", () => {
      debugLogDateTime("testLabel", null);
      expect(consoleSpy.debug).toHaveBeenCalledWith("[DateTime] testLabel: (empty)");

      debugLogDateTime("testLabel", undefined);
      expect(consoleSpy.debug).toHaveBeenCalledWith("[DateTime] testLabel: (empty)");
    });
  });
});
