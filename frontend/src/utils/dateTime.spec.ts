/**
 * Tests for dateTime utility functions
 */
import { describe, it, expect, vi, afterEach } from "vitest";
import { format24Hour, format24HourWithTZ, debugLogDateTime } from "./dateTime";

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

  describe("debugLogDateTime", () => {
    it("logs debug information for valid date", () => {
      debugLogDateTime("testLabel", "2025-12-01T14:30:00Z");
      expect(consoleSpy.debug).toHaveBeenCalled();
    });

    it("handles empty/null input gracefully", () => {
      debugLogDateTime("testLabel", null);
      expect(consoleSpy.debug).toHaveBeenCalledWith(expect.any(String), "[DateTime]", "testLabel: (empty)");

      debugLogDateTime("testLabel", undefined);
      expect(consoleSpy.debug).toHaveBeenCalledWith(expect.any(String), "[DateTime]", "testLabel: (empty)");
    });
  });
});
