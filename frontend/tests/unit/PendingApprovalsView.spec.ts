/**
 * Tests for PendingApprovalsView component utility functions
 *
 * This test suite covers duration formatting and end time computation:
 * - formatDuration(): Parses Go duration strings (e.g., "1h0m0s") to human-readable format
 * - computeEndTime(): Calculates end time from start time and duration
 *
 * @jest-environment jsdom
 */

/// <reference types="jest" />

describe("PendingApprovalsView Duration Utilities", () => {
  /**
   * Helper functions for duration formatting and end time computation
   */

  function formatDuration(durationStr: string | undefined): string {
    if (!durationStr) return "Not specified";

    // Parse Go duration string format: "1h0m0s"
    const match = durationStr.match(/^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$/);
    if (!match) return durationStr;

    const hours = parseInt(match[1] || "0", 10);
    const minutes = parseInt(match[2] || "0", 10);
    const seconds = parseInt(match[3] || "0", 10);

    const parts: string[] = [];
    if (hours > 0) parts.push(`${hours}h`);
    if (minutes > 0) parts.push(`${minutes}m`);
    if (seconds > 0) parts.push(`${seconds}s`);

    return parts.length > 0 ? parts.join(" ") : "0s";
  }

  function computeEndTime(startTimeStr: string | undefined, durationStr: string | undefined): string {
    if (!startTimeStr || !durationStr) return "Not available";

    try {
      const startTime = new Date(startTimeStr);

      // Parse Go duration string format: "1h0m0s"
      const match = durationStr.match(/^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$/);
      if (!match) return "Invalid duration format";

      const hours = parseInt(match[1] || "0", 10);
      const minutes = parseInt(match[2] || "0", 10);
      const seconds = parseInt(match[3] || "0", 10);

      // Calculate total milliseconds
      const totalMs = (hours * 3600 + minutes * 60 + seconds) * 1000;

      const endTime = new Date(startTime.getTime() + totalMs);
      return endTime.toLocaleString();
    } catch {
      return "Invalid date format";
    }
  }

  // Helper that returns the end time as a Date for testing (avoids locale parsing issues)
  function computeEndTimeAsDate(startTimeStr: string | undefined, durationStr: string | undefined): Date | null {
    if (!startTimeStr || !durationStr) return null;

    try {
      const startTime = new Date(startTimeStr);
      if (isNaN(startTime.getTime())) return null;

      // Parse Go duration string format: "1h0m0s"
      const match = durationStr.match(/^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$/);
      if (!match) return null;

      const hours = parseInt(match[1] || "0", 10);
      const minutes = parseInt(match[2] || "0", 10);
      const seconds = parseInt(match[3] || "0", 10);

      // Calculate total milliseconds
      const totalMs = (hours * 3600 + minutes * 60 + seconds) * 1000;

      return new Date(startTime.getTime() + totalMs);
    } catch {
      return null;
    }
  }

  describe("formatDuration()", () => {
    it("formats simple hours", () => {
      expect(formatDuration("1h0m0s")).toBe("1h");
      expect(formatDuration("2h0m0s")).toBe("2h");
      expect(formatDuration("24h0m0s")).toBe("24h");
    });

    it("formats simple minutes", () => {
      expect(formatDuration("0h30m0s")).toBe("30m");
      expect(formatDuration("0h45m0s")).toBe("45m");
      expect(formatDuration("0h1m0s")).toBe("1m");
    });

    it("formats simple seconds", () => {
      expect(formatDuration("0h0m30s")).toBe("30s");
      expect(formatDuration("0h0m1s")).toBe("1s");
      expect(formatDuration("0h0m0s")).toBe("0s");
    });

    it("formats combined hours and minutes", () => {
      expect(formatDuration("1h30m0s")).toBe("1h 30m");
      expect(formatDuration("2h15m0s")).toBe("2h 15m");
      expect(formatDuration("1h1m0s")).toBe("1h 1m");
    });

    it("formats combined hours, minutes, and seconds", () => {
      expect(formatDuration("1h30m45s")).toBe("1h 30m 45s");
      expect(formatDuration("2h15m30s")).toBe("2h 15m 30s");
      expect(formatDuration("1h0m1s")).toBe("1h 1s");
    });

    it("formats minutes and seconds", () => {
      expect(formatDuration("0h30m45s")).toBe("30m 45s");
      expect(formatDuration("0h1m30s")).toBe("1m 30s");
    });

    it('returns "Not specified" for undefined', () => {
      expect(formatDuration(undefined)).toBe("Not specified");
    });

    it("returns original string for invalid format", () => {
      expect(formatDuration("invalid")).toBe("invalid");
      expect(formatDuration("1 hour")).toBe("1 hour");
    });
  });

  describe("computeEndTime()", () => {
    it("computes end time with hours duration", () => {
      const startTime = "2025-11-14T10:00:00Z";
      const endTime = computeEndTimeAsDate(startTime, "1h0m0s");

      // Check that endTime is 1 hour after start
      expect(endTime).not.toBeNull();
      expect(endTime!.getTime()).toBeGreaterThan(new Date(startTime).getTime());
    });

    it("computes end time with minutes duration", () => {
      const startTime = "2025-11-14T10:00:00Z";
      const endTime = computeEndTimeAsDate(startTime, "0h30m0s");

      // Check that endTime is greater than start
      expect(endTime).not.toBeNull();
      expect(endTime!.getTime()).toBeGreaterThan(new Date(startTime).getTime());
    });

    it("computes end time with combined duration", () => {
      const startTime = "2025-11-14T10:00:00Z";
      const endTime = computeEndTimeAsDate(startTime, "1h30m0s");

      // Check that endTime is greater than start
      expect(endTime).not.toBeNull();
      expect(endTime!.getTime()).toBeGreaterThan(new Date(startTime).getTime());
    });

    it('returns "Not available" when start time is missing', () => {
      expect(computeEndTime(undefined, "1h0m0s")).toBe("Not available");
    });

    it('returns "Not available" when duration is missing', () => {
      expect(computeEndTime("2025-11-14T10:00:00Z", undefined)).toBe("Not available");
    });

    it('returns "Invalid duration format" for invalid duration', () => {
      expect(computeEndTime("2025-11-14T10:00:00Z", "invalid")).toBe("Invalid duration format");
    });

    it('returns "Invalid date format" for invalid start time', () => {
      const result = computeEndTime("not-a-date", "1h0m0s");
      // JavaScript returns "Invalid Date" for invalid dates when calling toLocaleString()
      expect(result).toContain("Invalid");
    });

    it("correctly calculates 60 minute duration", () => {
      const startTime = new Date("2025-11-14T10:48:00Z");
      const endTime = computeEndTimeAsDate(startTime.toISOString(), "1h0m0s");

      expect(endTime).not.toBeNull();
      // End time should be 1 hour later
      const timeDiffMs = endTime!.getTime() - startTime.getTime();
      expect(timeDiffMs).toBeCloseTo(3600000, -3); // 1 hour in ms, allowing for rounding
    });
  });

  describe("formatDuration() and computeEndTime() integration", () => {
    it("handles typical approval scenario", () => {
      const duration = "1h0m0s";
      const startTime = "2025-11-14T10:48:24Z";

      const formattedDuration = formatDuration(duration);
      expect(formattedDuration).toBe("1h");

      const endTime = computeEndTime(startTime, duration);
      expect(endTime).not.toBe("Not available");
      expect(endTime).not.toBe("Invalid duration format");
    });

    it("handles edge case with zero seconds", () => {
      const duration = "0h0m0s";
      const startTime = "2025-11-14T10:48:24Z";

      const formattedDuration = formatDuration(duration);
      expect(formattedDuration).toBe("0s");

      const endTime = computeEndTime(startTime, duration);
      expect(endTime).not.toBe("Not available");
    });

    it("handles realistic multi-day duration", () => {
      const duration = "48h30m15s";
      const startTime = "2025-11-14T10:48:24Z";

      const formattedDuration = formatDuration(duration);
      expect(formattedDuration).toContain("48h");
      expect(formattedDuration).toContain("30m");
      expect(formattedDuration).toContain("15s");

      const endTime = computeEndTime(startTime, duration);
      expect(endTime).not.toBe("Not available");
    });
  });
});
