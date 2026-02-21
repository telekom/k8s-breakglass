/**
 * Tests for useDuration composable
 */

import {
  parseDurationString,
  formatDuration,
  formatDurationFromSeconds,
  formatDurationRounded,
  formatDurationFromSecondsRounded,
  formatRoundedSeconds,
  computeEndTime,
  formatEndTime,
} from "@/composables/useDuration";

describe("useDuration", () => {
  describe("parseDurationString", () => {
    it("parses hours only", () => {
      expect(parseDurationString("1h0m0s")).toEqual({
        hours: 1,
        minutes: 0,
        seconds: 0,
        totalSeconds: 3600,
      });
      expect(parseDurationString("24h0m0s")).toEqual({
        hours: 24,
        minutes: 0,
        seconds: 0,
        totalSeconds: 86400,
      });
    });

    it("parses minutes only", () => {
      expect(parseDurationString("0h30m0s")).toEqual({
        hours: 0,
        minutes: 30,
        seconds: 0,
        totalSeconds: 1800,
      });
    });

    it("parses seconds only", () => {
      expect(parseDurationString("0h0m45s")).toEqual({
        hours: 0,
        minutes: 0,
        seconds: 45,
        totalSeconds: 45,
      });
    });

    it("parses combined duration", () => {
      expect(parseDurationString("1h30m45s")).toEqual({
        hours: 1,
        minutes: 30,
        seconds: 45,
        totalSeconds: 5445,
      });
    });

    it("parses short formats", () => {
      expect(parseDurationString("2h")).toEqual({
        hours: 2,
        minutes: 0,
        seconds: 0,
        totalSeconds: 7200,
      });
      expect(parseDurationString("30m")).toEqual({
        hours: 0,
        minutes: 30,
        seconds: 0,
        totalSeconds: 1800,
      });
      expect(parseDurationString("45s")).toEqual({
        hours: 0,
        minutes: 0,
        seconds: 45,
        totalSeconds: 45,
      });
    });

    it("parses days", () => {
      expect(parseDurationString("1d")).toEqual({
        hours: 24,
        minutes: 0,
        seconds: 0,
        totalSeconds: 86400,
      });
      expect(parseDurationString("7d")).toEqual({
        hours: 168,
        minutes: 0,
        seconds: 0,
        totalSeconds: 604800,
      });
    });

    it("returns null for invalid input", () => {
      expect(parseDurationString(null)).toBeNull();
      expect(parseDurationString(undefined)).toBeNull();
      expect(parseDurationString("")).toBeNull();
      expect(parseDurationString("invalid")).toBeNull();
      expect(parseDurationString("1x2y3z")).toBeNull();
    });
  });

  describe("formatDuration", () => {
    it("formats hours", () => {
      expect(formatDuration("1h0m0s")).toBe("1h");
      expect(formatDuration("2h0m0s")).toBe("2h");
    });

    it("formats minutes", () => {
      expect(formatDuration("0h30m0s")).toBe("30m");
    });

    it("formats seconds", () => {
      expect(formatDuration("0h0m45s")).toBe("45s");
    });

    it("formats combined", () => {
      expect(formatDuration("1h30m0s")).toBe("1h 30m");
      expect(formatDuration("1h30m45s")).toBe("1h 30m 45s");
      expect(formatDuration("0h30m45s")).toBe("30m 45s");
    });

    it("handles zero duration", () => {
      expect(formatDuration("0h0m0s")).toBe("0s");
    });

    it("returns 'Not specified' for undefined", () => {
      expect(formatDuration(undefined)).toBe("Not specified");
      expect(formatDuration(null)).toBe("Not specified");
    });

    it("returns original for invalid format", () => {
      expect(formatDuration("invalid")).toBe("invalid");
    });
  });

  describe("formatDurationFromSeconds", () => {
    it("formats seconds to readable string", () => {
      expect(formatDurationFromSeconds(3600)).toBe("1h");
      expect(formatDurationFromSeconds(1800)).toBe("30m");
      expect(formatDurationFromSeconds(45)).toBe("45s");
      expect(formatDurationFromSeconds(5445)).toBe("1h 30m 45s");
    });

    it("handles zero and negative", () => {
      expect(formatDurationFromSeconds(0)).toBe("0s");
      expect(formatDurationFromSeconds(-100)).toBe("0s");
      expect(formatDurationFromSeconds(null)).toBe("0s");
      expect(formatDurationFromSeconds(undefined)).toBe("0s");
    });
  });

  describe("computeEndTime", () => {
    it("computes end time correctly", () => {
      const start = "2025-12-01T10:00:00Z";
      const result = computeEndTime(start, "1h0m0s");

      expect(result).not.toBeNull();
      expect(result?.toISOString()).toBe("2025-12-01T11:00:00.000Z");
    });

    it("handles complex durations", () => {
      const start = "2025-12-01T10:00:00Z";
      const result = computeEndTime(start, "1h30m45s");

      expect(result).not.toBeNull();
      expect(result?.toISOString()).toBe("2025-12-01T11:30:45.000Z");
    });

    it("returns null for missing inputs", () => {
      expect(computeEndTime(null, "1h")).toBeNull();
      expect(computeEndTime("2025-12-01T10:00:00Z", null)).toBeNull();
      expect(computeEndTime(null, null)).toBeNull();
    });

    it("returns null for invalid duration", () => {
      expect(computeEndTime("2025-12-01T10:00:00Z", "invalid")).toBeNull();
    });
  });

  describe("formatEndTime", () => {
    it("formats end time with custom formatter", () => {
      const start = "2025-12-01T10:00:00Z";
      const formatter = (date: string) => new Date(date).toISOString();

      expect(formatEndTime(start, "1h0m0s", formatter)).toBe("2025-12-01T11:00:00.000Z");
    });

    it("returns 'Not available' for missing inputs", () => {
      expect(formatEndTime(null, "1h")).toBe("Not available");
      expect(formatEndTime("2025-12-01T10:00:00Z", null)).toBe("Not available");
    });
  });

  describe("formatRoundedSeconds", () => {
    it("returns 0s for zero or negative", () => {
      expect(formatRoundedSeconds(0)).toBe("0s");
      expect(formatRoundedSeconds(-10)).toBe("0s");
    });

    it("returns 0s for non-finite inputs", () => {
      expect(formatRoundedSeconds(NaN)).toBe("0s");
      expect(formatRoundedSeconds(Infinity)).toBe("0s");
      expect(formatRoundedSeconds(-Infinity)).toBe("0s");
    });

    it("returns exact seconds for < 1 minute", () => {
      expect(formatRoundedSeconds(45)).toBe("45s");
      expect(formatRoundedSeconds(1)).toBe("1s");
      expect(formatRoundedSeconds(59)).toBe("59s");
    });

    it("rounds to nearest minute for >= 1m and < 1h", () => {
      expect(formatRoundedSeconds(60)).toBe("1m");
      expect(formatRoundedSeconds(90)).toBe("2m"); // 1.5m rounds to 2m
      expect(formatRoundedSeconds(1800)).toBe("30m");
      expect(formatRoundedSeconds(3599)).toBe("1h"); // 59m 59s rounds to 60m, normalizes to 1h
    });

    it("rounds to nearest 5 minutes for >= 1h", () => {
      expect(formatRoundedSeconds(3600)).toBe("1h"); // exactly 1h
      expect(formatRoundedSeconds(5400)).toBe("1h 30m"); // 1h 30m — already clean
      expect(formatRoundedSeconds(7140)).toBe("2h"); // 1h 59m → 2h
      expect(formatRoundedSeconds(5580)).toBe("1h 35m"); // 1h 33m → 1h 35m
      expect(formatRoundedSeconds(86100)).toBe("23h 55m"); // 23h 55m → 23h 55m
      expect(formatRoundedSeconds(86340)).toBe("24h"); // 23h 59m → 24h
    });
  });

  describe("formatDurationRounded", () => {
    it("rounds near-boundary durations", () => {
      expect(formatDurationRounded("1h59m0s")).toBe("2h");
      expect(formatDurationRounded("1h33m0s")).toBe("1h 35m");
    });

    it("keeps clean durations unchanged", () => {
      expect(formatDurationRounded("30m")).toBe("30m");
      expect(formatDurationRounded("1h30m0s")).toBe("1h 30m");
      expect(formatDurationRounded("2h")).toBe("2h");
    });

    it("returns Not specified for empty", () => {
      expect(formatDurationRounded(undefined)).toBe("Not specified");
      expect(formatDurationRounded(null)).toBe("Not specified");
    });

    it("returns original for unparseable", () => {
      expect(formatDurationRounded("invalid")).toBe("invalid");
    });
  });

  describe("formatDurationFromSecondsRounded", () => {
    it("rounds seconds to nearest sensible unit", () => {
      expect(formatDurationFromSecondsRounded(7140)).toBe("2h"); // 1h 59m
      expect(formatDurationFromSecondsRounded(90)).toBe("2m"); // 1.5m
      expect(formatDurationFromSecondsRounded(45)).toBe("45s");
    });

    it("handles zero and null", () => {
      expect(formatDurationFromSecondsRounded(0)).toBe("0s");
      expect(formatDurationFromSecondsRounded(null)).toBe("0s");
      expect(formatDurationFromSecondsRounded(undefined)).toBe("0s");
    });
  });
});
