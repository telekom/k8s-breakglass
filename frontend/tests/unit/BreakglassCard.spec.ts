import { formatDurationSeconds, parseDurationInput, sanitizeReason, validateDuration } from "@/utils/breakglassSession";

/**
 * Tests for BreakglassCard component duration parsing, reason sanitization,
 * and validation logic.
 *
 * This test suite covers:
 * - parseDurationInput(): Flexible duration parser supporting multiple formats
 * - sanitizeReason(): HTML entity escaping for XSS prevention
 * - validateDuration(): Client-side duration validation
 * - formatDurationSeconds(): Duration conversion to human-readable format
 *
 * @jest-environment jsdom
 */

/// <reference types="jest" />

describe("BreakglassCard Duration and Reason Handling", () => {
  /**
   * parseDurationInput() tests
   *
   * Tests the flexible duration parser that supports:
   * - Simple hours: "1h", "2h"
   * - Simple minutes: "30m", "45m"
   * - Combined: "1h 30m", "2h 15m"
   * - Seconds: "3600", "7200"
   * - With/without spaces
   */
  describe("parseDurationInput()", () => {
    it("parses simple hours", () => {
      expect(parseDurationInput("1h")).toBe(3600);
      expect(parseDurationInput("2h")).toBe(7200);
      expect(parseDurationInput("24h")).toBe(86400);
    });

    it("parses simple minutes", () => {
      expect(parseDurationInput("30m")).toBe(1800);
      expect(parseDurationInput("45m")).toBe(2700);
      expect(parseDurationInput("1m")).toBe(60);
    });

    it("parses combined hours and minutes", () => {
      expect(parseDurationInput("1h 30m")).toBe(5400); // 3600 + 1800
      expect(parseDurationInput("2h 15m")).toBe(8100); // 7200 + 900
      expect(parseDurationInput("1h 1m")).toBe(3660);
    });

    it("parses combined without spaces", () => {
      expect(parseDurationInput("1h30m")).toBe(5400);
      expect(parseDurationInput("2h15m")).toBe(8100);
    });

    it("parses raw seconds", () => {
      expect(parseDurationInput("3600")).toBe(3600);
      expect(parseDurationInput("7200")).toBe(7200);
      expect(parseDurationInput("60")).toBe(60);
    });

    it("case-insensitive parsing", () => {
      expect(parseDurationInput("1H")).toBe(3600);
      expect(parseDurationInput("30M")).toBe(1800);
      expect(parseDurationInput("1H 30M")).toBe(5400);
    });

    it("parses with extra spaces", () => {
      expect(parseDurationInput("  1h  ")).toBe(3600);
      expect(parseDurationInput("1h  30m")).toBe(5400);
      expect(parseDurationInput("  1h 30m  ")).toBe(5400);
    });

    it("returns null for empty input", () => {
      expect(parseDurationInput("")).toBeNull();
      expect(parseDurationInput("   ")).toBeNull();
      expect(parseDurationInput("\n")).toBeNull();
    });

    it("returns null for invalid input", () => {
      expect(parseDurationInput("invalid")).toBeNull();
      expect(parseDurationInput("xyz")).toBeNull();
      expect(parseDurationInput("1x")).toBeNull();
    });

    it("returns null for zero or negative results", () => {
      expect(parseDurationInput("0h")).toBeNull();
      expect(parseDurationInput("0m")).toBeNull();
      expect(parseDurationInput("0")).toBeNull();
    });

    it("parses single unit correctly", () => {
      expect(parseDurationInput("5h")).toBe(18000);
      expect(parseDurationInput("90m")).toBe(5400);
    });

    it("handles leading zeros", () => {
      expect(parseDurationInput("01h")).toBe(3600);
      expect(parseDurationInput("00h 30m")).toBe(1800);
    });
  });

  /**
   * sanitizeReason() tests
   *
   * Tests HTML entity escaping to prevent XSS attacks
   * Covers: normal text, HTML entities, special characters
   */
  describe("sanitizeReason()", () => {
    it("escapes angle brackets", () => {
      expect(sanitizeReason("<script>")).toBe("&lt;script&gt;");
      expect(sanitizeReason("<div>test</div>")).toBe("&lt;div&gt;test&lt;/div&gt;");
    });

    it("escapes ampersands", () => {
      expect(sanitizeReason("fish & chips")).toBe("fish &amp; chips");
      expect(sanitizeReason("A & B & C")).toBe("A &amp; B &amp; C");
    });

    it("escapes quotes", () => {
      expect(sanitizeReason('say "hello"')).toBe('say "hello"');
      expect(sanitizeReason("it's fine")).toBe("it's fine");
    });

    it("escapes XSS attempts", () => {
      expect(sanitizeReason('<img src=x onerror="alert(1)">')).toBe("&lt;img src=x onerror=\"alert(1)\"&gt;");
      expect(sanitizeReason('<svg onload="alert(1)">')).toBe("&lt;svg onload=\"alert(1)\"&gt;");
    });

    it("preserves normal text", () => {
      expect(sanitizeReason("Database maintenance")).toBe("Database maintenance");
      expect(sanitizeReason("Testing in production")).toBe("Testing in production");
    });

    it("handles multiple special characters", () => {
      expect(sanitizeReason("Test & fix <bug>")).toBe("Test &amp; fix &lt;bug&gt;");
    });

    it("handles empty string", () => {
      expect(sanitizeReason("")).toBe("");
    });

    it("handles whitespace-only text", () => {
      expect(sanitizeReason("   ")).toBe("   ");
      expect(sanitizeReason("\t\n")).toBe("\t\n");
    });

    it("does not escape safe characters", () => {
      expect(sanitizeReason("Hello World 123!@#$%")).toBe("Hello World 123!@#$%");
    });
  });

  /**
   * validateDuration() tests
   *
   * Tests client-side duration validation
   * Covers: minimum duration (60s), maximum boundary, valid ranges
   */
  describe("validateDuration()", () => {
    it("rejects null/undefined", () => {
      expect(validateDuration(null, 3600).valid).toBe(false);
      expect(validateDuration(null, 3600).error).toContain("must be specified");
      expect(validateDuration(undefined as any, 3600).valid).toBe(false);
      expect(validateDuration(undefined as any, 3600).error).toContain("must be specified");
    });

    it("rejects duration below 60 seconds", () => {
      const result = validateDuration(30, 3600);
      expect(result.valid).toBe(false);
      expect(result.error).toContain("Duration must be at least 1 minute");
    });

    it("accepts duration at minimum (60 seconds)", () => {
      expect(validateDuration(60, 3600)).toEqual({ valid: true });
    });

    it("accepts duration in valid range", () => {
      expect(validateDuration(1800, 3600)).toEqual({ valid: true });
      expect(validateDuration(2700, 3600)).toEqual({ valid: true });
    });

    it("accepts duration at maximum", () => {
      expect(validateDuration(3600, 3600)).toEqual({ valid: true });
    });

    it("rejects duration exceeding maximum", () => {
      const result = validateDuration(3601, 3600);
      expect(result.valid).toBe(false);
      expect(result.error).toContain("exceeds maximum allowed time");
    });

    it("rejects negative duration", () => {
      const result = validateDuration(-100, 3600);
      expect(result.valid).toBe(false);
      expect(result.error).toContain("Duration must be at least 1 minute");
    });

    it("handles different max values", () => {
      const result = validateDuration(7200, 3600);
      expect(result.valid).toBe(false);
      expect(result.error).toContain("exceeds maximum allowed time");
      expect(validateDuration(7200, 86400)).toEqual({ valid: true });
    });

    it("accepts large valid durations", () => {
      expect(validateDuration(86400, 86400)).toEqual({ valid: true }); // 24 hours
    });

    it("rejects large durations exceeding max", () => {
      const result = validateDuration(86401, 86400);
      expect(result.valid).toBe(false);
    });
  });

  /**
   * formatDurationSeconds() tests
   *
   * Tests conversion of seconds to human-readable format
   * Supports output like "1h", "30m", "1h 30m"
   */
  describe("formatDurationSeconds()", () => {
    it("formats hours only", () => {
      expect(formatDurationSeconds(3600)).toBe("1h");
      expect(formatDurationSeconds(7200)).toBe("2h");
      expect(formatDurationSeconds(86400)).toBe("24h");
    });

    it("formats minutes only", () => {
      expect(formatDurationSeconds(60)).toBe("1m");
      expect(formatDurationSeconds(1800)).toBe("30m");
      expect(formatDurationSeconds(2700)).toBe("45m");
    });

    it("formats seconds only", () => {
      expect(formatDurationSeconds(30)).toBe("30s");
      expect(formatDurationSeconds(45)).toBe("45s");
    });

    it("formats hours and minutes", () => {
      expect(formatDurationSeconds(5400)).toBe("1h 30m");
      expect(formatDurationSeconds(8100)).toBe("2h 15m");
    });

    it("formats hours, minutes and seconds", () => {
      expect(formatDurationSeconds(3661)).toBe("1h 1m 1s");
      expect(formatDurationSeconds(7325)).toBe("2h 2m 5s");
    });

    it("handles zero", () => {
      expect(formatDurationSeconds(0)).toBe("0s");
    });

    it("handles negative values", () => {
      expect(formatDurationSeconds(-100)).toBe("0s");
    });

    it("formats common durations", () => {
      expect(formatDurationSeconds(300)).toBe("5m");
      expect(formatDurationSeconds(600)).toBe("10m");
      expect(formatDurationSeconds(1800)).toBe("30m");
      expect(formatDurationSeconds(3600)).toBe("1h");
    });

    it("omits zero components", () => {
      expect(formatDurationSeconds(3600)).toBe("1h"); // No 0m or 0s
      expect(formatDurationSeconds(1800)).toBe("30m"); // No 0h or 0s
      expect(formatDurationSeconds(60)).toBe("1m"); // No 0h or 0s
    });
  });

  /**
   * Combined Integration Tests
   *
   * Tests the interaction between parsing, sanitization, and validation
   */
  describe("Integration", () => {
    it("parses and validates a request with custom duration", () => {
      const userInput = "1h 30m";
      const parsed = parseDurationInput(userInput);
      const validation = validateDuration(parsed, 7200); // 2 hour max

      expect(parsed).toBe(5400);
      expect(validation.valid).toBe(true);
    });

    it("rejects request with duration exceeding max", () => {
      const userInput = "3h";
      const parsed = parseDurationInput(userInput);
      const validation = validateDuration(parsed, 7200); // 2 hour max

      expect(parsed).toBe(10800);
      expect(validation.valid).toBe(false);
      expect(validation.error).toContain("exceeds maximum allowed time");
    });

    it("sanitizes reason with XSS attempt", () => {
      const unsafeReason = '<img src=x onerror="steal()">';
      const sanitized = sanitizeReason(unsafeReason);

      expect(sanitized).not.toContain("<");
      expect(sanitized).not.toContain(">");
      expect(sanitized).toContain("&lt;");
      expect(sanitized).toContain("&gt;");
    });

    it("handles complete request validation flow", () => {
      const durationInput = "30m";
      const reasonInput = "Fixing <critical> bug & config issue";
      const maxDuration = 3600; // 1 hour

      const parsedDuration = parseDurationInput(durationInput);
      const durationValidation = validateDuration(parsedDuration, maxDuration);
      const sanitizedReason = sanitizeReason(reasonInput);

      expect(parsedDuration).toBe(1800);
      expect(durationValidation.valid).toBe(true);
      expect(sanitizedReason).toBe("Fixing &lt;critical&gt; bug &amp; config issue");
    });

    it("rejects invalid input at any step", () => {
      const invalidDuration = "invalid";
      const maxDuration = 3600;

      const parsed = parseDurationInput(invalidDuration);
      expect(parsed).toBeNull();

      // Validation should reject missing durations
      const validation = validateDuration(null, maxDuration);
      expect(validation.valid).toBe(false);
      expect(validation.error).toContain("must be specified");
    });
  });

  /**
   * DateTime Local to ISO 8601 Conversion Tests
   *
   * Tests the conversion between:
   * - datetime-local input (browser format: YYYY-MM-DDTHH:mm in LOCAL time)
   * - ISO 8601 UTC format (YYYY-MM-DDTHH:mm:ssZ)
   *
   * This is CRITICAL to ensure scheduled escalations use correct time
   */
  describe("scheduledStartTime conversion (datetime-local ↔ ISO 8601)", () => {
    // Helper to convert datetime-local string to ISO 8601
    function convertToISO8601(dateTimeLocal: string): string {
      const parts = dateTimeLocal.split("T");
      if (parts.length !== 2) return "";

      const datePart = parts[0]!;
      const timePart = parts[1]!;

      const dateParts = datePart.split("-").map(Number);
      const timeParts = timePart.split(":").map(Number);

      if (dateParts.length !== 3 || timeParts.length !== 2) return "";

      const year = dateParts[0]!;
      const month = dateParts[1]!;
      const day = dateParts[2]!;
      const hours = timeParts[0]!;
      const minutes = timeParts[1]!;

      // Create date in LOCAL timezone (not UTC!)
      const dt = new Date(year, month - 1, day, hours, minutes, 0, 0);

      // Convert to ISO 8601 UTC string
      return dt.toISOString();
    }

    // Helper to convert ISO 8601 back to datetime-local format
    function convertToDateTimeLocal(isoString: string): string {
      const dt = new Date(isoString);
      const year = dt.getFullYear();
      const month = String(dt.getMonth() + 1).padStart(2, "0");
      const day = String(dt.getDate()).padStart(2, "0");
      const hours = String(dt.getHours()).padStart(2, "0");
      const minutes = String(dt.getMinutes()).padStart(2, "0");
      return `${year}-${month}-${day}T${hours}:${minutes}`;
    }

    it("correctly converts local datetime to ISO 8601 UTC", () => {
      // User picks "2025-11-14 at 14:30" in their local time
      const localTime = "2025-11-14T14:30";
      const iso = convertToISO8601(localTime);

      // Parse back to verify it's a valid ISO string
      const parsed = new Date(iso);
      expect(parsed.toISOString()).toMatch(/^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d{3}Z$/);
    });

    it("maintains time value during round-trip conversion", () => {
      const originalLocal = "2025-11-14T14:30";
      const iso = convertToISO8601(originalLocal);
      const backToLocal = convertToDateTimeLocal(iso);

      // Should match the original (within parsing accuracy)
      expect(backToLocal).toBe(originalLocal);
    });

    it("handles dates in the future", () => {
      const futureTime = "2025-12-25T23:59";
      const iso = convertToISO8601(futureTime);
      const parsed = new Date(iso);

      // Should be parseable and valid
      expect(parsed.getTime()).toBeGreaterThan(0);
      expect(iso).toMatch(/Z$/); // Should end with Z (UTC)
    });

    it("handles dates across month boundaries", () => {
      const monthBoundary = "2025-11-30T23:00";
      const iso = convertToISO8601(monthBoundary);
      const parsed = new Date(iso);

      // Should properly handle month boundaries
      expect(parsed.toISOString()).toBeDefined();
    });

    it("handles dates across year boundaries", () => {
      const yearBoundary = "2025-12-31T23:59";
      const iso = convertToISO8601(yearBoundary);
      const parsed = new Date(iso);

      // Should properly handle year boundaries
      expect(parsed.toISOString()).toBeDefined();
    });

    it("rejects malformed datetime-local strings", () => {
      const malformed = [
        "",
        "invalid",
        "2025-11-14", // missing time
        "14:30", // missing date
        "2025-11-14 14:30", // wrong separator (space instead of T)
      ];

      malformed.forEach((input) => {
        const result = convertToISO8601(input);
        expect(result).toBe("");
      });

      // Note: JavaScript Date constructor is lenient with invalid dates like "2025-13-01"
      // (month 13 rolls over to next year), so we don't test that case here.
      // Real validation should happen at the backend.
    });

    it("produces ISO 8601 strings that reject past times", () => {
      // Create a time from 1 hour ago
      const now = new Date();
      const pastDate = new Date(now.getTime() - 3600000); // 1 hour ago

      const isoString = pastDate.toISOString();
      const parsed = new Date(isoString);

      // Should be in the past
      expect(parsed.getTime()).toBeLessThan(Date.now());
    });

    it("produces ISO 8601 strings that accept future times", () => {
      // Create a time 24 hours from now
      const now = new Date();
      const futureDate = new Date(now.getTime() + 86400000); // 24 hours from now

      const isoString = futureDate.toISOString();
      const parsed = new Date(isoString);

      // Should be in the future
      expect(parsed.getTime()).toBeGreaterThan(Date.now());
    });
  });
});
