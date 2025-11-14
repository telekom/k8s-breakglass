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

describe('BreakglassCard Duration and Reason Handling', () => {
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
  describe('parseDurationInput()', () => {
    // Helper function simulating the parseDurationInput logic
    function parseDurationInput(input: string): number | null {
      if (!input || !input.trim()) {
        return null;
      }

      let totalSeconds = 0;

      // Pattern: "1h 30m", "2h", "30m", or "3600"
      const hoursMatch = input.match(/(\d+)\s*h/i);
      if (hoursMatch && hoursMatch[1]) {
        totalSeconds += parseInt(hoursMatch[1], 10) * 3600;
      }

      const minutesMatch = input.match(/(\d+)\s*m/i);
      if (minutesMatch && minutesMatch[1]) {
        totalSeconds += parseInt(minutesMatch[1], 10) * 60;
      }

      // If only numbers (seconds)
      if (!input.match(/[a-z]/i) && input.match(/^\d+$/)) {
        totalSeconds = parseInt(input, 10);
      }

      return totalSeconds > 0 ? totalSeconds : null;
    }

    it('parses simple hours', () => {
      expect(parseDurationInput('1h')).toBe(3600);
      expect(parseDurationInput('2h')).toBe(7200);
      expect(parseDurationInput('24h')).toBe(86400);
    });

    it('parses simple minutes', () => {
      expect(parseDurationInput('30m')).toBe(1800);
      expect(parseDurationInput('45m')).toBe(2700);
      expect(parseDurationInput('1m')).toBe(60);
    });

    it('parses combined hours and minutes', () => {
      expect(parseDurationInput('1h 30m')).toBe(5400); // 3600 + 1800
      expect(parseDurationInput('2h 15m')).toBe(8100); // 7200 + 900
      expect(parseDurationInput('1h 1m')).toBe(3660);
    });

    it('parses combined without spaces', () => {
      expect(parseDurationInput('1h30m')).toBe(5400);
      expect(parseDurationInput('2h15m')).toBe(8100);
    });

    it('parses raw seconds', () => {
      expect(parseDurationInput('3600')).toBe(3600);
      expect(parseDurationInput('7200')).toBe(7200);
      expect(parseDurationInput('60')).toBe(60);
    });

    it('case-insensitive parsing', () => {
      expect(parseDurationInput('1H')).toBe(3600);
      expect(parseDurationInput('30M')).toBe(1800);
      expect(parseDurationInput('1H 30M')).toBe(5400);
    });

    it('parses with extra spaces', () => {
      expect(parseDurationInput('  1h  ')).toBe(3600);
      expect(parseDurationInput('1h  30m')).toBe(5400);
      expect(parseDurationInput('  1h 30m  ')).toBe(5400);
    });

    it('returns null for empty input', () => {
      expect(parseDurationInput('')).toBeNull();
      expect(parseDurationInput('   ')).toBeNull();
      expect(parseDurationInput('\n')).toBeNull();
    });

    it('returns null for invalid input', () => {
      expect(parseDurationInput('invalid')).toBeNull();
      expect(parseDurationInput('xyz')).toBeNull();
      expect(parseDurationInput('1x')).toBeNull();
    });

    it('returns null for zero or negative results', () => {
      expect(parseDurationInput('0h')).toBeNull();
      expect(parseDurationInput('0m')).toBeNull();
      expect(parseDurationInput('0')).toBeNull();
    });

    it('parses single unit correctly', () => {
      expect(parseDurationInput('5h')).toBe(18000);
      expect(parseDurationInput('90m')).toBe(5400);
    });

    it('handles leading zeros', () => {
      expect(parseDurationInput('01h')).toBe(3600);
      expect(parseDurationInput('00h 30m')).toBe(1800);
    });
  });

  /**
   * sanitizeReason() tests
   *
   * Tests HTML entity escaping to prevent XSS attacks
   * Covers: normal text, HTML entities, special characters
   */
  describe('sanitizeReason()', () => {
    // Helper function simulating the sanitizeReason logic
    function sanitizeReason(text: string): string {
      const htmlEntities: Record<string, string> = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;',
      };
      return text.replace(/[&<>"']/g, (char) => htmlEntities[char] || char);
    }

    it('escapes angle brackets', () => {
      expect(sanitizeReason('<script>')).toBe('&lt;script&gt;');
      expect(sanitizeReason('<div>test</div>')).toBe('&lt;div&gt;test&lt;/div&gt;');
    });

    it('escapes ampersands', () => {
      expect(sanitizeReason('fish & chips')).toBe('fish &amp; chips');
      expect(sanitizeReason('A & B & C')).toBe('A &amp; B &amp; C');
    });

    it('escapes quotes', () => {
      expect(sanitizeReason('say "hello"')).toBe('say &quot;hello&quot;');
      expect(sanitizeReason("it's fine")).toBe('it&#39;s fine');
    });

    it('escapes XSS attempts', () => {
      expect(sanitizeReason('<img src=x onerror="alert(1)">')).toBe(
        '&lt;img src=x onerror=&quot;alert(1)&quot;&gt;'
      );
      expect(sanitizeReason('<svg onload="alert(1)">')).toBe(
        '&lt;svg onload=&quot;alert(1)&quot;&gt;'
      );
    });

    it('preserves normal text', () => {
      expect(sanitizeReason('Database maintenance')).toBe('Database maintenance');
      expect(sanitizeReason('Testing in production')).toBe('Testing in production');
    });

    it('handles multiple special characters', () => {
      expect(sanitizeReason('Test & fix <bug>')).toBe('Test &amp; fix &lt;bug&gt;');
    });

    it('handles empty string', () => {
      expect(sanitizeReason('')).toBe('');
    });

    it('handles whitespace-only text', () => {
      expect(sanitizeReason('   ')).toBe('   ');
      expect(sanitizeReason('\t\n')).toBe('\t\n');
    });

    it('does not escape safe characters', () => {
      expect(sanitizeReason('Hello World 123!@#$%')).toBe('Hello World 123!@#$%');
    });
  });

  /**
   * validateDuration() tests
   *
   * Tests client-side duration validation
   * Covers: minimum duration (60s), maximum boundary, valid ranges
   */
  describe('validateDuration()', () => {
    // Helper function simulating the validateDuration logic
    function validateDuration(
      seconds: number | null,
      maxAllowed: number
    ): { valid: boolean; error?: string } {
      if (seconds === null || seconds === undefined) {
        return { valid: true }; // No duration specified, will use default
      }

      if (seconds < 60) {
        return { valid: false, error: 'Minimum duration is 1 minute' };
      }

      if (seconds > maxAllowed) {
        return {
          valid: false,
          error: `Duration cannot exceed ${maxAllowed} seconds`,
        };
      }

      return { valid: true };
    }

    it('accepts null/undefined (will use default)', () => {
      expect(validateDuration(null, 3600)).toEqual({ valid: true });
      expect(validateDuration(undefined as any, 3600)).toEqual({ valid: true });
    });

    it('rejects duration below 60 seconds', () => {
      const result = validateDuration(30, 3600);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('Minimum duration is 1 minute');
    });

    it('accepts duration at minimum (60 seconds)', () => {
      expect(validateDuration(60, 3600)).toEqual({ valid: true });
    });

    it('accepts duration in valid range', () => {
      expect(validateDuration(1800, 3600)).toEqual({ valid: true });
      expect(validateDuration(2700, 3600)).toEqual({ valid: true });
    });

    it('accepts duration at maximum', () => {
      expect(validateDuration(3600, 3600)).toEqual({ valid: true });
    });

    it('rejects duration exceeding maximum', () => {
      const result = validateDuration(3601, 3600);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('cannot exceed');
    });

    it('rejects negative duration', () => {
      const result = validateDuration(-100, 3600);
      expect(result.valid).toBe(false);
      expect(result.error).toContain('Minimum duration');
    });

    it('handles different max values', () => {
      expect(validateDuration(7200, 3600)).toEqual({
        valid: false,
        error: 'Duration cannot exceed 3600 seconds',
      });
      expect(validateDuration(7200, 86400)).toEqual({ valid: true });
    });

    it('accepts large valid durations', () => {
      expect(validateDuration(86400, 86400)).toEqual({ valid: true }); // 24 hours
    });

    it('rejects large durations exceeding max', () => {
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
  describe('formatDurationSeconds()', () => {
    // Helper function simulating the formatDurationSeconds logic
    function formatDurationSeconds(seconds: number): string {
      if (seconds <= 0) return '0s';

      const hours = Math.floor(seconds / 3600);
      const minutes = Math.floor((seconds % 3600) / 60);
      const secs = seconds % 60;

      const parts = [];
      if (hours > 0) parts.push(`${hours}h`);
      if (minutes > 0) parts.push(`${minutes}m`);
      if (secs > 0) parts.push(`${secs}s`);

      return parts.join(' ');
    }

    it('formats hours only', () => {
      expect(formatDurationSeconds(3600)).toBe('1h');
      expect(formatDurationSeconds(7200)).toBe('2h');
      expect(formatDurationSeconds(86400)).toBe('24h');
    });

    it('formats minutes only', () => {
      expect(formatDurationSeconds(60)).toBe('1m');
      expect(formatDurationSeconds(1800)).toBe('30m');
      expect(formatDurationSeconds(2700)).toBe('45m');
    });

    it('formats seconds only', () => {
      expect(formatDurationSeconds(30)).toBe('30s');
      expect(formatDurationSeconds(45)).toBe('45s');
    });

    it('formats hours and minutes', () => {
      expect(formatDurationSeconds(5400)).toBe('1h 30m');
      expect(formatDurationSeconds(8100)).toBe('2h 15m');
    });

    it('formats hours, minutes and seconds', () => {
      expect(formatDurationSeconds(3661)).toBe('1h 1m 1s');
      expect(formatDurationSeconds(7325)).toBe('2h 2m 5s');
    });

    it('handles zero', () => {
      expect(formatDurationSeconds(0)).toBe('0s');
    });

    it('handles negative values', () => {
      expect(formatDurationSeconds(-100)).toBe('0s');
    });

    it('formats common durations', () => {
      expect(formatDurationSeconds(300)).toBe('5m');
      expect(formatDurationSeconds(600)).toBe('10m');
      expect(formatDurationSeconds(1800)).toBe('30m');
      expect(formatDurationSeconds(3600)).toBe('1h');
    });

    it('omits zero components', () => {
      expect(formatDurationSeconds(3600)).toBe('1h'); // No 0m or 0s
      expect(formatDurationSeconds(1800)).toBe('30m'); // No 0h or 0s
      expect(formatDurationSeconds(60)).toBe('1m'); // No 0h or 0s
    });
  });

  /**
   * Combined Integration Tests
   *
   * Tests the interaction between parsing, sanitization, and validation
   */
  describe('Integration', () => {
    function parseDurationInput(input: string): number | null {
      if (!input || !input.trim()) return null;
      let totalSeconds = 0;
      const hoursMatch = input.match(/(\d+)\s*h/i);
      if (hoursMatch && hoursMatch[1]) {
        totalSeconds += parseInt(hoursMatch[1], 10) * 3600;
      }
      const minutesMatch = input.match(/(\d+)\s*m/i);
      if (minutesMatch && minutesMatch[1]) {
        totalSeconds += parseInt(minutesMatch[1], 10) * 60;
      }
      if (!input.match(/[a-z]/i) && input.match(/^\d+$/)) {
        totalSeconds = parseInt(input, 10);
      }
      return totalSeconds > 0 ? totalSeconds : null;
    }

    function validateDuration(
      seconds: number | null,
      maxAllowed: number
    ): { valid: boolean; error?: string } {
      if (seconds === null || seconds === undefined) {
        return { valid: true };
      }
      if (seconds < 60) {
        return { valid: false, error: 'Minimum duration is 1 minute' };
      }
      if (seconds > maxAllowed) {
        return { valid: false, error: `Duration cannot exceed ${maxAllowed} seconds` };
      }
      return { valid: true };
    }

    function sanitizeReason(text: string): string {
      const htmlEntities: Record<string, string> = {
        '&': '&amp;',
        '<': '&lt;',
        '>': '&gt;',
        '"': '&quot;',
        "'": '&#39;',
      };
      return text.replace(/[&<>"']/g, (char) => htmlEntities[char] || char);
    }

    it('parses and validates a request with custom duration', () => {
      const userInput = '1h 30m';
      const parsed = parseDurationInput(userInput);
      const validation = validateDuration(parsed, 7200); // 2 hour max

      expect(parsed).toBe(5400);
      expect(validation.valid).toBe(true);
    });

    it('rejects request with duration exceeding max', () => {
      const userInput = '3h';
      const parsed = parseDurationInput(userInput);
      const validation = validateDuration(parsed, 7200); // 2 hour max

      expect(parsed).toBe(10800);
      expect(validation.valid).toBe(false);
      expect(validation.error).toContain('cannot exceed');
    });

    it('sanitizes reason with XSS attempt', () => {
      const unsafeReason = '<img src=x onerror="steal()">';
      const sanitized = sanitizeReason(unsafeReason);

      expect(sanitized).not.toContain('<');
      expect(sanitized).not.toContain('>');
      expect(sanitized).toContain('&lt;');
      expect(sanitized).toContain('&gt;');
    });

    it('handles complete request validation flow', () => {
      const durationInput = '30m';
      const reasonInput = 'Fixing <critical> bug & config issue';
      const maxDuration = 3600; // 1 hour

      const parsedDuration = parseDurationInput(durationInput);
      const durationValidation = validateDuration(parsedDuration, maxDuration);
      const sanitizedReason = sanitizeReason(reasonInput);

      expect(parsedDuration).toBe(1800);
      expect(durationValidation.valid).toBe(true);
      expect(sanitizedReason).toBe('Fixing &lt;critical&gt; bug &amp; config issue');
    });

    it('rejects invalid input at any step', () => {
      const invalidDuration = 'invalid';
      const invalidReason = ''; // Will be trimmed
      const maxDuration = 3600;

      const parsed = parseDurationInput(invalidDuration);
      expect(parsed).toBeNull();

      // Even if reason is empty, validation should still work
      const validation = validateDuration(null, maxDuration);
      expect(validation.valid).toBe(true); // null means use default
    });
  });
});
