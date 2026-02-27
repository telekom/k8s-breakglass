/**
 * Composable for parsing and formatting Go-style duration strings
 * e.g., "1h30m45s", "2h", "30m", "1d"
 */

export interface ParsedDuration {
  hours: number;
  minutes: number;
  seconds: number;
  totalSeconds: number;
}

/**
 * Parse a Go duration string format (e.g., "1h30m45s")
 * Supports: days (d), hours (h), minutes (m), seconds (s)
 */
export function parseDurationString(durationStr: string | undefined | null): ParsedDuration | null {
  if (!durationStr) return null;

  // Support days explicitly
  const dayMatch = durationStr.match(/^(\d+)d$/);
  if (dayMatch && dayMatch[1]) {
    const days = parseInt(dayMatch[1], 10);
    return {
      hours: days * 24,
      minutes: 0,
      seconds: 0,
      totalSeconds: days * 86400,
    };
  }

  // Standard Go duration format: "1h30m45s"
  const match = durationStr.match(/^(?:(\d+)h)?(?:(\d+)m)?(?:(\d+)s)?$/);
  if (!match || (!match[1] && !match[2] && !match[3])) {
    return null;
  }

  const hours = parseInt(match[1] || "0", 10);
  const minutes = parseInt(match[2] || "0", 10);
  const seconds = parseInt(match[3] || "0", 10);
  const totalSeconds = hours * 3600 + minutes * 60 + seconds;

  return { hours, minutes, seconds, totalSeconds };
}

/**
 * Format a duration string to human-readable format
 * e.g., "1h30m45s" -> "1h 30m 45s"
 */
export function formatDuration(durationStr: string | undefined | null): string {
  if (!durationStr) return "Not specified";

  const parsed = parseDurationString(durationStr);
  if (!parsed) return durationStr; // Return original if unparseable

  const parts: string[] = [];
  if (parsed.hours > 0) parts.push(`${parsed.hours}h`);
  if (parsed.minutes > 0) parts.push(`${parsed.minutes}m`);
  if (parsed.seconds > 0) parts.push(`${parsed.seconds}s`);

  return parts.length > 0 ? parts.join(" ") : "0s";
}

/**
 * Format duration from seconds to human-readable
 */
export function formatDurationFromSeconds(seconds: number | undefined | null): string {
  if (!seconds || seconds <= 0) return "0s";

  const hours = Math.floor(seconds / 3600);
  const minutes = Math.floor((seconds % 3600) / 60);
  const secs = Math.floor(seconds % 60);

  const parts: string[] = [];
  if (hours > 0) parts.push(`${hours}h`);
  if (minutes > 0) parts.push(`${minutes}m`);
  if (secs > 0) parts.push(`${secs}s`);

  return parts.length > 0 ? parts.join(" ") : "0s";
}

/**
 * Round total seconds to the nearest sensible display unit.
 *
 * Rounding rules (applied in order):
 * - ≥ 1h  → round to nearest 5 min; if the remainder is 0 show hours only
 * - ≥ 1m  → round to nearest minute (drop seconds)
 * - < 1m  → show exact seconds
 *
 * The 5-minute threshold for hours means "1h 59m" becomes "2h" and
 * "1h 32m" becomes "1h 30m".
 *
 * @param totalSeconds — total duration in seconds
 * @returns human-readable rounded string
 */
export function formatRoundedSeconds(totalSeconds: number): string {
  if (!Number.isFinite(totalSeconds) || totalSeconds <= 0) return "0s";

  if (totalSeconds >= 3600) {
    // Round to nearest 5 minutes
    const rounded = Math.round(totalSeconds / 300) * 300;
    const hrs = Math.floor(rounded / 3600);
    const mins = Math.floor((rounded % 3600) / 60);
    const parts: string[] = [];
    if (hrs > 0) parts.push(`${hrs}h`);
    if (mins > 0) parts.push(`${mins}m`);
    return parts.length > 0 ? parts.join(" ") : "0s";
  }

  if (totalSeconds >= 60) {
    // Round to nearest minute
    const mins = Math.round(totalSeconds / 60);
    if (mins >= 60) {
      // Overflows into hours — delegate to the hours-tier rounding
      return formatRoundedSeconds(mins * 60);
    }
    return `${mins}m`;
  }

  // Less than 1 minute — exact seconds
  return `${Math.floor(totalSeconds)}s`;
}

/**
 * Format a Go duration string with cosmetic rounding for display.
 * The original exact value is preserved for backend use — this function
 * is purely for UI presentation.
 *
 * @see formatRoundedSeconds for rounding rules
 */
export function formatDurationRounded(durationStr: string | undefined | null): string {
  if (!durationStr) return "Not specified";

  const parsed = parseDurationString(durationStr);
  if (!parsed) return durationStr;

  return formatRoundedSeconds(parsed.totalSeconds);
}

/**
 * Format duration from seconds with cosmetic rounding for display.
 *
 * @see formatRoundedSeconds for rounding rules
 */
export function formatDurationFromSecondsRounded(seconds: number | undefined | null): string {
  if (!seconds || seconds <= 0) return "0s";
  return formatRoundedSeconds(seconds);
}

/**
 * Compute end time from start time and duration
 */
export function computeEndTime(
  startTimeStr: string | undefined | null,
  durationStr: string | undefined | null,
): Date | null {
  if (!startTimeStr || !durationStr) return null;

  try {
    const startTime = new Date(startTimeStr);
    const parsed = parseDurationString(durationStr);
    if (!parsed) return null;

    return new Date(startTime.getTime() + parsed.totalSeconds * 1000);
  } catch {
    // Date arithmetic or parsing failed — cannot compute end time
    return null;
  }
}

/**
 * Format end time from start and duration strings
 */
export function formatEndTime(
  startTimeStr: string | undefined | null,
  durationStr: string | undefined | null,
  formatter: (date: string) => string = (d) => d,
): string {
  const endTime = computeEndTime(startTimeStr, durationStr);
  if (!endTime) return "Not available";

  return formatter(endTime.toISOString());
}

/**
 * Composable hook for duration utilities
 */
export function useDuration() {
  return {
    parseDurationString,
    formatDuration,
    formatDurationRounded,
    formatDurationFromSeconds,
    formatDurationFromSecondsRounded,
    formatRoundedSeconds,
    computeEndTime,
    formatEndTime,
  };
}
