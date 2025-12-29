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
    formatDurationFromSeconds,
    computeEndTime,
    formatEndTime,
  };
}
