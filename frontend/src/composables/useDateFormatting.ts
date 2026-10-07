/**
 * Composable for date/time formatting utilities
 * Wraps utils/dateTime.ts functions for use in Vue components
 */

import { format24Hour } from "@/utils/dateTime";

export type DateValue = string | Date | number | undefined | null;

/**
 * Normalize various date formats to ISO string
 */
function toISOString(value: DateValue): string | null {
  if (!value) return null;

  try {
    if (typeof value === "string") {
      return value;
    }
    if (typeof value === "number") {
      return new Date(value).toISOString();
    }
    if (value instanceof Date) {
      return value.toISOString();
    }
    return null;
  } catch {
    // Value is not convertible to ISO date string — return null as sentinel
    return null;
  }
}

/**
 * Format date/time to 24-hour format with full details
 */
export function formatDateTime(value: DateValue): string {
  const iso = toISOString(value);
  return iso ? format24Hour(iso) : "—";
}

/**
 * Format relative time (e.g., "5 minutes ago")
 */
export function formatRelativeTime(value: DateValue): string {
  const iso = toISOString(value);
  if (!iso) return "—";

  try {
    const date = new Date(iso);
    const now = Date.now();
    const diff = now - date.getTime();
    const seconds = Math.floor(Math.abs(diff) / 1000);
    const minutes = Math.floor(seconds / 60);
    const hours = Math.floor(minutes / 60);
    const days = Math.floor(hours / 24);

    const isFuture = diff < 0;
    const prefix = isFuture ? "in " : "";
    const suffix = isFuture ? "" : " ago";

    if (seconds < 60) return `${prefix}${seconds}s${suffix}`;
    if (minutes < 60) return `${prefix}${minutes}m${suffix}`;
    if (hours < 24) return `${prefix}${hours}h${suffix}`;
    if (days < 7) return `${prefix}${days}d${suffix}`;

    // For longer periods, use formatted date
    return formatDateTime(value);
  } catch {
    // Date arithmetic failed (e.g. invalid ISO string) — return placeholder
    return "—";
  }
}
