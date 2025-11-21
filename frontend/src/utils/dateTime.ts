/**
 * DateTime formatting utilities with 24-hour format preference
 * Respects browser locale while enforcing 24-hour time format
 */

// Detect browser locale and log it for debugging
const browserLocale = navigator.language || "en-US";
const userTimeZone = Intl.DateTimeFormat().resolvedOptions().timeZone;
const use12Hour = /^en-US|^en-PH|^ja-JP|^ko-KR/.test(browserLocale);

console.log("[DateTime] Initialization:");
console.log(`  Browser locale: ${browserLocale}`);
console.log(`  User timezone: ${userTimeZone}`);
console.log(`  Browser prefers 12-hour format: ${use12Hour}`);
console.log(`  Using 24-hour format override: true`);

/**
 * Format a date/time string to 24-hour format
 * Respects user's timezone but enforces 24-hour display
 * @param isoString ISO 8601 date string
 * @param options Optional formatting options
 * @returns Formatted date string in 24-hour format
 */
export function format24Hour(
  isoString: string | null | undefined,
  options?: Partial<Intl.DateTimeFormatOptions>,
): string {
  if (!isoString) return "";

  try {
    const date = new Date(isoString);

    const defaultOptions: Intl.DateTimeFormatOptions = {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false, // Force 24-hour format
    };

    const mergedOptions = { ...defaultOptions, ...options };
    const formatted = date.toLocaleString(browserLocale, mergedOptions);

    return formatted;
  } catch (e) {
    console.error("[DateTime] Error formatting date:", isoString, e);
    return isoString;
  }
}

/**
 * Format date only in 24-hour context (no time)
 * @param isoString ISO 8601 date string
 * @returns Formatted date string
 */
export function formatDate(isoString: string | null | undefined): string {
  if (!isoString) return "";

  try {
    const date = new Date(isoString);
    return date.toLocaleString(browserLocale, {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour12: false,
    });
  } catch (e) {
    console.error("[DateTime] Error formatting date:", isoString, e);
    return isoString;
  }
}

/**
 * Format time only in 24-hour format
 * @param isoString ISO 8601 date string
 * @returns Formatted time string (HH:mm:ss)
 */
export function formatTime(isoString: string | null | undefined): string {
  if (!isoString) return "";

  try {
    const date = new Date(isoString);
    return date.toLocaleString(browserLocale, {
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
    });
  } catch (e) {
    console.error("[DateTime] Error formatting time:", isoString, e);
    return isoString;
  }
}

/**
 * Format time without seconds in 24-hour format
 * @param isoString ISO 8601 date string
 * @returns Formatted time string (HH:mm)
 */
export function formatTimeShort(isoString: string | null | undefined): string {
  if (!isoString) return "";

  try {
    const date = new Date(isoString);
    return date.toLocaleString(browserLocale, {
      hour: "2-digit",
      minute: "2-digit",
      hour12: false,
    });
  } catch (e) {
    console.error("[DateTime] Error formatting time:", isoString, e);
    return isoString;
  }
}

/**
 * Format relative to local timezone with timezone info
 * @param isoString ISO 8601 date string
 * @returns Formatted string with timezone
 */
export function format24HourWithTZ(isoString: string | null | undefined): string {
  if (!isoString) return "";

  try {
    const date = new Date(isoString);
    const formatted = date.toLocaleString(browserLocale, {
      year: "numeric",
      month: "2-digit",
      day: "2-digit",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
      hour12: false,
      timeZoneName: "short",
    });

    return formatted;
  } catch (e) {
    console.error("[DateTime] Error formatting date with TZ:", isoString, e);
    return isoString;
  }
}

/**
 * Get current browser locale info for debugging
 */
export function getLocaleInfo() {
  return {
    browserLocale,
    userTimeZone,
    use12Hour,
    timeZoneOffset: new Date().getTimezoneOffset(),
  };
}

/**
 * Log locale and formatting decisions for debugging
 */
export function debugLogDateTime(label: string, isoString: string | null | undefined): void {
  if (!isoString) {
    console.debug(`[DateTime] ${label}: (empty)`);
    return;
  }

  const date = new Date(isoString);
  const formatted24hr = format24Hour(isoString);
  const withTZ = format24HourWithTZ(isoString);

  console.debug(`[DateTime] ${label}:`, {
    isoString,
    formatted24hr,
    withTZ,
    utcTime: date.toUTCString(),
    locale: browserLocale,
    timezone: userTimeZone,
  });
}
