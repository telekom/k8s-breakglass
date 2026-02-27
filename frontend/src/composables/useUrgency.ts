/**
 * Composable for calculating urgency levels based on time remaining
 */

import { computed, type Ref } from "vue";

export type UrgencyLevel = "critical" | "high" | "normal";

export interface UrgencyConfig {
  /** Threshold in seconds for critical urgency (default: 3600 = 1 hour) */
  criticalThreshold: number;
  /** Threshold in seconds for high urgency (default: 21600 = 6 hours) */
  highThreshold: number;
}

const DEFAULT_CONFIG: UrgencyConfig = {
  criticalThreshold: 3600, // 1 hour
  highThreshold: 21600, // 6 hours
};

/**
 * Get time remaining in seconds until expiry
 */
export function getTimeRemaining(expiresAt: string | Date | undefined | null): number {
  if (!expiresAt) return Infinity;

  try {
    const expiry = typeof expiresAt === "string" ? new Date(expiresAt).getTime() : expiresAt.getTime();
    const now = Date.now();
    return Math.max(0, Math.floor((expiry - now) / 1000));
  } catch {
    // Unparseable date — treat as no deadline (Infinity)
    return Infinity;
  }
}

/**
 * Determine urgency level based on time remaining
 */
export function getUrgency(
  expiresAt: string | Date | undefined | null,
  config: UrgencyConfig = DEFAULT_CONFIG,
): UrgencyLevel {
  const secondsRemaining = getTimeRemaining(expiresAt);

  if (secondsRemaining === Infinity) return "normal";
  if (secondsRemaining < config.criticalThreshold) return "critical";
  if (secondsRemaining < config.highThreshold) return "high";
  return "normal";
}

export type UrgencyLabel = {
  icon: string;
  text: string;
  ariaLabel: string;
};

/**
 * Get urgency label with icon and accessible text
 */
export function getUrgencyLabel(level: UrgencyLevel): UrgencyLabel {
  switch (level) {
    case "critical":
      return { icon: "alert-warning", text: "Critical", ariaLabel: "Critical urgency" };
    case "high":
      return { icon: "content-clock", text: "High", ariaLabel: "High urgency" };
    default:
      return { icon: "content-clock", text: "Normal", ariaLabel: "Normal urgency" };
  }
}

/**
 * Get urgency label as a simple string (for backwards compatibility)
 */
export function getUrgencyLabelString(level: UrgencyLevel): string {
  const label = getUrgencyLabel(level);
  return `${label.icon} ${label.text}`;
}

/**
 * Get urgency description
 */
export function getUrgencyDescription(level: UrgencyLevel): string {
  switch (level) {
    case "critical":
      return "Less than 1 hour remaining";
    case "high":
      return "Less than 6 hours remaining";
    default:
      return "More than 6 hours remaining";
  }
}

/**
 * Check if time has expired
 */
export function isExpired(expiresAt: string | Date | undefined | null): boolean {
  if (!expiresAt) return false;
  return getTimeRemaining(expiresAt) === 0;
}

/**
 * Check if expiry time is in the future
 */
export function isFuture(expiresAt: string | Date | undefined | null): boolean {
  if (!expiresAt) return false;
  return getTimeRemaining(expiresAt) > 0;
}

/**
 * Composable for urgency calculations with reactive updates
 */
export function useUrgency(expiresAt: Ref<string | Date | undefined | null>, config: UrgencyConfig = DEFAULT_CONFIG) {
  const timeRemaining = computed(() => getTimeRemaining(expiresAt.value));
  const urgency = computed(() => getUrgency(expiresAt.value, config));
  const urgencyLabel = computed(() => getUrgencyLabel(urgency.value));
  const urgencyDescription = computed(() => getUrgencyDescription(urgency.value));
  const expired = computed(() => isExpired(expiresAt.value));
  const hasFutureExpiry = computed(() => isFuture(expiresAt.value));

  return {
    timeRemaining,
    urgency,
    urgencyLabel,
    urgencyDescription,
    expired,
    hasFutureExpiry,
  };
}

/**
 * Composable for urgency utilities (non-reactive)
 */
export function useUrgencyUtils(config: UrgencyConfig = DEFAULT_CONFIG) {
  return {
    getTimeRemaining,
    getUrgency: (expiresAt: string | Date | undefined | null) => getUrgency(expiresAt, config),
    getUrgencyLabel,
    getUrgencyLabelString,
    getUrgencyDescription,
    isExpired,
    isFuture,
  };
}
