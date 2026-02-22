export type StatusTone = "success" | "warning" | "danger" | "info" | "neutral" | "muted";

const STATE_TONE_MAP: Record<string, StatusTone> = {
  active: "success",
  approved: "success",
  running: "success",
  available: "info",
  pending: "warning",
  pendingrequest: "warning",
  waitingforscheduledtime: "warning",
  scheduled: "info",
  queued: "info",
  rejected: "danger",
  withdraw: "danger",
  withdrawn: "danger",
  dropped: "danger",
  cancelled: "danger",
  canceled: "danger",
  timeout: "danger",
  approvaltimeout: "danger",
  expired: "muted",
  idleexpired: "danger",
  completed: "muted",
  ended: "muted",
  unknown: "neutral",
  default: "neutral",
};

/**
 * Normalize a backend-provided state string and determine the tone that should be used for
 * rendering a status badge. This allows us to keep look & feel consistent across the app.
 */
export function statusToneFor(state?: string | null): StatusTone {
  if (!state) {
    return "neutral";
  }
  const normalized = state.toString().toLowerCase().replace(/\s+/g, "");
  return STATE_TONE_MAP[normalized] ?? "neutral";
}
