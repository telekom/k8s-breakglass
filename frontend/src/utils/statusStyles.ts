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

const STATE_DESCRIPTION_MAP: Record<string, string> = {
  pending: "Waiting for an approver to decide",
  pendingapproval: "Waiting for an approver to decide",
  approved: "Approved; access is granted until the session expires",
  active: "Access is currently granted",
  rejected: "An approver rejected this request",
  withdrawn: "The requester withdrew this request",
  expired: "The session reached its end time; access is revoked",
  idleexpired: "The session ended because it was idle; access is revoked",
  approvaltimeout: "No approver decided in time; the request lapsed",
  timeout: "No approver decided in time; the request lapsed",
  waitingforscheduledtime: "Approved; access starts at the scheduled time",
  terminated: "The session was ended early; access is revoked",
  failed: "The debug workload could not be started",
};

/** Short explanation of a backend session state, for status tag tooltips. */
export function statusDescriptionFor(state?: string | null): string {
  if (!state) return "";
  return STATE_DESCRIPTION_MAP[state.toString().toLowerCase().replace(/\s+/g, "")] ?? "";
}
