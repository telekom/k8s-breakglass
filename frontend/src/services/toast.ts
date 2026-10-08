import { reactive } from "vue";

export interface AppError {
  id: string;
  message: string;
  status?: number;
  cid?: string; // correlation id from backend
  source?: string; // origin/source of the error (e.g., "DebugSessionService", "HttpClient")
  ts: number;
  type?: "error" | "success" | "warning";
  autoHideDuration?: number;
  opened?: boolean;
}

const ERROR_AUTO_HIDE_MS = 10000;
const SUCCESS_AUTO_HIDE_MS = 6000;
const WARNING_AUTO_HIDE_MS = 8000;

const state = reactive<{ errors: AppError[] }>({ errors: [] });
let nextId = 0;

export interface PushErrorOptions {
  status?: number;
  cid?: string;
  source?: string;
}

/**
 * Add a toast unless an identical one (same type and message) is already
 * shown. One failure is often reported twice, e.g. by the HTTP interceptor
 * with its status code and by the view without it; the visible toast keeps
 * the most specific status and correlation id instead of stacking a copy.
 */
function addToast(entry: Omit<AppError, "id" | "ts" | "opened">): string {
  const existing = state.errors.find((e) => e.opened !== false && e.type === entry.type && e.message === entry.message);
  if (existing) {
    existing.status ??= entry.status;
    existing.cid ??= entry.cid;
    return existing.id;
  }
  const id = `toast-${++nextId}`;
  state.errors.push({ ...entry, id, ts: Date.now(), opened: true });
  setTimeout(() => dismissError(id), (entry.autoHideDuration ?? ERROR_AUTO_HIDE_MS) + 1000);
  return id;
}

export function pushError(message: string, statusOrOptions?: number | PushErrorOptions, cid?: string) {
  // Support both old signature (message, status, cid) and new options object
  let status: number | undefined;
  let correlationId: string | undefined;
  let source: string | undefined;

  if (typeof statusOrOptions === "object") {
    status = statusOrOptions.status;
    correlationId = statusOrOptions.cid;
    source = statusOrOptions.source;
  } else {
    status = statusOrOptions;
    correlationId = cid;
  }

  const isSuccessLike = !!status && status >= 200 && status < 300;
  addToast({
    message,
    status,
    cid: correlationId,
    source,
    type: isSuccessLike ? "success" : "error",
    autoHideDuration: isSuccessLike ? SUCCESS_AUTO_HIDE_MS : ERROR_AUTO_HIDE_MS,
  });
}

const reportedErrors = new WeakSet<object>();

/** Remember that a toast has already been shown for this caught error. */
export function markErrorReported(err: unknown) {
  if (err && typeof err === "object") reportedErrors.add(err);
}

/**
 * Toast a caught error unless the service that threw it already did (via
 * handleAxiosError), so one failure never shows up as two toasts with
 * different wording.
 */
export function reportError(err: unknown, fallback: string) {
  if (err && typeof err === "object" && reportedErrors.has(err)) return;
  pushError((err instanceof Error ? err.message : undefined) || fallback);
}

export function pushSuccess(message: string) {
  addToast({ message, type: "success", autoHideDuration: SUCCESS_AUTO_HIDE_MS });
}

export function pushWarning(message: string) {
  addToast({ message, type: "warning", autoHideDuration: WARNING_AUTO_HIDE_MS });
}

export function dismissError(id: string) {
  const idx = state.errors.findIndex((e) => e.id === id);
  if (idx >= 0) state.errors.splice(idx, 1);
}

export function useErrors() {
  return state;
}
