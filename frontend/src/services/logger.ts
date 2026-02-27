import { pushError } from "@/services/errors";

const DEBUG_STORAGE_KEY = "breakglass:debugLogs";
const DEBUG_QUERY_PARAM = "debugLogs";

export interface LogContext {
  [key: string]: unknown;
}

function isDevRuntime(): boolean {
  const nodeEnv =
    typeof globalThis !== "undefined"
      ? (globalThis as unknown as Record<string, Record<string, Record<string, string>>>)?.process?.env?.NODE_ENV
      : undefined;
  if (typeof nodeEnv === "string") {
    return nodeEnv !== "production";
  }
  return false;
}

function ts() {
  return new Date().toISOString();
}

function formatTag(tag: string) {
  return `[${tag}]`;
}

function parseBooleanFlag(value: string | null | undefined): boolean | null {
  if (value === null || value === undefined) return null;
  const normalized = value.trim().toLowerCase();
  if (["1", "true", "yes", "on"].includes(normalized)) return true;
  if (["0", "false", "no", "off"].includes(normalized)) return false;
  return null;
}

function readStoredDebugFlag(): boolean | null {
  if (typeof window === "undefined" || !window.localStorage) return null;
  try {
    const stored = window.localStorage.getItem(DEBUG_STORAGE_KEY);
    return parseBooleanFlag(stored);
  } catch {
    // localStorage unavailable (SSR, sandboxed iframe) — cannot read flag
    return null;
  }
}

function persistDebugFlag(enabled: boolean) {
  if (typeof window === "undefined" || !window.localStorage) return;
  try {
    window.localStorage.setItem(DEBUG_STORAGE_KEY, String(enabled));
  } catch {
    // localStorage write failed (quota, disabled) — non-critical
  }
}

function readQueryDebugFlag(): boolean | null {
  if (typeof window === "undefined") return null;
  try {
    const params = new URLSearchParams(window.location.search);
    const raw = params.get(DEBUG_QUERY_PARAM);
    return parseBooleanFlag(raw);
  } catch {
    // URL parsing failed (SSR or restricted context) — skip query flag
    return null;
  }
}

function detectInitialDebugFlag(): boolean {
  const queryFlag = readQueryDebugFlag();
  if (queryFlag !== null) {
    persistDebugFlag(queryFlag);
    return queryFlag;
  }
  const storedFlag = readStoredDebugFlag();
  if (storedFlag !== null) {
    return storedFlag;
  }
  return isDevRuntime();
}

let debugEnabled = detectInitialDebugFlag();

function announceDebugStatus(source: string) {
  console.info(ts(), "[logger]", `Debug logging ${debugEnabled ? "enabled" : "disabled"} via ${source}`); // eslint-disable-line no-console
}

export function isDebugLoggingEnabled() {
  return debugEnabled;
}

export function setDebugLoggingEnabled(enabled: boolean, source = "manual") {
  debugEnabled = enabled;
  persistDebugFlag(enabled);
  announceDebugStatus(source);
}

export function toggleDebugLogging(source = "manual toggle") {
  setDebugLoggingEnabled(!debugEnabled, source);
}

export function exposeDebugControls() {
  if (typeof window === "undefined") return;
  const w = window as unknown as Record<string, unknown>;
  w.breakglassDebug = {
    enable: () => setDebugLoggingEnabled(true, "window helper"),
    disable: () => setDebugLoggingEnabled(false, "window helper"),
    toggle: () => toggleDebugLogging("window helper toggle"),
    status: () => isDebugLoggingEnabled(),
  };
  if (debugEnabled) {
    announceDebugStatus("initial load");
  }
}

export function debug(tag: string, ...args: unknown[]) {
  if (!debugEnabled) return;
  console.debug(ts(), formatTag(tag), ...args); // eslint-disable-line no-console
}

export function info(tag: string, ...args: unknown[]) {
  console.info(ts(), formatTag(tag), ...args); // eslint-disable-line no-console
}

export function warn(tag: string, ...args: unknown[]) {
  console.warn(ts(), formatTag(tag), ...args);
}

export function error(tag: string, ...args: unknown[]) {
  console.error(ts(), formatTag(tag), ...args);
}

// Normalize axios errors and optionally push to UI error state
// When pushToUI is false, just logs and returns normalized error info without displaying a toast
export function handleAxiosError(
  tag: string,
  err: unknown,
  userMessage?: string,
  pushToUI = true,
): { message: string; status?: number; cid?: string } {
  const axiosErr = err as {
    response?: { data?: Record<string, unknown>; headers?: Record<string, string>; status?: number };
    message?: string;
  };
  const r = axiosErr?.response;
  const cid = (r?.data?.cid as string | undefined) || r?.headers?.["x-request-id"] || r?.headers?.["X-Request-ID"];
  const msg =
    (r?.data?.error as string | undefined) ||
    (typeof r?.data === "string" ? r.data : undefined) ||
    axiosErr?.message ||
    userMessage ||
    "Request failed";
  // Push sanitized message to global error UI if enabled
  if (pushToUI) {
    try {
      pushError(String(msg), r?.status, cid);
    } catch (e) {
      console.error(ts(), "[logger.handleAxiosError] pushError failed", e);
    }
  }
  // Log sanitized error to avoid leaking Authorization headers from Axios error.config
  const safeErr =
    err && typeof err === "object" && "config" in err
      ? { message: (err as { message?: string }).message, status: r?.status, code: (err as { code?: string }).code }
      : err;
  console.error(ts(), formatTag(tag), msg, safeErr);
  return { message: String(msg), status: r?.status, cid };
}

// ── Convenience helpers (merged from logger-console) ──────────────────────────

/** Log outgoing HTTP request at debug level */
export function request(tag: string, method: string, url: string, data?: unknown): void {
  debug(tag, `HTTP ${method} ${url}`, data !== undefined ? { data } : undefined);
}

/** Log HTTP response at debug level */
export function response(tag: string, method: string, url: string, status: number, data?: unknown): void {
  debug(tag, `HTTP ${method} ${url} — ${status}`, data !== undefined ? { data } : undefined);
}

/** Log a user or system action at info level */
export function action(tag: string, actionName: string, details?: LogContext): void {
  info(tag, `Action: ${actionName}`, details !== undefined ? details : undefined);
}

/** Log a state transition at debug level */
export function stateChange(tag: string, from: unknown, to: unknown, reason?: string): void {
  debug(tag, `State change: ${String(from)} → ${String(to)}`, reason !== undefined ? { reason } : undefined);
}

export default {
  info,
  warn,
  error,
  debug,
  request,
  response,
  action,
  stateChange,
  handleAxiosError,
  exposeDebugControls,
  setDebugLoggingEnabled,
  toggleDebugLogging,
  isDebugLoggingEnabled,
};
