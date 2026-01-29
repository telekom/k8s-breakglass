import { pushError } from "@/services/errors";

const DEBUG_STORAGE_KEY = "breakglass:debugLogs";
const DEBUG_QUERY_PARAM = "debugLogs";

function isDevRuntime(): boolean {
  const nodeEnv = typeof globalThis !== "undefined" ? (globalThis as any)?.process?.env?.NODE_ENV : undefined;
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
    return null;
  }
}

function persistDebugFlag(enabled: boolean) {
  if (typeof window === "undefined" || !window.localStorage) return;
  try {
    window.localStorage.setItem(DEBUG_STORAGE_KEY, String(enabled));
  } catch {
    // ignore persistence failures
  }
}

function readQueryDebugFlag(): boolean | null {
  if (typeof window === "undefined") return null;
  try {
    const params = new URLSearchParams(window.location.search);
    const raw = params.get(DEBUG_QUERY_PARAM);
    return parseBooleanFlag(raw);
  } catch {
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
  console.info(ts(), "[logger]", `Debug logging ${debugEnabled ? "enabled" : "disabled"} via ${source}`);
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
  (window as any).breakglassDebug = {
    enable: () => setDebugLoggingEnabled(true, "window helper"),
    disable: () => setDebugLoggingEnabled(false, "window helper"),
    toggle: () => toggleDebugLogging("window helper toggle"),
    status: () => isDebugLoggingEnabled(),
  };
  if (debugEnabled) {
    announceDebugStatus("initial load");
  }
}

export function debug(tag: string, ...args: any[]) {
  if (!debugEnabled) return;
  console.debug(ts(), formatTag(tag), ...args);
}

export function info(tag: string, ...args: any[]) {
  // keep things readable in dev and minimal in prod
  console.info(ts(), formatTag(tag), ...args);
}

export function warn(tag: string, ...args: any[]) {
  console.warn(ts(), formatTag(tag), ...args);
}

export function error(tag: string, ...args: any[]) {
  // send structured message to UI error store as well
  console.error(ts(), formatTag(tag), ...args);
}

// Normalize axios errors and optionally push to UI error state
// When pushToUI is false, just logs and returns normalized error info without displaying a toast
export function handleAxiosError(tag: string, err: any, userMessage?: string, pushToUI = true) {
  const r = err?.response;
  const cid = r?.data?.cid || r?.headers?.["x-request-id"] || r?.headers?.["X-Request-ID"];
  const msg =
    r?.data?.error ||
    (typeof r?.data === "string" ? r.data : undefined) ||
    err.message ||
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
  console.error(ts(), formatTag(tag), msg, err);
  return { message: String(msg), status: r?.status, cid };
}

export default {
  info,
  warn,
  error,
  debug,
  handleAxiosError,
  exposeDebugControls,
  setDebugLoggingEnabled,
  toggleDebugLogging,
  isDebugLoggingEnabled,
};
