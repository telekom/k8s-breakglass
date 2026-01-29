import { reactive } from "vue";

export interface AppError {
  id: string;
  message: string;
  status?: number;
  cid?: string; // correlation id from backend
  source?: string; // origin/source of the error (e.g., "DebugSessionService", "HttpClient")
  ts: number;
  type?: "error" | "success";
  autoHideDuration?: number;
  opened?: boolean;
}

const ERROR_AUTO_HIDE_MS = 10000;
const SUCCESS_AUTO_HIDE_MS = 6000;

const state = reactive<{ errors: AppError[] }>({ errors: [] });

export interface PushErrorOptions {
  status?: number;
  cid?: string;
  source?: string;
}

export function pushError(message: string, statusOrOptions?: number | PushErrorOptions, cid?: string) {
  const id = Math.random().toString(36).slice(2);

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
  state.errors.push({
    id,
    message,
    status,
    cid: correlationId,
    source,
    ts: Date.now(),
    type: isSuccessLike ? "success" : "error",
    autoHideDuration: isSuccessLike ? SUCCESS_AUTO_HIDE_MS : ERROR_AUTO_HIDE_MS,
    opened: true,
  });
  setTimeout(() => dismissError(id), (isSuccessLike ? SUCCESS_AUTO_HIDE_MS : ERROR_AUTO_HIDE_MS) + 1000);
}

export function pushSuccess(message: string) {
  const id = Math.random().toString(36).slice(2);
  state.errors.push({
    id,
    message,
    ts: Date.now(),
    type: "success",
    autoHideDuration: SUCCESS_AUTO_HIDE_MS,
    opened: true,
  });
  setTimeout(() => dismissError(id), SUCCESS_AUTO_HIDE_MS + 1000);
}

export function dismissError(id: string) {
  const idx = state.errors.findIndex((e) => e.id === id);
  if (idx >= 0) state.errors.splice(idx, 1);
}

export function useErrors() {
  return state;
}
