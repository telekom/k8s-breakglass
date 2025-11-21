import { reactive } from "vue";

export interface AppError {
  id: string;
  message: string;
  status?: number;
  cid?: string; // correlation id from backend
  ts: number;
  type?: "error" | "success";
}

const state = reactive<{ errors: AppError[] }>({ errors: [] });

export function pushError(message: string, status?: number, cid?: string) {
  const id = Math.random().toString(36).slice(2);
  state.errors.push({
    id,
    message,
    status,
    cid,
    ts: Date.now(),
    type: status && status >= 200 && status < 300 ? "success" : "error",
  });
  setTimeout(() => dismissError(id), 10000);
}

export function pushSuccess(message: string) {
  const id = Math.random().toString(36).slice(2);
  state.errors.push({ id, message, ts: Date.now(), type: "success" });
  setTimeout(() => dismissError(id), 7000);
}

export function dismissError(id: string) {
  const idx = state.errors.findIndex((e) => e.id === id);
  if (idx >= 0) state.errors.splice(idx, 1);
}

export function useErrors() {
  return state;
}
