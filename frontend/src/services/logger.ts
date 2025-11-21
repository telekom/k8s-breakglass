import { pushError } from "@/services/errors";

function ts() {
  return new Date().toISOString();
}

function formatTag(tag: string) {
  return `[${tag}]`;
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

// Normalize axios errors and push to UI error state
export function handleAxiosError(tag: string, err: any, userMessage?: string) {
  const r = err?.response;
  const cid = r?.data?.cid || r?.headers?.["x-request-id"] || r?.headers?.["X-Request-ID"];
  const msg =
    r?.data?.error ||
    (typeof r?.data === "string" ? r.data : undefined) ||
    err.message ||
    userMessage ||
    "Request failed";
  // Push sanitized message to global error UI
  try {
    pushError(String(msg), r?.status, cid);
  } catch (e) {
    console.error(ts(), "[logger.handleAxiosError] pushError failed", e);
  }
  console.error(ts(), formatTag(tag), msg, err);
  return { message: String(msg), status: r?.status, cid };
}

export default {
  info,
  warn,
  error,
  handleAxiosError,
};
