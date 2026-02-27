/**
 * Common error type for Axios-like error handling.
 *
 * Extracted to avoid repeating the same inline type cast across views.
 * Use `as AxiosLikeError` instead of defining the type inline.
 */
export interface AxiosLikeError {
  response?: { status?: number; data?: Record<string, unknown>; headers?: Record<string, string> };
  message?: string;
  code?: string;
  status?: number;
}
