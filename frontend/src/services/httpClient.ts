import axios, { AxiosHeaders, type AxiosInstance, type InternalAxiosRequestConfig } from "axios";
import type AuthService from "@/services/auth";
import logger from "@/services/logger";

export interface ApiClientOptions {
  baseURL?: string;
  enableDevTokenLogging?: boolean;
  /** If true, will attempt silent token renew on 401 and retry the request once */
  retryOn401?: boolean;
  /** Request timeout in milliseconds. Defaults to 30000 (30 seconds). */
  timeout?: number;
}

/** Default timeout for HTTP requests (30 seconds) */
const DEFAULT_TIMEOUT_MS = 30000;

// Track if we're currently retrying to avoid infinite loops
const RETRY_FLAG = "__authRetried";

export function createAuthenticatedApiClient(auth: AuthService, options?: ApiClientOptions): AxiosInstance {
  const client = axios.create({
    baseURL: options?.baseURL ?? "/api",
    timeout: options?.timeout ?? DEFAULT_TIMEOUT_MS,
  });

  // Request interceptor
  client.interceptors.request.use(
    async (config) => {
      const headers = AxiosHeaders.from(config.headers || {});
      headers.set("Authorization", `Bearer ${await auth.getAccessToken()}`);

      if (options?.enableDevTokenLogging && import.meta.env.DEV) {
        try {
          // eslint-disable-next-line @typescript-eslint/ban-ts-comment
          // @ts-ignore - dev flag injected via window
          if (typeof window !== "undefined" && (window.__DEV_TOKEN_LOG === true || window.__DEV_TOKEN_LOG === "true")) {
            logger.debug("HttpClient", "Authorization header:", headers.get("Authorization"));
          }
        } catch {
          // Window object unavailable (SSR / test) — dev token logging not applicable
        }
      }

      config.headers = headers;

      // Log outgoing request
      logger.request("HttpClient", config.method?.toUpperCase() || "GET", config.url || "", config.data);

      return config;
    },
    (error) => {
      logger.error("HttpClient", "Request interceptor error", error);
      return Promise.reject(error);
    },
  );

  // Response interceptor
  client.interceptors.response.use(
    (response) => {
      logger.response(
        "HttpClient",
        response.config.method?.toUpperCase() || "GET",
        response.config.url || "",
        response.status,
        response.data,
      );
      return response;
    },
    async (error) => {
      const config = error.config as InternalAxiosRequestConfig & { [RETRY_FLAG]?: boolean };

      // Handle 401 errors with optional retry after silent renew
      if (error.response?.status === 401 && options?.retryOn401 !== false && !config?.[RETRY_FLAG]) {
        logger.debug("HttpClient", "Received 401, attempting silent token renew before retry");

        try {
          const renewed = await auth.trySilentRenew();
          if (renewed) {
            logger.debug("HttpClient", "Silent renew successful, retrying request");
            // Mark this request as retried to avoid infinite loops
            config[RETRY_FLAG] = true;
            // Update the authorization header with the new token
            const headers = AxiosHeaders.from(config.headers || {});
            headers.set("Authorization", `Bearer ${await auth.getAccessToken()}`);
            config.headers = headers;
            // Retry the request
            return client.request(config);
          } else {
            logger.warn("HttpClient", "Silent renew failed, not retrying request");
          }
        } catch (renewError) {
          logger.error("HttpClient", "Error during silent renew attempt", renewError);
        }
      }

      if (error.response) {
        logger.error("HttpClient", `HTTP ${error.response.status} error`, error, {
          method: error.config?.method?.toUpperCase(),
          url: error.config?.url,
          status: error.response.status,
          data: error.response.data,
        });
      } else if (error.request) {
        // Check if this is a timeout error (axios uses ECONNABORTED for timeouts)
        const isTimeout = error.code === "ECONNABORTED";
        const errorType = isTimeout ? "Request timeout" : "No response received";
        logger.error("HttpClient", errorType, error, {
          method: error.config?.method?.toUpperCase(),
          url: error.config?.url,
          code: error.code,
          timeout: isTimeout ? (options?.timeout ?? DEFAULT_TIMEOUT_MS) : undefined,
        });
      } else {
        logger.error("HttpClient", "Request setup error", error);
      }
      return Promise.reject(error);
    },
  );

  return client;
}
