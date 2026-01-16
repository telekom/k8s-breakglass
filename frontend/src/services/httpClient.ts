import axios, { AxiosHeaders, type AxiosInstance } from "axios";
import type AuthService from "@/services/auth";
import logger from "@/services/logger-console";

export interface ApiClientOptions {
  baseURL?: string;
  enableDevTokenLogging?: boolean;
}

export function createAuthenticatedApiClient(auth: AuthService, options?: ApiClientOptions): AxiosInstance {
  const client = axios.create({
    baseURL: options?.baseURL ?? "/api",
  });

  // Request interceptor
  client.interceptors.request.use(
    async (config) => {
      const headers = AxiosHeaders.from(config.headers || {});
      headers.set("Authorization", `Bearer ${await auth.getAccessToken()}`);

      if (options?.enableDevTokenLogging) {
        try {
          // eslint-disable-next-line @typescript-eslint/ban-ts-comment
          // @ts-ignore - dev flag injected via window
          if (typeof window !== "undefined" && (window.__DEV_TOKEN_LOG === true || window.__DEV_TOKEN_LOG === "true")) {
            console.debug("[httpClient] Authorization header:", headers.get("Authorization"));
          }
        } catch {
          // ignore outside browser contexts
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
    (error) => {
      if (error.response) {
        logger.error("HttpClient", `HTTP ${error.response.status} error`, error, {
          method: error.config?.method?.toUpperCase(),
          url: error.config?.url,
          status: error.response.status,
          data: error.response.data,
        });
      } else if (error.request) {
        logger.error("HttpClient", "No response received", error, {
          method: error.config?.method?.toUpperCase(),
          url: error.config?.url,
          code: error.code,
        });
      } else {
        logger.error("HttpClient", "Request setup error", error);
      }
      return Promise.reject(error);
    },
  );

  return client;
}
