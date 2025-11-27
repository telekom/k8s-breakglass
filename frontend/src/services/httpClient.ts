import axios, { AxiosHeaders, type AxiosInstance } from "axios";
import type AuthService from "@/services/auth";

export interface ApiClientOptions {
  baseURL?: string;
  enableDevTokenLogging?: boolean;
}

export function createAuthenticatedApiClient(auth: AuthService, options?: ApiClientOptions): AxiosInstance {
  const client = axios.create({
    baseURL: options?.baseURL ?? "/api",
  });

  client.interceptors.request.use(async (config) => {
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
    return config;
  });

  return client;
}
