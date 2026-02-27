import type Config from "@/model/config";
import axios from "axios";
import { debug, info, warn, error as logError } from "@/services/logger";
import { getIdentityProvider, extractOIDCConfig } from "@/services/identityProvider";
import { pushError } from "@/services/errors";

const CONFIG_RETRY_ATTEMPTS = 3;
const CONFIG_RETRY_BASE_DELAY_MS = 500;
const UI_FLAVOUR_STORAGE_KEY = "k8sBreakglassUiFlavourOverride";
const SUPPORTED_UI_FLAVOURS = new Set(["telekom", "oss", "neutral"]);
const CLEAR_OVERRIDE_TOKENS = new Set(["auto", "clear", "default", "reset"]);

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchConfigWithRetry(): Promise<Record<string, unknown>> {
  let lastError: unknown;
  for (let attempt = 1; attempt <= CONFIG_RETRY_ATTEMPTS; attempt++) {
    try {
      debug("ConfigService", "Fetching /api/config", { attempt, maxAttempts: CONFIG_RETRY_ATTEMPTS });
      const res = await axios.get<Record<string, unknown>>("/api/config");
      return res.data || {};
    } catch (err) {
      lastError = err;
      const delay = CONFIG_RETRY_BASE_DELAY_MS * Math.pow(2, attempt - 1);
      logError("ConfigService", `Failed to fetch /api/config (attempt ${attempt}/${CONFIG_RETRY_ATTEMPTS})`, err);
      warn(
        "ConfigService",
        "/api/config attempt failed, will retry if attempts remain",
        attempt,
        CONFIG_RETRY_ATTEMPTS,
        err,
      );
      if (attempt < CONFIG_RETRY_ATTEMPTS) {
        await sleep(delay);
      }
    }
  }
  throw lastError;
}

function parseRuntimeConfigPayload(data: Record<string, unknown>): Partial<Config> {
  const result: Partial<Config> = {};
  if (!data || typeof data !== "object") {
    return result;
  }

  const nested = (data.frontend ?? {}) as Record<string, unknown>;

  if (nested.oidcAuthority && nested.oidcClientID) {
    result.oidcAuthority = nested.oidcAuthority as string;
    result.oidcClientID = nested.oidcClientID as string;
  } else if (data.oidcAuthority && data.oidcClientID) {
    result.oidcAuthority = data.oidcAuthority as string;
    result.oidcClientID = data.oidcClientID as string;
  }

  result.brandingName = (nested.brandingName ?? data.brandingName ?? result.brandingName) as string | undefined;
  result.uiFlavour = (nested.uiFlavour ?? data.uiFlavour ?? result.uiFlavour) as string | undefined;

  return result;
}

function mergeConfigValues(target: Partial<Config>, source: Partial<Config>) {
  if (!source) return;
  if (!target.oidcAuthority && source.oidcAuthority) {
    target.oidcAuthority = source.oidcAuthority;
  }
  if (!target.oidcClientID && source.oidcClientID) {
    target.oidcClientID = source.oidcClientID;
  }
  if (typeof target.brandingName === "undefined" && typeof source.brandingName !== "undefined") {
    target.brandingName = source.brandingName;
  }
  if (typeof target.uiFlavour === "undefined" && typeof source.uiFlavour !== "undefined") {
    target.uiFlavour = source.uiFlavour;
  }
}

function normalizeFlavour(value: unknown): string | undefined {
  if (typeof value !== "string") {
    return undefined;
  }
  const normalized = value.trim().toLowerCase();
  return normalized && SUPPORTED_UI_FLAVOURS.has(normalized) ? normalized : undefined;
}

function readBrowserFlavourOverride(): string | undefined {
  if (typeof window === "undefined") {
    return undefined;
  }

  try {
    const params = new URLSearchParams(window.location.search ?? "");
    const rawQueryValue = params.get("flavour") ?? params.get("uiFlavour");

    if (rawQueryValue && CLEAR_OVERRIDE_TOKENS.has(rawQueryValue.toLowerCase())) {
      window.localStorage?.removeItem(UI_FLAVOUR_STORAGE_KEY);
      info("ConfigService", "Cleared UI flavour override");
      return undefined;
    }

    const queryValue = normalizeFlavour(rawQueryValue ?? undefined);
    if (queryValue) {
      window.localStorage?.setItem(UI_FLAVOUR_STORAGE_KEY, queryValue);
      info("ConfigService", "Stored UI flavour override from query", queryValue);
      return queryValue;
    }

    const storedValue = window.localStorage?.getItem(UI_FLAVOUR_STORAGE_KEY);
    return normalizeFlavour(storedValue ?? undefined);
  } catch (err) {
    warn("ConfigService", "Failed to read UI flavour override", err);
    return undefined;
  }
}

// Supports both legacy flat shape { oidcAuthority, oidcClientID }
// and new nested shape { frontend: { oidcAuthority, oidcClientID, uiFlavour }, authorizationServer: {...} }
export default async function getConfig(): Promise<Config> {
  const resolved: Partial<Config> = {};

  try {
    debug("ConfigService", "Fetching configuration from /api/identity-provider");
    const idpConfig = await getIdentityProvider();
    if (idpConfig && idpConfig.type) {
      const oidcConfig = extractOIDCConfig(idpConfig);
      if (oidcConfig) {
        debug("ConfigService", "Successfully extracted OIDC config from IdentityProvider", {
          authority: oidcConfig.oidcAuthority,
          clientID: oidcConfig.oidcClientID,
        });
        resolved.oidcAuthority = oidcConfig.oidcAuthority;
        resolved.oidcClientID = oidcConfig.oidcClientID;
      }
    }
  } catch (err) {
    logError("ConfigService", "Failed to fetch from /api/identity-provider, falling back to /api/config", err);
  }

  const missingOidc = !resolved.oidcAuthority || !resolved.oidcClientID;
  const missingBranding = typeof resolved.brandingName === "undefined";
  const missingFlavour = typeof resolved.uiFlavour === "undefined";
  const needsRuntimeConfig = missingOidc || missingBranding || missingFlavour;

  if (needsRuntimeConfig) {
    debug("ConfigService", "Fetching /api/config for missing fields", {
      missingOidc,
      missingBranding,
      missingFlavour,
    });
    let data: Record<string, unknown> = {};
    try {
      data = await fetchConfigWithRetry();
    } catch (err) {
      if (missingOidc) {
        const status = axios.isAxiosError(err) ? err.response?.status : undefined;
        pushError("Failed to load controller configuration. Please refresh or contact an administrator.", status);
        logError("ConfigService", "Exhausted retries for /api/config", err);
        throw err;
      }
      logError("ConfigService", "Optional fields unavailable from /api/config", err);
    }

    debug("ConfigService", "Received config from /api/config:", {
      hasFlatConfig: !!(data?.oidcAuthority && data?.oidcClientID),
      hasNestedConfig: !!(
        (data?.frontend as Record<string, unknown> | undefined)?.oidcAuthority &&
        (data?.frontend as Record<string, unknown> | undefined)?.oidcClientID
      ),
      keys: data ? Object.keys(data).sort() : [],
    });
    mergeConfigValues(resolved, parseRuntimeConfigPayload(data));
  }

  if (!resolved.oidcAuthority || !resolved.oidcClientID) {
    logError("ConfigService", "Config missing OIDC fields after all attempts", resolved);
    return { oidcAuthority: "", oidcClientID: "", brandingName: resolved.brandingName, uiFlavour: resolved.uiFlavour };
  }

  const finalConfig: Config = {
    oidcAuthority: resolved.oidcAuthority,
    oidcClientID: resolved.oidcClientID,
    brandingName: resolved.brandingName,
    uiFlavour: resolved.uiFlavour,
  };

  const flavourOverride = readBrowserFlavourOverride();
  if (flavourOverride) {
    finalConfig.uiFlavour = flavourOverride;
  }

  return finalConfig;
}
