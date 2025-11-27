import type Config from "@/model/config";
import axios from "axios";
import { error as logError } from "@/services/logger";
import { getIdentityProvider, extractOIDCConfig } from "@/services/identityProvider";
import { pushError } from "@/services/errors";

const CONFIG_RETRY_ATTEMPTS = 3;
const CONFIG_RETRY_BASE_DELAY_MS = 500;

function sleep(ms: number) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

async function fetchConfigWithRetry(): Promise<any> {
  let lastError: unknown;
  for (let attempt = 1; attempt <= CONFIG_RETRY_ATTEMPTS; attempt++) {
    try {
      console.debug("[ConfigService] Fetching /api/config", { attempt, maxAttempts: CONFIG_RETRY_ATTEMPTS });
      const res = await axios.get<any>("/api/config");
      return res.data || {};
    } catch (err) {
      lastError = err;
      const delay = CONFIG_RETRY_BASE_DELAY_MS * Math.pow(2, attempt - 1);
      logError(
        "ConfigService",
        `Failed to fetch /api/config (attempt ${attempt}/${CONFIG_RETRY_ATTEMPTS})`,
        err,
      );
      console.warn(
        "[ConfigService] /api/config attempt failed, will retry if attempts remain",
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

// Supports both legacy flat shape { oidcAuthority, oidcClientID }
// and new nested shape { frontend: { oidcAuthority, oidcClientID, uiFlavour }, authorizationServer: {...} }
export default async function getConfig(): Promise<Config> {
  try {
    console.debug("[ConfigService] Fetching configuration from /api/identity-provider");
    // Try fetching from new IdentityProvider endpoint first
    const idpConfig = await getIdentityProvider();
    if (idpConfig && idpConfig.type) {
      const oidcConfig = extractOIDCConfig(idpConfig);
      if (oidcConfig) {
        console.debug("[ConfigService] Successfully extracted OIDC config from IdentityProvider", {
          authority: oidcConfig.oidcAuthority,
          clientID: oidcConfig.oidcClientID,
        });
        return {
          oidcAuthority: oidcConfig.oidcAuthority,
          oidcClientID: oidcConfig.oidcClientID,
          brandingName: undefined,
          uiFlavour: undefined,
        };
      }
    }
  } catch (err) {
    logError("ConfigService", "Failed to fetch from /api/identity-provider, falling back to /api/config", err);
    console.warn("[ConfigService] Failed to fetch from /api/identity-provider, falling back to /api/config", err);
  }

  // Fall back to /api/config if IdentityProvider endpoint fails or returns invalid data
  console.debug("[ConfigService] Falling back to /api/config endpoint");
  let data: any = {};
  try {
    data = await fetchConfigWithRetry();
  } catch (err) {
    const status = axios.isAxiosError(err) ? err.response?.status : undefined;
    pushError("Failed to load controller configuration. Please refresh or contact an administrator.", status);
    logError("ConfigService", "Exhausted retries for /api/config", err);
    throw err;
  }
  console.debug("[ConfigService] Received config from /api/config:", {
    hasFlatConfig: !!(data.oidcAuthority && data.oidcClientID),
    hasNestedConfig: !!(data.frontend?.oidcAuthority && data.frontend?.oidcClientID),
    keys: Object.keys(data).sort(),
  });
  if (data.oidcAuthority && data.oidcClientID) {
    console.debug("[ConfigService] Using flat config structure");
    return {
      oidcAuthority: data.oidcAuthority,
      oidcClientID: data.oidcClientID,
      brandingName: data.brandingName,
      uiFlavour: data.uiFlavour,
    };
  }
  if (data.frontend && data.frontend.oidcAuthority && data.frontend.oidcClientID) {
    console.debug("[ConfigService] Using nested config structure");
    return {
      oidcAuthority: data.frontend.oidcAuthority,
      oidcClientID: data.frontend.oidcClientID,
      brandingName: data.frontend.brandingName,
      uiFlavour: data.frontend.uiFlavour,
    };
  }
  logError("ConfigService", "Config missing OIDC fields", data);
  console.error("[ConfigService] Config missing required OIDC fields", data);
  return { oidcAuthority: "", oidcClientID: "", brandingName: undefined, uiFlavour: undefined };
}
