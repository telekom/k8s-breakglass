import { createApp } from "vue";
import { createPinia } from "pinia";

import App from "@/App.vue";
import router from "@/router";
import AuthService, { AuthRedirect, AuthSilentRedirect, type State } from "@/services/auth";
import { AuthKey } from "@/keys";
import getConfig from "@/services/config";
import { BrandingKey } from "@/keys";
import type Config from "@/model/config";
import { exposeDebugControls, debug } from "@/services/logger";
import logger from "@/services/logger-console";
import { pushError } from "@/services/toast";

const CONFIG_CACHE_KEY = "breakglass_runtime_config";
const explicitMockFlag = import.meta.env.VITE_USE_MOCK_AUTH;
const USE_MOCK_AUTH =
  explicitMockFlag === "false" ? false : explicitMockFlag === "true" ? true : import.meta.env.DEV === true;

// Log application startup
logger.info("App", "Application starting", {
  mode: import.meta.env.MODE,
  dev: import.meta.env.DEV,
  useMockAuth: USE_MOCK_AUTH,
  baseUrl: import.meta.env.BASE_URL,
});

exposeDebugControls();

function cacheRuntimeConfig(config: Config) {
  try {
    sessionStorage.setItem(CONFIG_CACHE_KEY, JSON.stringify(config));
  } catch (error) {
    console.warn("[ConfigCache] Failed to persist runtime config", error);
  }
}

function readCachedRuntimeConfig(): Config | null {
  try {
    const cached = sessionStorage.getItem(CONFIG_CACHE_KEY);
    if (cached) {
      return JSON.parse(cached) as Config;
    }
  } catch (error) {
    console.warn("[ConfigCache] Failed to read runtime config cache", error);
  }
  return null;
}

/**
 * Initialize flavour-dependent UI components and bootstrap the application.
 * The flavour is fetched from the backend config (/api/config), allowing runtime
 * configuration without requiring a rebuild.
 */
async function initializeApp() {
  // Fetch configuration from backend, which includes runtime-configurable UI flavour
  debug("App.init", "Fetching runtime config");
  logger.info("App", "Fetching runtime config from backend");

  const config = await getConfig();
  cacheRuntimeConfig(config);

  // Determine flavour from backend config or fall back to default
  const rawFlavour = config.uiFlavour || "oss";
  // Backward compatibility: treat legacy "default" as neutral/oss.
  const flavour = rawFlavour === "default" ? "oss" : rawFlavour;
  logger.info("App", "UI flavour determined", { flavour });

  // Configure favicon based on flavour
  try {
    const fav = document.getElementById("app-favicon") as HTMLLinkElement | null;
    if (fav) {
      if (flavour === "telekom") {
        fav.type = "image/x-icon";
        fav.href = "/favicon.ico"; // legacy branded icon
      } else {
        fav.type = "image/svg+xml";
        fav.href = "/favicon-oss.svg";
      }
    } else {
      // create if missing
      const link = document.createElement("link");
      link.id = "app-favicon";
      link.rel = "icon";
      if (flavour === "telekom") {
        link.type = "image/x-icon";
        link.href = "/favicon.ico";
      } else {
        link.type = "image/svg+xml";
        link.href = "/favicon-oss.svg";
      }
      document.head.appendChild(link);
    }
    // Preload the favicon to avoid unnecessary requests
    const faviconLink = document.getElementById("app-favicon") as HTMLLinkElement;
    if (faviconLink && faviconLink.href && !faviconLink.href.endsWith("/")) {
      // Ensure href doesn't have trailing slash
      faviconLink.href = faviconLink.href.replace(/\/$/, "");
    }
  } catch (e) {
    console.warn("[favicon] swap failed", e);
  }

  // Expose flavour for e2e/UI tests & theming hooks
  try {
    (window as any).__BREAKGLASS_UI_FLAVOUR = flavour;
    document.documentElement.setAttribute("data-ui-flavour", flavour);
  } catch (e) {
    console.warn("[ui-flavour] expose failed", e);
  }

  // Load appropriate Scale components based on runtime flavour
  debug("App.init", "Applying Scale components for flavour", { flavour });
  if (flavour === "oss" || flavour === "neutral") {
    // Use neutral variant. Stylesheet imports are side-effect only; types not provided.
    await import("@telekom/scale-components-neutral/dist/scale-components/scale-components.css");
    // eslint-disable-next-line @typescript-eslint/ban-ts-comment
    // @ts-ignore loader lacks types in neutral package version
    const { applyPolyfills, defineCustomElements } = await import("@telekom/scale-components-neutral/loader");
    await applyPolyfills();
    await defineCustomElements(window);
  } else {
    // Default Telekom-branded components
    await import("@telekom/scale-components/dist/scale-components/scale-components.css");
    const { applyPolyfills, defineCustomElements } = await import("@telekom/scale-components/loader");
    await applyPolyfills();
    await defineCustomElements(window);
  }

  // Initialize Vue app
  logger.info("App", "Initializing Vue application");
  const app = createApp(App);

  app.use(createPinia());
  app.use(router);

  // Global Vue error handler — catches uncaught errors in components, lifecycle hooks, and watchers
  app.config.errorHandler = (err, instance, info) => {
    const componentName = instance?.$options?.name || instance?.$options?.__name || "Unknown";
    logger.error("Vue", `Uncaught error in ${componentName} (${info})`, err);
    pushError("An unexpected error occurred. Please try again.");
  };

  // Catch unhandled promise rejections outside Vue's scope.
  // This listener is intentionally never removed — it lives for the entire
  // application lifetime and there is no teardown path for the root app.
  window.addEventListener("unhandledrejection", (event) => {
    event.preventDefault();
    logger.error("App", "Unhandled promise rejection", event.reason);
  });

  const auth = new AuthService(config, { mock: USE_MOCK_AUTH });
  if (USE_MOCK_AUTH) {
    console.info("[AuthService] Mock authentication enabled (dev default)");
    logger.info("App", "Mock authentication enabled");
    // Expose auth service and router for Playwright/E2E testing
    (window as any).__BREAKGLASS_AUTH = auth;
    (window as any).__VUE_ROUTER__ = router;
  }
  app.provide(AuthKey, auth);
  // Provide optional branding name for the UI. Fallbacks will be used by components
  // if branding is not provided by the backend.
  app.provide(BrandingKey, config.brandingName);
  // If backend provided a branding name, set the document title as a convenience.
  if (config.brandingName) {
    document.title = config.brandingName;
    logger.info("App", "Branding applied", { brandingName: config.brandingName });
  }

  // Handle OIDC login callback
  await router.isReady();
  logger.debug("App", "Router ready", { currentPath: router.currentRoute.value.path });

  if (router.currentRoute.value.path === AuthRedirect) {
    try {
      debug("Auth.callback", "Processing signin callback");
      logger.info("App", "Processing OIDC signin callback");
      const user = await auth.handleSigninCallback();
      if (user && user.state) {
        const state = user.state as State;
        if (state.path) {
          logger.info("App", "Redirecting to original path", { path: state.path });
          router.replace(state.path);
        } else {
          logger.info("App", "Redirecting to home");
          router.replace("/");
        }
      } else {
        router.replace("/");
      }
    } catch (error) {
      // Log and surface a friendly message
      logger.error("App", "OIDC signin callback failed", error);
      console.error("[AuthCallback]", error);
    }
  } else {
    // Wait for initial auth state to be loaded before mounting
    // This prevents a race condition where the app renders with authenticated=false
    // before the stored user session is loaded from storage
    logger.debug("App", "Waiting for auth initialization");
    await auth.ready;
    logger.debug("App", "Auth initialization complete");
  }

  logger.info("App", "Mounting Vue application");
  app.mount("#app");
}

async function initializeSilentRenew() {
  logger.info("SilentRenew", "Initializing silent renew callback");

  if (USE_MOCK_AUTH) {
    console.info("[SilentRenew] Mock auth enabled, skipping silent renew callback");
    logger.info("SilentRenew", "Skipping silent renew - mock auth enabled");
    return;
  }
  const cachedConfig = readCachedRuntimeConfig();
  const config = cachedConfig || (await getConfig());
  if (!cachedConfig) {
    cacheRuntimeConfig(config);
  }
  const auth = new AuthService(config);
  try {
    await auth.userManager.signinSilentCallback();
    logger.info("SilentRenew", "Silent renew callback completed successfully");
  } catch (error) {
    logger.error("SilentRenew", "Silent renew callback failed", error);
    console.error("[SilentRenew]", error);
  }
}

const isSilentRenew = window.location.pathname === AuthSilentRedirect;
logger.info("App", "Bootstrap check", {
  isSilentRenew,
  pathname: window.location.pathname,
});

if (isSilentRenew) {
  initializeSilentRenew().catch((error) => {
    logger.error("SilentRenew", "Initialization error", error);
    console.error("[SilentRenewInit]", error);
  });
} else {
  // Bootstrap the application
  initializeApp().catch((error) => {
    logger.error("App", "Application initialization failed", error);
    console.error("[AppInitialization]", error);
    // Show error message to user if initialization fails
    const app = document.getElementById("app");
    if (app) {
      app.innerHTML =
        '<div style="padding: 20px; color: red; font-family: monospace;">Failed to initialize application. Please check the console for details.</div>';
    }
  });
}
