import { createApp } from "vue";
import { createPinia } from "pinia";

import App from "@/App.vue";
import router from "@/router";
import AuthService, { AuthRedirect, AuthSilentRedirect, type State } from "@/services/auth";
import { AuthKey } from "@/keys";
import getConfig from "@/services/config";
import { BrandingKey } from "@/keys";
import type Config from "@/model/config";

const CONFIG_CACHE_KEY = "breakglass_runtime_config";
const explicitMockFlag = import.meta.env.VITE_USE_MOCK_AUTH;
const USE_MOCK_AUTH = typeof explicitMockFlag === "string" ? explicitMockFlag === "true" : import.meta.env.DEV === true;

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
  const config = await getConfig();
  cacheRuntimeConfig(config);

  // Determine flavour from backend config or fall back to default
  const flavour = config.uiFlavour || "oss";

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
  if (flavour === "oss" || flavour === "neutral" || flavour === "default") {
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
  const app = createApp(App);

  app.use(createPinia());
  app.use(router);

  const auth = new AuthService(config, { mock: USE_MOCK_AUTH });
  if (USE_MOCK_AUTH) {
    console.info("[AuthService] Mock authentication enabled (dev default)");
  }
  app.provide(AuthKey, auth);
  // Provide optional branding name for the UI. Fallbacks will be used by components
  // if branding is not provided by the backend.
  app.provide(BrandingKey, config.brandingName);
  // If backend provided a branding name, set the document title as a convenience.
  if (config.brandingName) {
    document.title = config.brandingName;
  }

  // Handle OIDC login callback
  await router.isReady();
  if (router.currentRoute.value.path === AuthRedirect) {
    try {
      const user = await auth.handleSigninCallback();
      if (user && user.state) {
        const state = user.state as State;
        if (state.path) {
          router.replace(state.path);
        } else {
          router.replace("/");
        }
      } else {
        router.replace("/");
      }
    } catch (error) {
      // Log and surface a friendly message

      console.error("[AuthCallback]", error);
    }
  }

  app.mount("#app");
}

async function initializeSilentRenew() {
  if (USE_MOCK_AUTH) {
    console.info("[SilentRenew] Mock auth enabled, skipping silent renew callback");
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
  } catch (error) {
    console.error("[SilentRenew]", error);
  }
}

const isSilentRenew = window.location.pathname === AuthSilentRedirect;

if (isSilentRenew) {
  initializeSilentRenew().catch((error) => {
    console.error("[SilentRenewInit]", error);
  });
} else {
  // Bootstrap the application
  initializeApp().catch((error) => {
    console.error("[AppInitialization]", error);
    // Show error message to user if initialization fails
    const app = document.getElementById("app");
    if (app) {
      app.innerHTML =
        '<div style="padding: 20px; color: red; font-family: monospace;">Failed to initialize application. Please check the console for details.</div>';
    }
  });
}
