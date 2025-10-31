import { createApp } from "vue";
import { createPinia } from "pinia";

import App from "@/App.vue";
// Conditionally import Scale components depending on flavour (default: oss)
const flavour = (import.meta as any).env?.VITE_UI_FLAVOUR || "oss";
// Favicon swap: default neutral favicon; use branded icon for telekom flavour if present
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
} catch (e) {
  // eslint-disable-next-line no-console
  console.warn("[favicon] swap failed", e);
}
// Expose flavour for e2e/UI tests & theming hooks
try {
  (window as any).__BREAKGLASS_UI_FLAVOUR = flavour;
  document.documentElement.setAttribute('data-ui-flavour', flavour);
} catch (e) {
  // eslint-disable-next-line no-console
  console.warn('[ui-flavour] expose failed', e);
}
if (flavour === "oss" || flavour === "neutral" || flavour === "default") {
  // Use neutral variant. Stylesheet imports are side-effect only; types not provided.
  // @ts-expect-error stylesheet side-effect import
  import("@telekom/scale-components-neutral/dist/scale-components/scale-components.css");
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore loader lacks types in neutral package version
  import("@telekom/scale-components-neutral/loader").then(({ applyPolyfills, defineCustomElements }) => {
    applyPolyfills().then(() => defineCustomElements(window));
  });
} else {
  // Default Telekom-branded components
  // @ts-expect-error stylesheet side-effect import
  import("@telekom/scale-components/dist/scale-components/scale-components.css");
  import("@telekom/scale-components/loader").then(({ applyPolyfills, defineCustomElements }) => {
    applyPolyfills().then(() => defineCustomElements(window));
  });
}
import router from "@/router";
import AuthService, { AuthRedirect, type State } from "@/services/auth";
import { AuthKey } from "@/keys";
import getConfig from "@/services/config";
import { BrandingKey } from "@/keys";

const app = createApp(App);

app.use(createPinia());
app.use(router);

getConfig().then((config) => {
  const auth = new AuthService(config);
  app.provide(AuthKey, auth);
  // Provide optional branding name for the UI. Fallbacks will be used by components
  // if branding is not provided by the backend.
  app.provide(BrandingKey, config.brandingName);
  // If backend provided a branding name, set the document title as a convenience.
  if (config.brandingName) {
    document.title = config.brandingName;
  }

  // Handle OIDC login callback
  router.isReady().then(() => {
    if (router.currentRoute.value.path === AuthRedirect) {
      auth.userManager
        .signinCallback()
        .then((user) => {
          if (user && user.state) {
            const state = user.state as State;
            if (state.path) {
              router.replace(state.path);
              return;
            }
          }
          router.replace("/");
        })
        .catch(function (error) {
          // Log and surface a friendly message
          // eslint-disable-next-line no-console
          console.error('[AuthCallback]', error);
        });
    }
  });
  app.mount("#app");
});
