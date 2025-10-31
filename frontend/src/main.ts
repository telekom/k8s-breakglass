import { createApp } from "vue";
import { createPinia } from "pinia";

import App from "@/App.vue";
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
