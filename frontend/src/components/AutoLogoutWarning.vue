<template>
  <transition name="fade-slide">
    <div
      v-if="show"
      class="auto-logout-warning-container"
      role="status"
      aria-live="polite"
      data-testid="auto-logout-warning"
    >
      <scale-notification
        heading="Session expiring soon"
        variant="warning"
        opened
        class="logout-notification"
        @scale-close="dismiss"
      >
        <p class="warning-copy">
          Your session will expire shortly. Re-authenticate to continue, or log out if you are finished.
        </p>
        <div class="warning-actions">
          <scale-button
            variant="primary"
            size="small"
            :loading="renewing"
            data-testid="reauthenticate-button"
            @click="reauthenticate"
          >
            Re-authenticate
          </scale-button>
          <scale-button variant="secondary" size="small" data-testid="dismiss-button" @click="dismiss"
            >Dismiss</scale-button
          >
          <scale-button variant="ghost" size="small" data-testid="logout-button" @click="logout">Log out</scale-button>
        </div>
      </scale-notification>
    </div>
  </transition>
</template>

<script lang="ts">
import { inject, onMounted, onUnmounted, ref } from "vue";
import { AuthKey } from "@/keys";
import { warn } from "@/services/logger";

export default {
  name: "AutoLogoutWarning",
  setup() {
    const show = ref(false);
    const renewing = ref(false);
    const dismissed = ref(false);
    let timer: number | null = null;
    const requireAuth = () => {
      const injectedAuth = inject(AuthKey);
      if (!injectedAuth) {
        throw new Error("AutoLogoutWarning requires an Auth provider");
      }
      return injectedAuth;
    };
    const auth = requireAuth();
    const WARNING_THRESHOLD_MS = 30000; // 30 seconds

    function logout() {
      auth.logout();
    }

    function getCurrentIdentityProviderName(): string | undefined {
      return auth.getIdentityProviderName() ?? sessionStorage.getItem("oidc_idp_name") ?? undefined;
    }

    async function reauthenticate() {
      if (!auth || renewing.value) return;
      renewing.value = true;
      try {
        const path = window.location.pathname + window.location.search + window.location.hash;
        const idpName = getCurrentIdentityProviderName();
        await auth.login(idpName ? { path, idpName } : { path });
        show.value = false;
        dismissed.value = false;
      } catch (err) {
        warn("AutoLogoutWarning", "Re-authentication failed", err);
      } finally {
        renewing.value = false;
      }
    }

    function dismiss() {
      dismissed.value = true;
      show.value = false;
    }

    function getAvailableOIDCStorages(): Storage[] {
      const storages: Storage[] = [];
      if (typeof window === "undefined") {
        return storages;
      }
      if (typeof window.sessionStorage !== "undefined") {
        storages.push(window.sessionStorage);
      }
      if (typeof window.localStorage !== "undefined") {
        storages.push(window.localStorage);
      }
      return storages;
    }

    function getStoredOIDCUserValues(): string[] {
      const defaultStorageKey =
        "oidc.user:" + auth.userManager.settings.authority + ":" + auth.userManager.settings.client_id;
      const values: string[] = [];
      const seenValues = new Set<string>();

      for (const storage of getAvailableOIDCStorages()) {
        const keys = new Set<string>([defaultStorageKey]);
        for (let index = 0; index < storage.length; index += 1) {
          const key = storage.key(index);
          if (key?.startsWith("oidc.user:")) {
            keys.add(key);
          }
        }

        for (const key of keys) {
          const value = storage.getItem(key);
          if (value && !seenValues.has(value)) {
            seenValues.add(value);
            values.push(value);
          }
        }
      }

      return values;
    }

    function checkExpiring() {
      let nearestExpiryMs: number | null = null;
      for (const userStr of getStoredOIDCUserValues()) {
        try {
          const parsed = JSON.parse(userStr) as { expires_at?: unknown } | null;
          if (parsed && typeof parsed.expires_at === "number") {
            const expiresIn = parsed.expires_at * 1000 - Date.now();
            if (expiresIn > 0 && (nearestExpiryMs === null || expiresIn < nearestExpiryMs)) {
              nearestExpiryMs = expiresIn;
            }
          }
        } catch (e) {
          warn("AutoLogoutWarning", "Failed to parse OIDC user data from browser storage", e);
        }
      }

      if (nearestExpiryMs === null) {
        show.value = false;
        return;
      }

      if (nearestExpiryMs < WARNING_THRESHOLD_MS) {
        show.value = !dismissed.value;
        return;
      }

      show.value = false;
      dismissed.value = false;
    }

    onMounted(() => {
      checkExpiring();
      timer = window.setInterval(checkExpiring, 5000);
    });
    onUnmounted(() => {
      if (timer) clearInterval(timer);
    });

    return { show, logout, reauthenticate, dismiss, renewing };
  },
};
</script>

<style scoped>
.auto-logout-warning-container {
  position: fixed;
  bottom: var(--space-lg);
  right: var(--space-lg);
  z-index: var(--z-auto-logout);
  max-width: 400px;
  width: 100%;
}

.logout-notification {
  width: 100%;
  box-shadow: var(--shadow-card);
}

.warning-copy {
  margin-bottom: var(--space-md);
}

.warning-actions {
  display: flex;
  gap: var(--space-xs);
  justify-content: flex-end;
  flex-wrap: wrap;
}

.fade-slide-enter-active,
.fade-slide-leave-active {
  transition: all var(--telekom-motion-duration-transition, 200ms) var(--telekom-motion-easing-standard);
}

.fade-slide-enter-from,
.fade-slide-leave-to {
  opacity: 0;
  transform: translateY(20px);
}
</style>
