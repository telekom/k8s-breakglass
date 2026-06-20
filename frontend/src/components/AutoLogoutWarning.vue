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

const TOKEN_PERSISTENCE_KEY = "breakglass_oidc_token_persistence";

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
      const sessionStorageValue = getStorageItem(getBrowserStorage("sessionStorage"), "oidc_idp_name");
      const localStorageValue = shouldReadLocalOIDCStorage()
        ? getStorageItem(getBrowserStorage("localStorage"), "breakglass_current_idp_name")
        : undefined;
      return auth.getIdentityProviderName() ?? sessionStorageValue ?? localStorageValue ?? undefined;
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

    function getBrowserStorage(name: "sessionStorage" | "localStorage"): Storage | undefined {
      if (typeof window === "undefined") {
        return undefined;
      }
      try {
        return window[name];
      } catch (err) {
        warn("AutoLogoutWarning", `Unable to access browser ${name}`, err);
        return undefined;
      }
    }

    function getStorageItem(storage: Storage | undefined, key: string): string | null {
      if (!storage) {
        return null;
      }
      try {
        return storage.getItem(key);
      } catch (err) {
        warn("AutoLogoutWarning", "Unable to read browser storage item", err);
        return null;
      }
    }

    function getStorageLength(storage: Storage): number {
      try {
        return storage.length;
      } catch (err) {
        warn("AutoLogoutWarning", "Unable to enumerate browser storage", err);
        return 0;
      }
    }

    function getStorageKey(storage: Storage, index: number): string | null {
      try {
        return storage.key(index);
      } catch (err) {
        warn("AutoLogoutWarning", "Unable to read browser storage key", err);
        return null;
      }
    }

    function shouldReadLocalOIDCStorage(): boolean {
      if (import.meta.env.PROD) {
        return false;
      }
      return getStorageItem(getBrowserStorage("localStorage"), TOKEN_PERSISTENCE_KEY) === "persistent";
    }

    function getAvailableOIDCStorages(): Storage[] {
      const storages: Storage[] = [];
      const sessionStorage = getBrowserStorage("sessionStorage");
      if (sessionStorage) storages.push(sessionStorage);
      if (shouldReadLocalOIDCStorage()) {
        const localStorage = getBrowserStorage("localStorage");
        if (localStorage) storages.push(localStorage);
      }
      return storages;
    }

    function getTrustedOIDCUserKeyPrefixes(): string[] {
      const prefixes = new Set<string>();
      const configuredAuthority = auth.userManager.settings.authority;
      if (configuredAuthority) {
        prefixes.add(`oidc.user:${configuredAuthority}:`);
      }
      prefixes.add("oidc.user:/api/oidc/authority:");
      return Array.from(prefixes);
    }

    function isTrustedOIDCUserKey(key: string, trustedPrefixes: readonly string[]): boolean {
      return trustedPrefixes.some((prefix) => key.startsWith(prefix));
    }

    function getStoredOIDCUserValues(): string[] {
      const defaultStorageKey =
        "oidc.user:" + auth.userManager.settings.authority + ":" + auth.userManager.settings.client_id;
      const trustedPrefixes = getTrustedOIDCUserKeyPrefixes();
      const values: string[] = [];
      const seenValues = new Set<string>();

      for (const storage of getAvailableOIDCStorages()) {
        const keys = new Set<string>([defaultStorageKey]);
        for (let index = 0; index < getStorageLength(storage); index += 1) {
          const key = getStorageKey(storage, index);
          if (key && isTrustedOIDCUserKey(key, trustedPrefixes)) {
            keys.add(key);
          }
        }

        for (const key of keys) {
          const value = getStorageItem(storage, key);
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
