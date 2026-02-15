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
          Your session will expire shortly. Click stay logged in to silently renew, or log out if you are finished.
        </p>
        <div class="warning-actions">
          <scale-button
            variant="primary"
            size="small"
            :loading="renewing"
            data-testid="stay-logged-in-button"
            @click="stayLoggedIn"
          >
            Stay logged in
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

    async function stayLoggedIn() {
      if (!auth || renewing.value) return;
      renewing.value = true;
      try {
        await auth.userManager.signinSilent();
        show.value = false;
        dismissed.value = false;
      } catch (err) {
        console.warn("[AutoLogoutWarning] Silent renew failed", err);
      } finally {
        renewing.value = false;
      }
    }

    function dismiss() {
      dismissed.value = true;
      show.value = false;
    }

    function checkExpiring() {
      const userStr = localStorage.getItem(
        "oidc.user:" + auth.userManager.settings.authority + ":" + auth.userManager.settings.client_id,
      );
      if (userStr) {
        try {
          const parsed = JSON.parse(userStr);
          if (parsed && parsed.expires_at) {
            const expiresIn = parsed.expires_at * 1000 - Date.now();
            if (expiresIn < WARNING_THRESHOLD_MS && expiresIn > 0 && !dismissed.value) {
              show.value = true;
            } else {
              show.value = false;
              if (expiresIn > WARNING_THRESHOLD_MS) {
                dismissed.value = false;
              }
            }
          }
        } catch {}
      }
    }

    onMounted(() => {
      timer = window.setInterval(checkExpiring, 5000);
    });
    onUnmounted(() => {
      if (timer) clearInterval(timer);
    });

    return { show, logout, stayLoggedIn, dismiss, renewing };
  },
};
</script>

<style scoped>
.auto-logout-warning-container {
  position: fixed;
  bottom: var(--space-lg);
  right: var(--space-lg);
  z-index: 3000;
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
  transition: all 0.3s ease;
}

.fade-slide-enter-from,
.fade-slide-leave-to {
  opacity: 0;
  transform: translateY(20px);
}
</style>
