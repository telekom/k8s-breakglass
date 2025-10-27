<template>
  <div v-if="show" class="auto-logout-warning">
    <div class="warning-content">
      <h2>Session Expiring Soon</h2>
      <p>Your session will expire in less than a minute. Please interact with the app to stay logged in, or <button @click="logout">Log out now</button>.</p>
    </div>
  </div>
</template>

<script lang="ts">
import { inject, onMounted, onUnmounted, ref } from 'vue';
import AuthService from '@/services/auth';
import { AuthKey } from '@/keys';

export default {
  name: 'AutoLogoutWarning',
  setup() {
    const show = ref(false);
    let timer: number | null = null;
    const auth = inject(AuthKey) as AuthService;

    function logout() {
      auth?.logout();
    }

    function checkExpiring() {
      const userStr = localStorage.getItem('oidc.user:' + auth?.userManager.settings.authority + ':' + auth?.userManager.settings.client_id);
      if (userStr) {
        try {
          const parsed = JSON.parse(userStr);
          if (parsed && parsed.expires_at) {
            const expiresIn = parsed.expires_at * 1000 - Date.now();
            show.value = expiresIn < 60000 && expiresIn > 0;
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

    return { show, logout };
  }
};
</script>

<style scoped>
.auto-logout-warning {
  position: fixed;
  top: 0;
  left: 0;
  width: 100vw;
  height: 100vh;
  background: rgba(0,0,0,0.4);
  display: flex;
  align-items: center;
  justify-content: center;
  z-index: 9999;
}
.warning-content {
  background: #fffbe6;
  border: 2px solid #ffb300;
  border-radius: 10px;
  padding: 2rem 2.5rem;
  box-shadow: 0 2px 16px rgba(0,0,0,0.12);
  text-align: center;
  color: #222; /* ensure readable text on all themes */
}
.warning-content h2 {
  color: #d9006c;
  margin-bottom: 1rem;
}
.warning-content button {
  background: #d9006c;
  color: #fff;
  border: none;
  border-radius: 5px;
  padding: 0.5em 1.2em;
  font-weight: 600;
  cursor: pointer;
  margin-left: 0.5em;
}
.warning-content button:hover {
  background: #b8005a;
}
</style>