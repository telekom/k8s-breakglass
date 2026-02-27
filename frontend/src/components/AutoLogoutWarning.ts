import { inject, onMounted, onUnmounted, ref } from "vue";
import AuthService from "@/services/auth";
import { AuthKey } from "@/keys";

const show = ref(false);
let timer: number | null = null;

export default {
  name: "AutoLogoutWarning",
  setup() {
    const auth = inject(AuthKey) as AuthService;

    function logout() {
      auth?.logout();
    }

    function checkExpiring() {
      const userStr = localStorage.getItem(
        "oidc.user:" + auth?.userManager.settings.authority + ":" + auth?.userManager.settings.client_id,
      );
      if (userStr) {
        try {
          const parsed = JSON.parse(userStr);
          if (parsed && parsed.expires_at) {
            const expiresIn = parsed.expires_at * 1000 - Date.now();
            show.value = expiresIn < 60000 && expiresIn > 0;
          }
        } catch {
          // JSON.parse of OIDC user string failed — token may be corrupted
        }
      }
    }

    onMounted(() => {
      timer = window.setInterval(checkExpiring, 5000);
    });
    onUnmounted(() => {
      if (timer) clearInterval(timer);
    });

    return { show, logout };
  },
};
