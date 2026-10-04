import { ref } from "vue";
import type BreakglassService from "@/services/breakglass";
import type { SessionCR } from "@/model/breakglass";
import { debug, warn } from "@/services/logger";

const TAG = "usePendingRequests";

export function usePendingRequests(service: BreakglassService | null) {
  const requests = ref<SessionCR[]>([]);
  const loading = ref(true);
  const error = ref("");

  async function loadRequests() {
    if (!service) {
      error.value = "Auth not available";
      loading.value = false;
      warn(`${TAG}.loadRequests`, "Missing BreakglassService instance");
      return;
    }

    loading.value = true;
    debug(`${TAG}.loadRequests`, "Loading outstanding requests");

    try {
      const data = await service.fetchMyOutstandingRequests();
      requests.value = data;
      error.value = "";
      debug(`${TAG}.loadRequests`, "Loaded outstanding requests", { count: data.length });
    } catch (err: unknown) {
      const message = (err instanceof Error ? err.message : undefined) || "Failed to load requests";
      error.value = message;
      warn(`${TAG}.loadRequests`, "Failed to load outstanding requests", { errorMessage: message });
    } finally {
      loading.value = false;
    }
  }

  return {
    requests,
    loading,
    error,
    loadRequests,
  };
}
