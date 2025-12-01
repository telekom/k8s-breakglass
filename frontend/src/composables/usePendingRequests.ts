import { ref } from "vue";
import type BreakglassService from "@/services/breakglass";
import type { SessionCR } from "@/model/breakglass";
import { debug, warn } from "@/services/logger";

const TAG = "usePendingRequests";

export function usePendingRequests(service: BreakglassService | null) {
  const requests = ref<SessionCR[]>([]);
  const loading = ref(true);
  const error = ref("");
  const withdrawing = ref("");

  async function loadRequests() {
    if (!service) {
      error.value = "Auth not available";
      loading.value = false;
      warn(`${TAG}.loadRequests`, "Missing BreakglassService instance");
      return;
    }

    loading.value = true;
    debug(`${TAG}.loadRequests`, "Loading pending requests");

    try {
      const data = await service.fetchMyOutstandingRequests();
      requests.value = data;
      error.value = "";
      debug(`${TAG}.loadRequests`, "Loaded pending requests", { count: data.length });
    } catch (err: any) {
      const message = err?.message || "Failed to load requests";
      error.value = message;
      warn(`${TAG}.loadRequests`, "Failed to load pending requests", { errorMessage: message });
    } finally {
      loading.value = false;
    }
  }

  async function withdrawRequest(req: SessionCR) {
    if (!service) {
      warn(`${TAG}.withdrawRequest`, "Missing BreakglassService instance");
      return;
    }

    const sessionName = req.metadata?.name || req.name || "";
    withdrawing.value = sessionName;
    debug(`${TAG}.withdrawRequest`, "Attempting withdraw", { sessionName });

    try {
      await service.withdrawMyRequest(req);
      requests.value = requests.value.filter((existing) => existing.metadata?.name !== sessionName);
      error.value = "";
      debug(`${TAG}.withdrawRequest`, "Withdraw complete", { sessionName });
    } catch (err: any) {
      const message = err?.message || "Failed to withdraw request";
      error.value = message;
      warn(`${TAG}.withdrawRequest`, "Withdraw failed", { sessionName, errorMessage: message });
    } finally {
      withdrawing.value = "";
    }
  }

  return {
    requests,
    loading,
    error,
    withdrawing,
    loadRequests,
    withdrawRequest,
  };
}
