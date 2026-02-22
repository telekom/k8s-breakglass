// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { ref } from "vue";
import type { SessionCR } from "@/model/breakglass";

/**
 * Composable that encapsulates the withdraw-confirmation dialog state
 * shared by MyPendingRequests and SessionBrowser.
 *
 * @param onConfirm - Callback invoked with the target session when the
 *   user confirms the withdrawal.
 */
export function useWithdrawConfirmation(onConfirm: (session: SessionCR) => void | Promise<unknown>) {
  const withdrawDialogOpen = ref(false);
  const withdrawTarget = ref<SessionCR | null>(null);

  /** Open the confirmation dialog for the given session. */
  function requestWithdraw(session: SessionCR) {
    withdrawTarget.value = session;
    withdrawDialogOpen.value = true;
  }

  /** User confirmed — wait for callback, then clear state. */
  async function confirmWithdraw() {
    if (!withdrawTarget.value) return;
    const session = withdrawTarget.value;
    try {
      await onConfirm(session);
      withdrawDialogOpen.value = false;
      withdrawTarget.value = null;
    } catch (error) {
      // Keep dialog open so the user sees that the operation did not complete.
      throw error;
    }
  }

  /** User cancelled — just reset the dialog state. */
  function cancelWithdraw() {
    withdrawDialogOpen.value = false;
    withdrawTarget.value = null;
  }

  return {
    withdrawDialogOpen,
    withdrawTarget,
    requestWithdraw,
    confirmWithdraw,
    cancelWithdraw,
  };
}
