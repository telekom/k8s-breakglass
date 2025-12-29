/**
 * Composable for session action management (approve, reject, withdraw, drop, cancel)
 */

import { ref, reactive } from "vue";
import type { SessionCR } from "@/model/breakglass";
import { pushError, pushSuccess } from "@/services/toast";
import { debug, warn } from "@/services/logger";
import { getSessionKey, getSessionUser, getSessionGroup, getSessionState, normalizeState } from "./useSessionList";

const TAG = "useSessionActions";

export type SessionActionType = "approve" | "reject" | "withdraw" | "drop" | "cancel";

export interface SessionActionConfig {
  /** Display label for the action */
  label: string;
  /** Button variant */
  variant: "primary" | "secondary" | "danger";
  /** Loading label */
  loadingLabel: string;
  /** Success message template (use {user} and {group} placeholders) */
  successMessage: string;
  /** Error message template */
  errorMessage: string;
  /** Confirmation message (if requires confirmation) */
  confirmMessage?: string;
}

const ACTION_CONFIGS: Record<SessionActionType, SessionActionConfig> = {
  approve: {
    label: "Approve",
    variant: "primary",
    loadingLabel: "Approving...",
    successMessage: "Approved request for {user} ({group})",
    errorMessage: "Failed to approve request",
  },
  reject: {
    label: "Reject",
    variant: "danger",
    loadingLabel: "Rejecting...",
    successMessage: "Rejected request for {user} ({group})",
    errorMessage: "Failed to reject request",
    confirmMessage: "Reject request for {user} ({group})?",
  },
  withdraw: {
    label: "Withdraw",
    variant: "secondary",
    loadingLabel: "Withdrawing...",
    successMessage: "Withdrew request {name}",
    errorMessage: "Failed to withdraw request",
    confirmMessage: "Withdraw this request? This action cannot be undone.",
  },
  drop: {
    label: "Drop",
    variant: "secondary",
    loadingLabel: "Dropping...",
    successMessage: "Dropped session {name}",
    errorMessage: "Failed to drop session",
    confirmMessage: "Drop active session {name}?",
  },
  cancel: {
    label: "Cancel",
    variant: "danger",
    loadingLabel: "Cancelling...",
    successMessage: "Cancelled session {name}",
    errorMessage: "Failed to cancel session",
    confirmMessage: "Cancel session {name}?",
  },
};

export interface ActionHandlers {
  approve?: (session: SessionCR, note?: string) => Promise<void>;
  reject?: (session: SessionCR, note?: string) => Promise<void>;
  withdraw?: (session: SessionCR) => Promise<void>;
  drop?: (session: SessionCR) => Promise<void>;
  cancel?: (session: SessionCR) => Promise<void>;
}

export interface ActionPermissions {
  canApprove?: (session: SessionCR) => boolean;
  canReject?: (session: SessionCR) => boolean;
  canWithdraw?: (session: SessionCR) => boolean;
  canDrop?: (session: SessionCR) => boolean;
  canCancel?: (session: SessionCR) => boolean;
}

/**
 * Check if session is in pending state
 */
export function isPending(session: SessionCR): boolean {
  return normalizeState(getSessionState(session)) === "pending";
}

/**
 * Check if session is active (approved/active)
 */
export function isActive(session: SessionCR): boolean {
  const state = normalizeState(getSessionState(session));
  return state === "approved" || state === "active";
}

/**
 * Check if session is waiting for scheduled time
 */
export function isScheduled(session: SessionCR): boolean {
  const state = normalizeState(getSessionState(session));
  return state === "waitingforscheduledtime" || state === "scheduled";
}

/**
 * Format action message with session details
 */
function formatMessage(template: string, session: SessionCR): string {
  return template
    .replace("{user}", getSessionUser(session))
    .replace("{group}", getSessionGroup(session))
    .replace("{name}", getSessionKey(session))
    .replace("{cluster}", session.spec?.cluster || "unknown");
}

/**
 * Main composable for session actions
 */
export function useSessionActions(handlers: ActionHandlers, permissions?: ActionPermissions) {
  // Track which sessions have which action running
  const busyActions = reactive<Record<string, SessionActionType | undefined>>({});
  const notes = reactive<Record<string, string>>({});
  const lastError = ref<string>("");

  // Check if any action is running for a session
  function isSessionBusy(session: SessionCR): boolean {
    const key = getSessionKey(session);
    return !!busyActions[key];
  }

  // Check if specific action is running
  function isActionRunning(session: SessionCR, action: SessionActionType): boolean {
    const key = getSessionKey(session);
    return busyActions[key] === action;
  }

  // Get the currently running action for a session
  function getRunningAction(session: SessionCR): SessionActionType | undefined {
    return busyActions[getSessionKey(session)];
  }

  // Set/clear busy state
  function setBusy(session: SessionCR, action?: SessionActionType) {
    const key = getSessionKey(session);
    if (action) {
      busyActions[key] = action;
    } else {
      delete busyActions[key];
    }
  }

  // Get/set note for a session
  function getNote(session: SessionCR): string {
    return notes[getSessionKey(session)] || "";
  }

  function setNote(session: SessionCR, note: string) {
    notes[getSessionKey(session)] = note;
  }

  function clearNote(session: SessionCR) {
    delete notes[getSessionKey(session)];
  }

  // Permission checks with defaults
  function canPerformAction(session: SessionCR, action: SessionActionType): boolean {
    if (isSessionBusy(session)) return false;

    switch (action) {
      case "approve":
        return permissions?.canApprove?.(session) ?? isPending(session);
      case "reject":
        return permissions?.canReject?.(session) ?? isPending(session);
      case "withdraw":
        return permissions?.canWithdraw?.(session) ?? isPending(session);
      case "drop":
        return permissions?.canDrop?.(session) ?? isActive(session);
      case "cancel":
        return permissions?.canCancel?.(session) ?? isActive(session);
      default:
        return false;
    }
  }

  // Get available actions for a session
  function getAvailableActions(session: SessionCR): SessionActionType[] {
    const actions: SessionActionType[] = [];
    const allActions: SessionActionType[] = ["approve", "reject", "withdraw", "drop", "cancel"];

    for (const action of allActions) {
      if (handlers[action] && canPerformAction(session, action)) {
        actions.push(action);
      }
    }

    return actions;
  }

  // Get action configuration
  function getActionConfig(action: SessionActionType): SessionActionConfig {
    return ACTION_CONFIGS[action];
  }

  // Get button label (respects loading state)
  function getActionLabel(session: SessionCR, action: SessionActionType): string {
    const config = ACTION_CONFIGS[action];
    return isActionRunning(session, action) ? config.loadingLabel : config.label;
  }

  // Execute an action with error handling
  async function executeAction(
    session: SessionCR,
    action: SessionActionType,
    options: { skipConfirm?: boolean; onSuccess?: () => void; onError?: (error: string) => void } = {},
  ): Promise<boolean> {
    const handler = handlers[action];
    if (!handler) {
      warn(`${TAG}.executeAction`, `No handler for action: ${action}`);
      return false;
    }

    if (!canPerformAction(session, action)) {
      debug(`${TAG}.executeAction`, `Cannot perform action: ${action}`, { session: getSessionKey(session) });
      return false;
    }

    const config = ACTION_CONFIGS[action];

    // Confirmation if needed
    if (config.confirmMessage && !options.skipConfirm) {
      const message = formatMessage(config.confirmMessage, session);
      if (typeof window !== "undefined" && !window.confirm(message)) {
        return false;
      }
    }

    setBusy(session, action);
    lastError.value = "";

    try {
      debug(`${TAG}.executeAction`, `Executing action: ${action}`, { session: getSessionKey(session) });

      // Actions that may use notes
      if (action === "approve" || action === "reject") {
        const note = getNote(session);
        await handler(session, note || undefined);
      } else {
        await (handler as (session: SessionCR) => Promise<void>)(session);
      }

      const successMsg = formatMessage(config.successMessage, session);
      pushSuccess(successMsg);
      clearNote(session);
      options.onSuccess?.();

      debug(`${TAG}.executeAction`, `Action completed: ${action}`, { session: getSessionKey(session) });
      return true;
    } catch (err: any) {
      const errorMsg = err?.message || config.errorMessage;
      lastError.value = errorMsg;
      pushError(errorMsg);
      options.onError?.(errorMsg);

      warn(`${TAG}.executeAction`, `Action failed: ${action}`, {
        session: getSessionKey(session),
        error: errorMsg,
      });
      return false;
    } finally {
      setBusy(session);
    }
  }

  // Convenience methods for specific actions
  async function approve(session: SessionCR, options?: Parameters<typeof executeAction>[2]) {
    return executeAction(session, "approve", { ...options, skipConfirm: true });
  }

  async function reject(session: SessionCR, options?: Parameters<typeof executeAction>[2]) {
    return executeAction(session, "reject", options);
  }

  async function withdraw(session: SessionCR, options?: Parameters<typeof executeAction>[2]) {
    return executeAction(session, "withdraw", options);
  }

  async function drop(session: SessionCR, options?: Parameters<typeof executeAction>[2]) {
    return executeAction(session, "drop", options);
  }

  async function cancel(session: SessionCR, options?: Parameters<typeof executeAction>[2]) {
    return executeAction(session, "cancel", options);
  }

  return {
    // State
    busyActions,
    notes,
    lastError,

    // Checks
    isSessionBusy,
    isActionRunning,
    getRunningAction,
    canPerformAction,
    getAvailableActions,

    // Configuration
    getActionConfig,
    getActionLabel,

    // Notes
    getNote,
    setNote,
    clearNote,

    // Actions
    executeAction,
    approve,
    reject,
    withdraw,
    drop,
    cancel,
  };
}
