/**
 * Tests for useSessionActions composable
 */

import { vi } from "vitest";
import { useSessionActions, isPending, isActive, isScheduled } from "@/composables/useSessionActions";
import type { SessionCR } from "@/model/breakglass";

// Mock toast service
vi.mock("@/services/toast", () => ({
  pushError: vi.fn(),
  pushSuccess: vi.fn(),
}));

// Mock logger
vi.mock("@/services/logger", () => ({
  debug: vi.fn(),
  warn: vi.fn(),
}));

import { pushError, pushSuccess } from "@/services/toast";

describe("useSessionActions", () => {
  function createSession(state = "Pending"): SessionCR {
    return {
      metadata: { name: "session-1" },
      spec: { grantedGroup: "ops", cluster: "prod", user: "alice@example.com" },
      status: { state },
    };
  }

  beforeEach(() => {
    vi.clearAllMocks();
    // Mock window.confirm
    window.confirm = vi.fn(() => true);
  });

  describe("isPending", () => {
    it("returns true for pending sessions", () => {
      expect(isPending(createSession("Pending"))).toBe(true);
      expect(isPending(createSession("pending"))).toBe(true);
    });

    it("returns false for non-pending sessions", () => {
      expect(isPending(createSession("Approved"))).toBe(false);
      expect(isPending(createSession("Rejected"))).toBe(false);
    });
  });

  describe("isActive", () => {
    it("returns true for approved/active sessions", () => {
      expect(isActive(createSession("Approved"))).toBe(true);
      expect(isActive(createSession("Active"))).toBe(true);
    });

    it("returns false for non-active sessions", () => {
      expect(isActive(createSession("Pending"))).toBe(false);
      expect(isActive(createSession("Rejected"))).toBe(false);
    });
  });

  describe("isScheduled", () => {
    it("returns true for scheduled sessions", () => {
      expect(isScheduled(createSession("WaitingForScheduledTime"))).toBe(true);
      expect(isScheduled(createSession("Scheduled"))).toBe(true);
    });

    it("returns false for non-scheduled sessions", () => {
      expect(isScheduled(createSession("Pending"))).toBe(false);
    });
  });

  describe("useSessionActions", () => {
    it("tracks busy state during action", async () => {
      const mockApprove = vi.fn().mockResolvedValue(undefined);
      const { approve, isSessionBusy, isActionRunning } = useSessionActions({
        approve: mockApprove,
      });

      const session = createSession();
      expect(isSessionBusy(session)).toBe(false);

      const promise = approve(session);

      // During execution
      expect(isSessionBusy(session)).toBe(true);
      expect(isActionRunning(session, "approve")).toBe(true);

      await promise;

      // After completion
      expect(isSessionBusy(session)).toBe(false);
      expect(isActionRunning(session, "approve")).toBe(false);
    });

    it("calls handler and shows success message", async () => {
      const mockApprove = vi.fn().mockResolvedValue(undefined);
      const { approve } = useSessionActions({ approve: mockApprove });

      const session = createSession();
      const result = await approve(session);

      expect(result).toBe(true);
      expect(mockApprove).toHaveBeenCalledWith(session, undefined);
      expect(pushSuccess).toHaveBeenCalled();
    });

    it("handles errors and shows error message", async () => {
      const mockApprove = vi.fn().mockRejectedValue(new Error("Network error"));
      const { approve, lastError } = useSessionActions({ approve: mockApprove });

      const session = createSession();
      const result = await approve(session);

      expect(result).toBe(false);
      expect(lastError.value).toBe("Network error");
      expect(pushError).toHaveBeenCalledWith("Network error");
    });

    it("respects confirmation for destructive actions", async () => {
      const mockReject = vi.fn().mockResolvedValue(undefined);
      const { reject } = useSessionActions({ reject: mockReject });

      // User cancels
      (window.confirm as ReturnType<typeof vi.fn>).mockReturnValueOnce(false);

      const session = createSession();
      const result = await reject(session);

      expect(result).toBe(false);
      expect(mockReject).not.toHaveBeenCalled();
    });

    it("skips confirmation when specified", async () => {
      const mockReject = vi.fn().mockResolvedValue(undefined);
      const { reject } = useSessionActions({ reject: mockReject });

      const session = createSession();
      await reject(session, { skipConfirm: true });

      expect(window.confirm).not.toHaveBeenCalled();
      expect(mockReject).toHaveBeenCalled();
    });

    it("passes notes for approve/reject actions", async () => {
      const mockApprove = vi.fn().mockResolvedValue(undefined);
      const { approve, setNote } = useSessionActions({ approve: mockApprove });

      const session = createSession();
      setNote(session, "LGTM - emergency fix");
      await approve(session);

      expect(mockApprove).toHaveBeenCalledWith(session, "LGTM - emergency fix");
    });

    it("clears note after successful action", async () => {
      const mockApprove = vi.fn().mockResolvedValue(undefined);
      const { approve, setNote, getNote } = useSessionActions({ approve: mockApprove });

      const session = createSession();
      setNote(session, "Test note");
      expect(getNote(session)).toBe("Test note");

      await approve(session);

      expect(getNote(session)).toBe("");
    });

    it("gets available actions for a session", () => {
      const mockWithdraw = vi.fn();
      const mockDrop = vi.fn();

      const { getAvailableActions } = useSessionActions(
        { withdraw: mockWithdraw, drop: mockDrop },
        {
          canWithdraw: (s) => isPending(s),
          canDrop: (s) => isActive(s),
        },
      );

      const pendingSession = createSession("Pending");
      expect(getAvailableActions(pendingSession)).toContain("withdraw");
      expect(getAvailableActions(pendingSession)).not.toContain("drop");

      const activeSession = createSession("Approved");
      expect(getAvailableActions(activeSession)).toContain("drop");
      expect(getAvailableActions(activeSession)).not.toContain("withdraw");
    });

    it("prevents action when session is busy", async () => {
      let resolveApprove: () => void;
      const mockApprove = vi.fn(
        () =>
          new Promise<void>((resolve) => {
            resolveApprove = resolve;
          }),
      );
      const { approve, canPerformAction } = useSessionActions({ approve: mockApprove });

      const session = createSession();

      // Start first action
      const promise1 = approve(session);

      // Try second action - should be blocked
      expect(canPerformAction(session, "approve")).toBe(false);
      const result2 = await approve(session);
      expect(result2).toBe(false);

      // Complete first action
      resolveApprove!();
      await promise1;

      // Now should be able to act again
      expect(canPerformAction(session, "approve")).toBe(true);
    });

    it("calls onSuccess callback", async () => {
      const mockApprove = vi.fn().mockResolvedValue(undefined);
      const onSuccess = vi.fn();
      const { approve } = useSessionActions({ approve: mockApprove });

      const session = createSession();
      await approve(session, { onSuccess });

      expect(onSuccess).toHaveBeenCalled();
    });

    it("calls onError callback", async () => {
      const mockApprove = vi.fn().mockRejectedValue(new Error("Failed"));
      const onError = vi.fn();
      const { approve } = useSessionActions({ approve: mockApprove });

      const session = createSession();
      await approve(session, { onError });

      expect(onError).toHaveBeenCalledWith("Failed");
    });

    it("returns correct action label based on loading state", () => {
      const mockApprove = vi.fn(
        () => new Promise<void>(() => {}), // Never resolves
      );
      const { approve, getActionLabel } = useSessionActions({ approve: mockApprove });

      const session = createSession();

      expect(getActionLabel(session, "approve")).toBe("Approve");

      approve(session);

      expect(getActionLabel(session, "approve")).toBe("Approving...");
    });

    it("shows correct confirmation message for withdraw action", async () => {
      const mockWithdraw = vi.fn().mockResolvedValue(undefined);
      window.confirm = vi.fn(() => true);
      const { withdraw } = useSessionActions({ withdraw: mockWithdraw });

      const session = createSession();
      await withdraw(session);

      expect(window.confirm).toHaveBeenCalledWith(expect.stringContaining("Withdraw this request?"));
    });

    it("shows correct confirmation message for drop action", async () => {
      const mockDrop = vi.fn().mockResolvedValue(undefined);
      window.confirm = vi.fn(() => true);
      const { drop } = useSessionActions({ drop: mockDrop });

      const session = createSession("Approved");
      await drop(session);

      expect(window.confirm).toHaveBeenCalledWith(expect.stringContaining("Drop active session"));
    });

    it("shows correct confirmation message for cancel action", async () => {
      const mockCancel = vi.fn().mockResolvedValue(undefined);
      window.confirm = vi.fn(() => true);
      const { cancel } = useSessionActions({ cancel: mockCancel });

      // Cancel requires session to be Active
      const session = createSession("Active");
      await cancel(session);

      expect(window.confirm).toHaveBeenCalledWith(expect.stringContaining("Cancel session"));
    });

    it("withdraw returns false when user declines confirmation", async () => {
      const mockWithdraw = vi.fn().mockResolvedValue(undefined);
      window.confirm = vi.fn(() => false);
      const { withdraw } = useSessionActions({ withdraw: mockWithdraw });

      const session = createSession();
      const result = await withdraw(session);

      expect(result).toBe(false);
      expect(mockWithdraw).not.toHaveBeenCalled();
    });

    it("getRunningAction returns current action type", async () => {
      let resolveApprove: () => void;
      const mockApprove = vi.fn(
        () =>
          new Promise<void>((resolve) => {
            resolveApprove = resolve;
          }),
      );
      const { approve, getRunningAction } = useSessionActions({ approve: mockApprove });

      const session = createSession();

      expect(getRunningAction(session)).toBeUndefined();

      const promise = approve(session);
      expect(getRunningAction(session)).toBe("approve");

      resolveApprove!();
      await promise;

      expect(getRunningAction(session)).toBeUndefined();
    });

    it("getAvailableActions respects custom permissions", () => {
      const { getAvailableActions } = useSessionActions(
        {
          approve: vi.fn(),
          reject: vi.fn(),
          withdraw: vi.fn(),
        },
        {
          canApprove: () => false,
          canReject: () => true,
          canWithdraw: () => true,
        },
      );

      const session = createSession();
      const actions = getAvailableActions(session);

      expect(actions).not.toContain("approve");
      expect(actions).toContain("reject");
      expect(actions).toContain("withdraw");
    });
  });
});
