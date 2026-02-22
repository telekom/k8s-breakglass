// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Tests for the withdraw confirmation dialog behaviour
 * at the composable level used by the MyPendingRequests view.
 *
 * Since the dialog state is inline (ref-based) inside the views,
 * these tests validate the composable-level contract:
 * - `withdraw(session, { skipConfirm: true })` should NOT call window.confirm
 * - `withdraw(session)` (without skipConfirm) should call window.confirm
 *
 * In MyPendingRequests, the view opens a scale-modal first,
 * then calls withdraw with skipConfirm: true.
 *
 * Note: SessionBrowser currently has its own implementation that calls
 * `executeSessionAction` directly after showing the modal and is not
 * covered by this test suite.
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { useSessionActions, type ActionHandlers } from "@/composables/useSessionActions";
import { useWithdrawConfirmation } from "@/composables/useWithdrawConfirmation";
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

function makeSession(name: string): SessionCR {
  return {
    metadata: { name, creationTimestamp: new Date().toISOString() },
    spec: { user: "alice@example.com", grantedGroup: "admins", cluster: "test" },
    status: { state: "pending" },
  } as unknown as SessionCR;
}

describe("Withdraw confirmation integration", () => {
  let withdrawHandler: ReturnType<typeof vi.fn<(session: SessionCR) => Promise<void>>>;
  let handlers: ActionHandlers;
  let confirmSpy: ReturnType<typeof vi.spyOn>;

  beforeEach(() => {
    withdrawHandler = vi.fn().mockResolvedValue(undefined);
    handlers = { withdraw: withdrawHandler };
    confirmSpy = vi.spyOn(window, "confirm").mockReturnValue(true);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("calls window.confirm when skipConfirm is not set", async () => {
    const { withdraw } = useSessionActions(handlers);
    const session = makeSession("req-1");

    await withdraw(session);

    expect(confirmSpy).toHaveBeenCalledOnce();
    expect(withdrawHandler).toHaveBeenCalledWith(session);
  });

  it("does not call window.confirm when skipConfirm is true", async () => {
    const { withdraw } = useSessionActions(handlers);
    const session = makeSession("req-2");

    await withdraw(session, { skipConfirm: true });

    expect(confirmSpy).not.toHaveBeenCalled();
    expect(withdrawHandler).toHaveBeenCalledWith(session);
  });

  it("does not call handler when user cancels window.confirm", async () => {
    confirmSpy.mockReturnValue(false);
    const { withdraw } = useSessionActions(handlers);
    const session = makeSession("req-3");

    const result = await withdraw(session);

    expect(confirmSpy).toHaveBeenCalledOnce();
    expect(withdrawHandler).not.toHaveBeenCalled();
    expect(result).toBe(false);
  });

  it("withdraw with skipConfirm returns true on success", async () => {
    const { withdraw } = useSessionActions(handlers);
    const session = makeSession("req-4");

    const result = await withdraw(session, { skipConfirm: true });

    expect(result).toBe(true);
    expect(withdrawHandler).toHaveBeenCalledWith(session);
  });

  it("withdraw with skipConfirm returns false on handler error", async () => {
    withdrawHandler.mockRejectedValue(new Error("API error"));
    const { withdraw } = useSessionActions(handlers);
    const session = makeSession("req-5");

    const result = await withdraw(session, { skipConfirm: true });

    expect(result).toBe(false);
  });
});

describe("useWithdrawConfirmation", () => {
  it("opens dialog and sets target on requestWithdraw", () => {
    const onConfirm = vi.fn();
    const { withdrawDialogOpen, withdrawTarget, requestWithdraw } = useWithdrawConfirmation(onConfirm);

    const session = makeSession("req-10");
    requestWithdraw(session);

    expect(withdrawDialogOpen.value).toBe(true);
    expect(withdrawTarget.value).toBe(session);
  });

  it("clears dialog state and calls callback on confirmWithdraw", async () => {
    const onConfirm = vi.fn().mockResolvedValue(undefined);
    const { withdrawDialogOpen, withdrawTarget, requestWithdraw, confirmWithdraw } = useWithdrawConfirmation(onConfirm);

    const session = makeSession("req-11");
    requestWithdraw(session);
    await confirmWithdraw();

    expect(onConfirm).toHaveBeenCalledWith(session);
    expect(withdrawDialogOpen.value).toBe(false);
    expect(withdrawTarget.value).toBeNull();
  });

  it("keeps dialog open when onConfirm throws (race-safe)", async () => {
    const onConfirm = vi.fn().mockRejectedValue(new Error("network error"));
    const { withdrawDialogOpen, withdrawTarget, requestWithdraw, confirmWithdraw } = useWithdrawConfirmation(onConfirm);

    const session = makeSession("req-12");
    requestWithdraw(session);

    await expect(confirmWithdraw()).rejects.toThrow("network error");

    // Dialog should remain open so the user sees the operation failed
    expect(withdrawDialogOpen.value).toBe(true);
    expect(withdrawTarget.value).toBe(session);
  });

  it("resets dialog state on cancelWithdraw", () => {
    const onConfirm = vi.fn();
    const { withdrawDialogOpen, withdrawTarget, requestWithdraw, cancelWithdraw } = useWithdrawConfirmation(onConfirm);

    requestWithdraw(makeSession("req-13"));
    cancelWithdraw();

    expect(withdrawDialogOpen.value).toBe(false);
    expect(withdrawTarget.value).toBeNull();
    expect(onConfirm).not.toHaveBeenCalled();
  });

  it("does nothing when confirmWithdraw is called without a target", async () => {
    const onConfirm = vi.fn();
    const { confirmWithdraw } = useWithdrawConfirmation(onConfirm);

    await confirmWithdraw();

    expect(onConfirm).not.toHaveBeenCalled();
  });
});
