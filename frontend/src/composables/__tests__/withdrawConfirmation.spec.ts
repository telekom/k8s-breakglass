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
