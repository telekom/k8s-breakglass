// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Unit tests for `useWithdrawConfirmation` composable.
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, vi } from "vitest";
import { useWithdrawConfirmation } from "@/composables/useWithdrawConfirmation";
import type { SessionCR } from "@/model/breakglass";

function makeSession(name: string): SessionCR {
  return {
    metadata: { name, creationTimestamp: new Date().toISOString() },
    spec: { user: "alice@example.com", grantedGroup: "admins", cluster: "test" },
    status: { state: "pending" },
  } as unknown as SessionCR;
}

describe("useWithdrawConfirmation", () => {
  it("starts with dialog closed and no target", () => {
    const { withdrawDialogOpen, withdrawTarget } = useWithdrawConfirmation(vi.fn());
    expect(withdrawDialogOpen.value).toBe(false);
    expect(withdrawTarget.value).toBeNull();
  });

  it("requestWithdraw opens dialog and sets target", () => {
    const { withdrawDialogOpen, withdrawTarget, requestWithdraw } =
      useWithdrawConfirmation(vi.fn());
    const session = makeSession("req-1");

    requestWithdraw(session);

    expect(withdrawDialogOpen.value).toBe(true);
    expect(withdrawTarget.value).toEqual(session);
  });

  it("confirmWithdraw calls onConfirm and resets state", async () => {
    const onConfirm = vi.fn();
    const { withdrawDialogOpen, withdrawTarget, requestWithdraw, confirmWithdraw } =
      useWithdrawConfirmation(onConfirm);
    const session = makeSession("req-2");

    requestWithdraw(session);
    await confirmWithdraw();

    expect(onConfirm).toHaveBeenCalledWith(session);
    expect(withdrawDialogOpen.value).toBe(false);
    expect(withdrawTarget.value).toBeNull();
  });

  it("confirmWithdraw is a no-op when no target is set", async () => {
    const onConfirm = vi.fn();
    const { confirmWithdraw } = useWithdrawConfirmation(onConfirm);

    await confirmWithdraw();

    expect(onConfirm).not.toHaveBeenCalled();
  });

  it("cancelWithdraw resets state without calling onConfirm", () => {
    const onConfirm = vi.fn();
    const { withdrawDialogOpen, withdrawTarget, requestWithdraw, cancelWithdraw } =
      useWithdrawConfirmation(onConfirm);

    requestWithdraw(makeSession("req-3"));
    cancelWithdraw();

    expect(withdrawDialogOpen.value).toBe(false);
    expect(withdrawTarget.value).toBeNull();
    expect(onConfirm).not.toHaveBeenCalled();
  });
});
