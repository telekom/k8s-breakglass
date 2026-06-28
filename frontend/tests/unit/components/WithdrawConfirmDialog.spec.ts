// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

/**
 * Tests for WithdrawConfirmDialog component.
 *
 * @vitest-environment jsdom
 */

import { afterEach, describe, it, expect } from "vitest";
import { shallowMount } from "@vue/test-utils";
import WithdrawConfirmDialog from "@/components/WithdrawConfirmDialog.vue";

const mountedWrappers: Array<{ unmount: () => void }> = [];

function mountDialog(props: { opened: boolean; sessionName?: string }) {
  const wrapper = shallowMount(WithdrawConfirmDialog, { props });
  mountedWrappers.push(wrapper);
  return wrapper;
}

describe("WithdrawConfirmDialog", () => {
  afterEach(() => {
    for (const wrapper of mountedWrappers.splice(0)) {
      wrapper.unmount();
    }
    document.body.style.overflow = "";
    document.documentElement.style.overflow = "";
  });

  it("renders the modal with the correct heading", () => {
    const wrapper = mountDialog({ opened: true });
    const modal = wrapper.find('[data-testid="withdraw-confirm-modal"]');
    expect(modal.exists()).toBe(true);
    expect(modal.attributes("heading")).toBe("Withdraw Request");
  });

  it("shows session name when provided", () => {
    const wrapper = mountDialog({ opened: true, sessionName: "req-42" });
    expect(wrapper.text()).toContain("req-42");
  });

  it("does not show session name when not provided", () => {
    const wrapper = mountDialog({ opened: true });
    expect(wrapper.find(".withdraw-detail").exists()).toBe(false);
  });

  it("emits confirm when Withdraw button is clicked", async () => {
    const wrapper = mountDialog({ opened: true });
    await wrapper.find('[data-testid="withdraw-confirm-btn"]').trigger("click");
    expect(wrapper.emitted("confirm")).toHaveLength(1);
  });

  it("emits cancel when Cancel button is clicked", async () => {
    const wrapper = mountDialog({ opened: true });
    await wrapper.find('[data-testid="withdraw-cancel-btn"]').trigger("click");
    expect(wrapper.emitted("cancel")).toHaveLength(1);
  });

  it("emits cancel when Escape is pressed", () => {
    const wrapper = mountDialog({ opened: true });
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
    expect(wrapper.emitted("cancel")).toHaveLength(1);
    wrapper.unmount();
  });

  it("passes opened prop through to scale-modal", () => {
    const wrapper = mountDialog({ opened: false });
    const modal = wrapper.find('[data-testid="withdraw-confirm-modal"]');
    expect(modal.attributes("opened")).toBe("false");
  });
});
