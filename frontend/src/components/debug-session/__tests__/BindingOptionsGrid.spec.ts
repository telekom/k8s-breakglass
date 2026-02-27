// SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { describe, it, expect } from "vitest";
import { mount } from "@vue/test-utils";
import BindingOptionsGrid from "../BindingOptionsGrid.vue";
import type { BindingOption } from "@/model/debugSession";

const baseOptions: BindingOption[] = [
  {
    bindingRef: { name: "binding-a", namespace: "ns-a", displayName: "Binding A" },
    displayName: "Option Alpha",
    constraints: { maxDuration: "4h" },
    approval: { required: false },
  },
  {
    bindingRef: { name: "binding-b", namespace: "ns-b" },
    displayName: "Option Beta",
    approval: { required: true, canAutoApprove: true },
  },
];

function factory(props: Partial<InstanceType<typeof BindingOptionsGrid>["$props"]> = {}) {
  return mount(BindingOptionsGrid, {
    props: {
      bindingOptions: baseOptions,
      selectedIndex: 0,
      ...props,
    },
    global: {
      stubs: {
        "scale-icon-action-clock": true,
        "scale-icon-action-success": true,
        "scale-icon-user-file-user": true,
        "scale-icon-action-random": true,
        "scale-icon-device-server": true,
        "scale-icon-action-add-circle": true,
        "scale-icon-content-link": true,
      },
    },
  });
}

describe("BindingOptionsGrid", () => {
  it("has the correct component name", () => {
    const wrapper = factory();
    expect(wrapper.vm.$options.name).toBe("BindingOptionsGrid");
  });

  it("renders binding option cards for each option", () => {
    const wrapper = factory();
    const cards = wrapper.findAll('[data-testid="binding-option-card"]');
    expect(cards).toHaveLength(2);
  });

  it("marks the selected card with the selected class", () => {
    const wrapper = factory({ selectedIndex: 1 });
    const cards = wrapper.findAll('[data-testid="binding-option-card"]');
    expect(cards[1]!.classes()).toContain("selected");
    expect(cards[0]!.classes()).not.toContain("selected");
  });

  it("sets aria-checked correctly on the selected option", () => {
    const wrapper = factory({ selectedIndex: 0 });
    const cards = wrapper.findAll('[data-testid="binding-option-card"]');
    expect(cards[0]!.attributes("aria-checked")).toBe("true");
    expect(cards[1]!.attributes("aria-checked")).toBe("false");
  });

  it("emits update:selectedIndex when a card is clicked", async () => {
    const wrapper = factory({ selectedIndex: 0 });
    const cards = wrapper.findAll('[data-testid="binding-option-card"]');
    await cards[1]!.trigger("click");
    expect(wrapper.emitted("update:selectedIndex")).toBeTruthy();
    expect(wrapper.emitted("update:selectedIndex")![0]).toEqual([1]);
  });

  it("displays binding source references", () => {
    const wrapper = factory();
    const refs = wrapper.findAll('[data-testid="binding-source-ref"]');
    expect(refs).toHaveLength(2);
    expect(refs[0]!.text()).toContain("ns-a/binding-a");
    expect(refs[1]!.text()).toContain("ns-b/binding-b");
  });

  it("shows display name for options", () => {
    const wrapper = factory();
    expect(wrapper.text()).toContain("Option Alpha");
    expect(wrapper.text()).toContain("Option Beta");
  });

  it("renders the radiogroup container", () => {
    const wrapper = factory();
    const grid = wrapper.find('[data-testid="binding-options-grid"]');
    expect(grid.exists()).toBe(true);
    expect(grid.attributes("role")).toBe("radiogroup");
  });
});
