// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { defineComponent, ref, toRef } from "vue";
import { mount } from "@vue/test-utils";
import { afterEach, describe, expect, it } from "vitest";
import { useModalBehavior } from "@/composables/useModalBehavior";

const mountedWrappers: Array<{ unmount: () => void }> = [];

const ModalHarness = defineComponent({
  props: {
    opened: {
      type: Boolean,
      required: true,
    },
  },
  emits: ["close"],
  setup(props, { emit }) {
    useModalBehavior(toRef(props, "opened"), () => emit("close"));
    return {};
  },
  template: "<div />",
});

const SelfClosingModalHarness = defineComponent({
  emits: ["close"],
  setup(_, { emit }) {
    const opened = ref(true);
    useModalBehavior(opened, () => {
      opened.value = false;
      emit("close");
    });
    return {};
  },
  template: "<div />",
});

describe("useModalBehavior", () => {
  afterEach(() => {
    for (const wrapper of mountedWrappers.splice(0)) {
      wrapper.unmount();
    }
    document.body.style.overflow = "";
    document.documentElement.style.overflow = "";
  });

  it("closes an open modal on Escape", () => {
    const wrapper = mount(ModalHarness, { props: { opened: true } });
    mountedWrappers.push(wrapper);

    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));

    expect(wrapper.emitted("close")).toHaveLength(1);
  });

  it("ignores Escape when the modal is closed", () => {
    const wrapper = mount(ModalHarness, { props: { opened: false } });
    mountedWrappers.push(wrapper);

    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));

    expect(wrapper.emitted("close")).toBeUndefined();
  });

  it("closes the most recently opened modal first", () => {
    const first = mount(ModalHarness, { props: { opened: true } });
    const second = mount(ModalHarness, { props: { opened: true } });
    mountedWrappers.push(first, second);

    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));

    expect(first.emitted("close")).toBeUndefined();
    expect(second.emitted("close")).toHaveLength(1);
  });

  it("removes a synchronously closed modal before repeated Escape events", () => {
    const wrapper = mount(SelfClosingModalHarness);
    mountedWrappers.push(wrapper);

    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));

    expect(wrapper.emitted("close")).toHaveLength(1);
  });

  it("locks background scrolling while any modal is open", async () => {
    document.body.style.overflow = "auto";
    document.documentElement.style.overflow = "visible";

    const first = mount(ModalHarness, { props: { opened: true } });
    const second = mount(ModalHarness, { props: { opened: true } });
    mountedWrappers.push(first, second);

    expect(document.body.style.overflow).toBe("hidden");
    expect(document.documentElement.style.overflow).toBe("hidden");

    await first.setProps({ opened: false });
    expect(document.body.style.overflow).toBe("hidden");
    expect(document.documentElement.style.overflow).toBe("hidden");

    await second.setProps({ opened: false });
    expect(document.body.style.overflow).toBe("auto");
    expect(document.documentElement.style.overflow).toBe("visible");
  });
});
