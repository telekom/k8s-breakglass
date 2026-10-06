// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

import { defineComponent, nextTick, ref, toRef } from "vue";
import { mount } from "@vue/test-utils";
import { afterEach, describe, expect, it, vi } from "vitest";
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

const ModalWithEscapeChildHarness = defineComponent({
  props: {
    opened: {
      type: Boolean,
      required: true,
    },
    preventDefault: {
      type: Boolean,
      default: false,
    },
    stopPropagation: {
      type: Boolean,
      default: false,
    },
  },
  emits: ["child-escape", "close"],
  setup(props, { emit }) {
    useModalBehavior(toRef(props, "opened"), () => emit("close"));

    function handleChildKeydown(event: KeyboardEvent) {
      if (event.key !== "Escape") return;
      if (props.preventDefault) event.preventDefault();
      if (props.stopPropagation) event.stopPropagation();
      emit("child-escape");
    }

    return { handleChildKeydown };
  },
  template: `
    <div>
      <button type="button" data-test="child-control" @keydown="handleChildKeydown">Child</button>
    </div>
  `,
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

function createScaleModal() {
  const modal = document.createElement("scale-modal") as HTMLElement & { opened?: boolean };
  modal.opened = true;
  const closeButton = document.createElement("button");
  closeButton.className = "modal__close-button";
  modal.attachShadow({ mode: "open" }).appendChild(closeButton);
  return { modal, closeButton };
}

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

  it("lets nested controls consume Escape before closing the modal", () => {
    const wrapper = mount(ModalWithEscapeChildHarness, {
      attachTo: document.body,
      props: { opened: true, stopPropagation: true },
    });
    mountedWrappers.push(wrapper);

    wrapper
      .find('[data-test="child-control"]')
      .element.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true }));

    expect(wrapper.emitted("child-escape")).toHaveLength(1);
    expect(wrapper.emitted("close")).toBeUndefined();
  });

  it("ignores Escape events already handled by nested controls", () => {
    const wrapper = mount(ModalWithEscapeChildHarness, {
      attachTo: document.body,
      props: { opened: true, preventDefault: true },
    });
    mountedWrappers.push(wrapper);

    wrapper
      .find('[data-test="child-control"]')
      .element.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true }));

    expect(wrapper.emitted("child-escape")).toHaveLength(1);
    expect(wrapper.emitted("close")).toBeUndefined();
  });

  it("moves focus into the opened dialog and returns it to the trigger on close", async () => {
    const trigger = document.createElement("button");
    trigger.textContent = "Open";
    document.body.appendChild(trigger);
    trigger.focus();

    // Minimal stand-in for an opened scale-modal with its shadow close button,
    // rendered (as in the app) once the dialog's opened state is true.
    const { modal, closeButton } = createScaleModal();

    try {
      const wrapper = mount(ModalHarness, { props: { opened: true } });
      mountedWrappers.push(wrapper);
      document.body.appendChild(modal);
      await nextTick();
      await Promise.resolve();

      expect(modal.shadowRoot?.activeElement).toBe(closeButton);

      modal.opened = false;
      await wrapper.setProps({ opened: false });
      expect(document.activeElement).toBe(trigger);
    } finally {
      modal.remove();
      trigger.remove();
    }
  });

  it("focuses a dialog that is inserted a few frames after opening", async () => {
    const trigger = document.createElement("button");
    document.body.appendChild(trigger);
    trigger.focus();

    const { modal, closeButton } = createScaleModal();

    try {
      const wrapper = mount(ModalHarness, { props: { opened: true } });
      mountedWrappers.push(wrapper);
      await nextTick();
      await new Promise((resolve) => requestAnimationFrame(resolve));
      expect(document.activeElement).toBe(trigger);

      document.body.appendChild(modal);
      await vi.waitFor(() => expect(modal.shadowRoot?.activeElement).toBe(closeButton));
    } finally {
      modal.remove();
      trigger.remove();
    }
  });

  it("focuses the most recently opened dialog even when it precedes the other in DOM order", async () => {
    const older = createScaleModal();
    const newer = createScaleModal();

    try {
      const first = mount(ModalHarness, { props: { opened: true } });
      mountedWrappers.push(first);
      document.body.appendChild(older.modal);
      await vi.waitFor(() => expect(older.modal.shadowRoot?.activeElement).toBe(older.closeButton));

      const second = mount(ModalHarness, { props: { opened: true } });
      mountedWrappers.push(second);
      document.body.insertBefore(newer.modal, older.modal);

      await vi.waitFor(() => expect(newer.modal.shadowRoot?.activeElement).toBe(newer.closeButton));
      expect(document.activeElement).toBe(newer.modal);
    } finally {
      older.modal.remove();
      newer.modal.remove();
    }
  });

  it("anchors focus on the page heading when a refresh replaces the trigger", async () => {
    const main = document.createElement("div");
    main.id = "main";
    const heading = document.createElement("h1");
    heading.textContent = "Request access";
    const trigger = document.createElement("button");
    main.append(heading, trigger);
    document.body.appendChild(main);
    trigger.focus();
    const { modal } = createScaleModal();

    try {
      const wrapper = mount(ModalHarness, { props: { opened: true } });
      mountedWrappers.push(wrapper);
      document.body.appendChild(modal);
      await vi.waitFor(() => expect(document.activeElement).toBe(modal));

      modal.remove();
      await wrapper.setProps({ opened: false });
      expect(document.activeElement).toBe(trigger);

      // The successful action refreshes the list and the trigger is replaced.
      trigger.remove();
      const replacement = document.createElement("button");
      main.appendChild(replacement);

      await vi.waitFor(() => expect(document.activeElement).toBe(heading));
    } finally {
      main.remove();
    }
  });

  it("anchors focus on the heading when a slow request replaces the trigger much later", async () => {
    const main = document.createElement("div");
    main.id = "main";
    const heading = document.createElement("h1");
    const trigger = document.createElement("button");
    main.append(heading, trigger);
    document.body.appendChild(main);
    trigger.focus();
    const { modal } = createScaleModal();

    try {
      const wrapper = mount(ModalHarness, { props: { opened: true } });
      mountedWrappers.push(wrapper);
      document.body.appendChild(modal);
      await vi.waitFor(() => expect(document.activeElement).toBe(modal));
      modal.remove();
      await wrapper.setProps({ opened: false });
      expect(document.activeElement).toBe(trigger);

      vi.useFakeTimers();
      vi.advanceTimersByTime(30_000);
      vi.useRealTimers();
      trigger.remove();

      await vi.waitFor(() => expect(document.activeElement).toBe(heading));
    } finally {
      vi.useRealTimers();
      main.remove();
    }
  });

  it("does not move focus once the user has focused something else", async () => {
    const main = document.createElement("div");
    main.id = "main";
    const heading = document.createElement("h1");
    const trigger = document.createElement("button");
    const other = document.createElement("button");
    main.append(heading, trigger, other);
    document.body.appendChild(main);
    trigger.focus();
    const { modal } = createScaleModal();

    try {
      const wrapper = mount(ModalHarness, { props: { opened: true } });
      mountedWrappers.push(wrapper);
      document.body.appendChild(modal);
      await vi.waitFor(() => expect(document.activeElement).toBe(modal));
      modal.remove();
      await wrapper.setProps({ opened: false });

      other.focus();
      trigger.remove();
      await new Promise((resolve) => setTimeout(resolve, 50));

      expect(document.activeElement).toBe(other);
    } finally {
      main.remove();
    }
  });

  it("keeps focus in the top dialog when the dialog underneath closes", async () => {
    const trigger = document.createElement("button");
    document.body.appendChild(trigger);
    trigger.focus();
    const lower = createScaleModal();
    const upper = createScaleModal();

    try {
      const first = mount(ModalHarness, { props: { opened: true } });
      mountedWrappers.push(first);
      document.body.appendChild(lower.modal);
      await vi.waitFor(() => expect(document.activeElement).toBe(lower.modal));

      const second = mount(ModalHarness, { props: { opened: true } });
      mountedWrappers.push(second);
      document.body.appendChild(upper.modal);
      await vi.waitFor(() => expect(upper.modal.shadowRoot?.activeElement).toBe(upper.closeButton));

      lower.modal.remove();
      await first.setProps({ opened: false });
      await new Promise((resolve) => setTimeout(resolve, 50));

      expect(document.activeElement).toBe(upper.modal);
      expect(upper.modal.shadowRoot?.activeElement).toBe(upper.closeButton);
    } finally {
      lower.modal.remove();
      upper.modal.remove();
      trigger.remove();
    }
  });

  it("keeps focus on the trigger when it survives closing", async () => {
    const trigger = document.createElement("button");
    document.body.appendChild(trigger);
    trigger.focus();
    const { modal } = createScaleModal();

    try {
      const wrapper = mount(ModalHarness, { props: { opened: true } });
      mountedWrappers.push(wrapper);
      document.body.appendChild(modal);
      await vi.waitFor(() => expect(document.activeElement).toBe(modal));

      modal.remove();
      await wrapper.setProps({ opened: false });
      await new Promise((resolve) => setTimeout(resolve, 250));

      expect(document.activeElement).toBe(trigger);
    } finally {
      trigger.remove();
    }
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
