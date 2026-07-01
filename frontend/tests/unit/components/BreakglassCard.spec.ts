// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

/**
 * @vitest-environment jsdom
 */

import { mount } from "@vue/test-utils";
import { nextTick } from "vue";
import { describe, expect, it } from "vitest";
import BreakglassCard from "@/components/BreakglassCard.vue";
import type { Breakglass } from "@/model/breakglass";

const SCALE_STUBS = {
  SessionSummaryCard: {
    template: `
      <section>
        <slot name="status" />
        <slot name="chips" />
        <slot name="body" />
        <slot name="timeline" />
        <slot name="footer" />
        <slot />
      </section>
    `,
  },
  "scale-button": {
    props: {
      disabled: {
        type: Boolean,
        default: false,
      },
    },
    emits: ["click"],
    template: '<button v-bind="$attrs" :disabled="disabled" @click="$emit(\'click\', $event)"><slot /></button>',
  },
  "scale-modal": {
    template: '<section v-bind="$attrs"><slot /></section>',
  },
  "scale-textarea": {
    props: ["value", "invalid"],
    template: '<textarea v-bind="$attrs" :value="value" :aria-invalid="invalid ? \'true\' : undefined"></textarea>',
  },
  "scale-text-field": {
    props: ["value"],
    template: '<input v-bind="$attrs" :value="value" />',
  },
  "scale-dropdown-select": true,
  "scale-dropdown-select-option": true,
  "scale-tag": true,
};

function makeBreakglass(overrides: Partial<Breakglass> = {}): Breakglass {
  return {
    from: "requester-group",
    to: "admin-group",
    group: "admin-group",
    cluster: "dev",
    duration: 3600,
    expiry: 0,
    state: "Available",
    selfApproval: false,
    approvalGroups: ["approver-group"],
    requestingGroups: ["requester-group"],
    requestReason: { mandatory: true, description: "Explain the operational need" },
    ...overrides,
  };
}

describe("BreakglassCard request reason validation", () => {
  it("shows a visible required reason error until the requester enters text", async () => {
    const wrapper = mount(BreakglassCard, {
      props: {
        breakglass: makeBreakglass(),
        time: Date.now(),
      },
      global: {
        stubs: SCALE_STUBS,
      },
    });

    await wrapper.find('[data-testid="request-access-button"]').trigger("click");

    const reasonError = wrapper.find('[data-testid="reason-error"]');
    expect(reasonError.exists()).toBe(true);
    expect(reasonError.text()).toContain("Reason is required");

    wrapper.find('[data-testid="reason-input"]').element.dispatchEvent(
      new CustomEvent("scale-change", {
        bubbles: true,
        detail: { value: "Emergency production repair" },
      }),
    );
    await nextTick();

    expect(wrapper.find('[data-testid="reason-error"]').exists()).toBe(false);
  });
});
