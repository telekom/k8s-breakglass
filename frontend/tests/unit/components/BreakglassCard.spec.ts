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
  "scale-dropdown-select-item": true,
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
  it("submits an optional ticket reference verbatim without treating it as a reason", async () => {
    const wrapper = mount(BreakglassCard, {
      props: { breakglass: makeBreakglass({ requestReason: { mandatory: false } }), time: Date.now() },
      global: { stubs: SCALE_STUBS },
    });
    await wrapper.find('[data-testid="request-access-button"]').trigger("click");
    const ticketSystemID = "arbitrary <reference>\nü";
    wrapper
      .get('[data-testid="ticket-system-id-input"]')
      .element.dispatchEvent(new CustomEvent("scale-change", { bubbles: true, detail: { value: ticketSystemID } }));
    await nextTick();
    await wrapper.get('[data-testid="submit-request-button"]').trigger("click");
    const requests = wrapper.emitted("request");
    expect(requests).toHaveLength(1);
    expect(requests?.[0]?.[3]).toBe(ticketSystemID);
  });
  it.each([
    { displayName: "Production admin", escalationName: "admin-a1b2c3d4", expected: "Production admin" },
    { displayName: "", escalationName: "admin-a1b2c3d4", expected: "admin-a1b2c3d4" },
    { displayName: undefined, escalationName: "admin-a1b2c3d4", expected: "admin-a1b2c3d4" },
    { displayName: undefined, escalationName: undefined, expected: "admin-group" },
  ])("renders the escalation title with fallback: $expected", ({ displayName, escalationName, expected }) => {
    const wrapper = mount(BreakglassCard, {
      props: { breakglass: makeBreakglass({ displayName, escalationName }), time: Date.now() },
      global: { stubs: { ...SCALE_STUBS, SessionSummaryCard: false } },
    });
    expect(wrapper.get('[data-testid="summary-card-title"]').text()).toBe(expected);
    expect(wrapper.findAll('[data-testid="escalation-name"]')).toHaveLength(1);
    expect(wrapper.get('[data-testid="escalation-name"]').text()).toBe("admin-group");
    expect(wrapper.get('[data-testid="escalation-card"]').attributes("data-escalation-name")).toBe(escalationName);
    expect(wrapper.text()).toContain("Granted group");
    expect(wrapper.text()).toContain("admin-group");
  });

  it("exposes every deduplicated identity without replacing the legacy granted-group selector", () => {
    const identities = ["admin-a1b2c3d4", "Production admin", "admin-e5f6a7b8", "Secondary admin"];
    const wrapper = mount(BreakglassCard, {
      props: {
        breakglass: makeBreakglass({
          escalationName: identities[0],
          displayName: identities[1],
          escalationIdentities: identities,
        }),
        time: Date.now(),
      },
      global: { stubs: { ...SCALE_STUBS, SessionSummaryCard: false } },
    });
    expect(
      JSON.parse(wrapper.get('[data-testid="escalation-card"]').attributes("data-escalation-identities")!),
    ).toEqual(identities);
    expect(wrapper.get('[data-testid="summary-card-title"]').text()).toBe("Production admin");
    expect(wrapper.get('[data-testid="escalation-name"]').text()).toBe("admin-group");
  });

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
