// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

/**
 * @vitest-environment jsdom
 */

import { describe, expect, it } from "vitest";
import { mount } from "@vue/test-utils";
import { nextTick } from "vue";
import DebugSessionCard from "@/components/DebugSessionCard.vue";
import type { DebugSessionSummary } from "@/model/debugSession";

const SCALE_STUBS = {
  "scale-tag": true,
  "scale-icon-alert-error": true,
  "scale-button": true,
  "scale-modal": { template: "<div><slot/><slot name='action'/></div>" },
  "scale-text-field": true,
  "scale-dropdown-select": true,
  "scale-dropdown-select-item": true,
};

function makeSession(name: string, state: DebugSessionSummary["state"] = "PendingApproval"): DebugSessionSummary {
  return {
    name,
    templateRef: "debug-template",
    cluster: "test-cluster",
    requestedBy: "alice",
    state,
    participants: 0,
    isParticipant: false,
    allowedPods: 1,
  };
}

describe("DebugSessionCard", () => {
  it("uses collision-safe label targets for per-card reject controls", async () => {
    const sessions = [makeSession("team/session-b"), makeSession("team-session-b")];
    const wrapper = mount(
      {
        components: { DebugSessionCard },
        data: () => ({ sessions }),
        template: `
          <div>
            <DebugSessionCard
              v-for="session in sessions"
              :key="session.name"
              :session="session"
            />
          </div>
        `,
      },
      {
        global: {
          stubs: SCALE_STUBS,
        },
      },
    );

    for (const button of wrapper.findAll('[data-testid="reject-button"]')) {
      await button.trigger("click");
    }

    const rejectInputs = wrapper.findAll('[data-testid="reject-reason-input"]');
    expect(rejectInputs).toHaveLength(sessions.length);
    const rejectIds = rejectInputs.map((input) => input.attributes("id"));

    expect(new Set(rejectIds).size).toBe(rejectIds.length);
  });

  it("uses collision-safe label targets for per-card renew controls", async () => {
    const sessions = [makeSession("team/session-b", "Active"), makeSession("team-session-b", "Active")];
    const wrapper = mount(
      {
        components: { DebugSessionCard },
        data: () => ({ sessions }),
        template: `
          <div>
            <DebugSessionCard
              v-for="session in sessions"
              :key="session.name"
              :session="session"
              :is-owner="true"
            />
          </div>
        `,
      },
      {
        global: {
          stubs: SCALE_STUBS,
        },
      },
    );

    for (const button of wrapper.findAll('[data-testid="renew-button"]')) {
      await button.trigger("click");
    }

    const renewInputs = wrapper.findAll('[data-testid="renew-duration-select"]');
    expect(renewInputs).toHaveLength(sessions.length);
    const renewIds = renewInputs.map((input) => input.attributes("id"));

    expect(new Set(renewIds).size).toBe(renewIds.length);
    for (const id of renewIds) {
      expect(wrapper.find(`label[for="${id}"]`).exists()).toBe(true);
    }
    const wrapper = mount(DebugSessionCard, {
      props: {
        session: makeSession("team/session-b", "Active"),
        isOwner: true,
      },
      global: {
        stubs: SCALE_STUBS,
      },
    });

    await wrapper.find('[data-testid="renew-button"]').trigger("click");

    let select = wrapper.find('[data-testid="renew-duration-select"]');
    expect(select.attributes("value")).toBe("1h");

    const changeEvent = new CustomEvent("scale-change", {
      bubbles: true,
      detail: { value: "2h" },
    });
    select.element.dispatchEvent(changeEvent);
    await nextTick();

    await wrapper.find('[data-testid="renew-confirm-button"]').trigger("click");
    expect(wrapper.emitted("renew")?.[0]).toEqual(["2h"]);

    await wrapper.find('[data-testid="renew-button"]').trigger("click");

    select = wrapper.find('[data-testid="renew-duration-select"]');
    expect(select.attributes("value")).toBe("1h");
  });

  it("offers the same renew durations as the details view", async () => {
    const wrapper = mount(DebugSessionCard, {
      props: {
        session: makeSession("team/session-b", "Active"),
        isOwner: true,
      },
      global: {
        stubs: SCALE_STUBS,
      },
    });

    await wrapper.find('[data-testid="renew-button"]').trigger("click");

    const renewSelect = wrapper.find('[data-testid="renew-duration-select"]');
    const fourHourOption = renewSelect.find('[value="4h"]');

    expect(fourHourOption.exists()).toBe(true);
    expect(fourHourOption.text()).toBe("4 hours");
  });

  it("resets the reject reason each time the modal opens", async () => {
    const wrapper = mount(DebugSessionCard, {
      props: {
        session: makeSession("team/session-b"),
      },
      global: {
        stubs: SCALE_STUBS,
      },
    });

    await wrapper.find('[data-testid="reject-button"]').trigger("click");

    const vm = wrapper.vm as unknown as { rejectReason: string };
    vm.rejectReason = "needs a clearer business reason";
    await nextTick();
    expect(vm.rejectReason).toBe("needs a clearer business reason");

    await wrapper.find('[data-testid="reject-cancel-button"]').trigger("click");
    await wrapper.find('[data-testid="reject-button"]').trigger("click");

    expect(vm.rejectReason).toBe("");
  });
});
