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
  const approvalActions =
    state === "PendingApproval"
      ? {
          canApprove: true,
          canReject: true,
        }
      : {};

  return {
    name,
    templateRef: "debug-template",
    cluster: "test-cluster",
    requestedBy: "alice",
    state,
    participants: 0,
    isParticipant: false,
    allowedPods: 1,
    ...approvalActions,
  };
}

function expectAccessibleLabel(wrapper: ReturnType<typeof mount>, targetId: string | undefined, text: string) {
  expect(targetId).toBeTruthy();
  const label = wrapper.find(`label[for="${targetId}"]`);
  expect(label.exists()).toBe(true);
  expect(label.text()).toBe(text);
}

describe("DebugSessionCard", () => {
  it("uses collision-safe label targets for per-card reject controls", async () => {
    const sessions = [makeSession("team/session-b"), makeSession("team-session-b")];
    const rejectWrapper = mount(
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

    for (const button of rejectWrapper.findAll('[data-testid="reject-button"]')) {
      await button.trigger("click");
    }

    const rejectInputs = rejectWrapper.findAll('[data-testid="reject-reason-input"]');
    expect(rejectInputs).toHaveLength(sessions.length);
    const rejectIds = rejectInputs.map((input) => input.attributes("id"));

    expect(new Set(rejectIds).size).toBe(rejectIds.length);
    for (const id of rejectIds) {
      expectAccessibleLabel(rejectWrapper, id, "Rejection Reason");
    }
  });

  it("uses collision-safe label targets for per-card renew controls", async () => {
    const sessions = [makeSession("team/session-b", "Active"), makeSession("team-session-b", "Active")];
    const renewWrapper = mount(
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

    for (const button of renewWrapper.findAll('[data-testid="renew-button"]')) {
      await button.trigger("click");
    }

    const renewInputs = renewWrapper.findAll('[data-testid="renew-duration-select"]');
    expect(renewInputs).toHaveLength(sessions.length);
    const renewIds = renewInputs.map((input) => input.attributes("id"));

    expect(new Set(renewIds).size).toBe(renewIds.length);
    for (const id of renewIds) {
      expectAccessibleLabel(renewWrapper, id, "Extend By");
    }
  });

  it("resets the renew duration each time the modal opens", async () => {
    const renewResetWrapper = mount(DebugSessionCard, {
      props: {
        session: makeSession("team/session-b", "Active"),
        isOwner: true,
      },
      global: {
        stubs: SCALE_STUBS,
      },
    });

    await renewResetWrapper.find('[data-testid="renew-button"]').trigger("click");

    let select = renewResetWrapper.find('[data-testid="renew-duration-select"]');
    expect(select.attributes("value")).toBe("1h");

    const changeEvent = new CustomEvent("scale-change", {
      bubbles: true,
      detail: { value: "2h" },
    });
    select.element.dispatchEvent(changeEvent);
    await nextTick();

    await renewResetWrapper.find('[data-testid="renew-confirm-button"]').trigger("click");
    expect(renewResetWrapper.emitted("renew")?.[0]).toEqual(["2h"]);

    await renewResetWrapper.find('[data-testid="renew-button"]').trigger("click");

    select = renewResetWrapper.find('[data-testid="renew-duration-select"]');
    expect(select.attributes("value")).toBe("1h");
  });

  it("offers the same renew durations as the details view", async () => {
    const renewDurationsWrapper = mount(DebugSessionCard, {
      props: {
        session: makeSession("team/session-b", "Active"),
        isOwner: true,
      },
      global: {
        stubs: SCALE_STUBS,
      },
    });

    await renewDurationsWrapper.find('[data-testid="renew-button"]').trigger("click");

    const renewSelect = renewDurationsWrapper.find('[data-testid="renew-duration-select"]');
    const fourHourOption = renewSelect.find('[value="4h"]');

    expect(fourHourOption.exists()).toBe(true);
    expect(fourHourOption.text()).toBe("4 hours");
  });

  it("resets the reject reason each time the modal opens", async () => {
    const rejectResetWrapper = mount(DebugSessionCard, {
      props: {
        session: makeSession("team/session-b"),
      },
      global: {
        stubs: SCALE_STUBS,
      },
    });

    await rejectResetWrapper.find('[data-testid="reject-button"]').trigger("click");

    const vm = rejectResetWrapper.vm as unknown as { rejectReason: string };
    vm.rejectReason = "needs a clearer business reason";
    await nextTick();
    expect(vm.rejectReason).toBe("needs a clearer business reason");

    await rejectResetWrapper.find('[data-testid="reject-cancel-button"]').trigger("click");
    await rejectResetWrapper.find('[data-testid="reject-button"]').trigger("click");

    expect(vm.rejectReason).toBe("");
  });

  it("hides approval actions when the API does not authorize them", () => {
    const approvalActionsWrapper = mount(DebugSessionCard, {
      props: {
        session: {
          ...makeSession("team/session-b"),
          canApprove: false,
          canReject: false,
        },
      },
      global: {
        stubs: SCALE_STUBS,
      },
    });

    expect(approvalActionsWrapper.find('[data-testid="approve-button"]').exists()).toBe(false);
    expect(approvalActionsWrapper.find('[data-testid="reject-button"]').exists()).toBe(false);
  });
});
