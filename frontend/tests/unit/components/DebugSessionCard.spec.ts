// SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
//
// SPDX-License-Identifier: Apache-2.0

/**
 * @vitest-environment jsdom
 */

import { describe, expect, it } from "vitest";
import { mount } from "@vue/test-utils";
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

function makeSession(name: string): DebugSessionSummary {
  return {
    name,
    templateRef: "debug-template",
    cluster: "test-cluster",
    requestedBy: "alice",
    state: "PendingApproval",
    participants: 0,
    isParticipant: false,
    allowedPods: 1,
  };
}

describe("DebugSessionCard", () => {
  it("uses unique label targets for per-card reject and renew controls", () => {
    const sessions = [makeSession("session-a"), makeSession("team/session-b")];
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

    const rejectInputs = wrapper.findAll('[data-testid="reject-reason-input"]');
    const renewInputs = wrapper.findAll('[data-testid="renew-duration-select"]');

    expect(rejectInputs.map((input) => input.attributes("id"))).toEqual([
      "reject-reason-session-a",
      "reject-reason-team-session-b",
    ]);
    expect(renewInputs.map((input) => input.attributes("id"))).toEqual([
      "renew-duration-session-a",
      "renew-duration-team-session-b",
    ]);
    expect(wrapper.find('label[for="reject-reason-session-a"]').exists()).toBe(true);
    expect(wrapper.find('label[for="reject-reason-team-session-b"]').exists()).toBe(true);
    expect(wrapper.find('label[for="renew-duration-session-a"]').exists()).toBe(true);
    expect(wrapper.find('label[for="renew-duration-team-session-b"]').exists()).toBe(true);
  });
});
