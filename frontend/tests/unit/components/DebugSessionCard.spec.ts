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
  it("uses collision-safe label targets for per-card reject and renew controls", () => {
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

    const rejectInputs = wrapper.findAll('[data-testid="reject-reason-input"]');
    const renewInputs = wrapper.findAll('[data-testid="renew-duration-select"]');

    const rejectIds = rejectInputs.map((input) => input.attributes("id"));
    const renewIds = renewInputs.map((input) => input.attributes("id"));

    expect(new Set(rejectIds).size).toBe(rejectIds.length);
    expect(new Set(renewIds).size).toBe(renewIds.length);
    for (const id of rejectIds) {
      expect(wrapper.find(`label[for="${id}"]`).exists()).toBe(true);
    }
    for (const id of renewIds) {
      expect(wrapper.find(`label[for="${id}"]`).exists()).toBe(true);
    }
  });
});
