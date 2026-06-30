/**
 * @vitest-environment jsdom
 */

import { describe, expect, it } from "vitest";
import { mount } from "@vue/test-utils";
import ApprovalModalContent from "@/components/ApprovalModalContent.vue";
import type { SessionCR } from "@/model/breakglass";

const requiredNoteSession: SessionCR = {
  metadata: { name: "session-1" },
  spec: {
    user: "requester@example.com",
    grantedGroup: "cluster-admin",
    cluster: "prod",
    approvalReasonConfig: {
      mandatory: true,
      description: "Document the incident ticket",
    },
  },
  status: { state: "Pending" },
};

const ScaleButtonStub = {
  props: {
    disabled: { type: Boolean, default: false },
  },
  template: '<button v-bind="$attrs" :disabled="disabled"><slot /></button>',
};

function isDisabled(selector: string, wrapper: ReturnType<typeof mount>): boolean {
  const disabled = wrapper.find(selector).attributes("disabled");
  return disabled !== undefined && disabled !== "false";
}

describe("ApprovalModalContent", () => {
  it("disables approve and reject while a required approver note is empty", () => {
    const wrapper = mount(ApprovalModalContent, {
      props: {
        session: requiredNoteSession,
        approverNote: "",
        isApproving: false,
      },
      global: {
        stubs: {
          "scale-button": ScaleButtonStub,
          "scale-textarea": true,
        },
      },
    });

    expect(isDisabled('[data-testid="approve-button"]', wrapper)).toBe(true);
    expect(isDisabled('[data-testid="reject-button"]', wrapper)).toBe(true);
  });

  it("enables approve and reject when the required approver note is filled", () => {
    const wrapper = mount(ApprovalModalContent, {
      props: {
        session: requiredNoteSession,
        approverNote: "INC-123 reviewed",
        isApproving: false,
      },
      global: {
        stubs: {
          "scale-button": ScaleButtonStub,
          "scale-textarea": true,
        },
      },
    });

    expect(isDisabled('[data-testid="approve-button"]', wrapper)).toBe(false);
    expect(isDisabled('[data-testid="reject-button"]', wrapper)).toBe(false);
  });

  it("shows approval controls for lowercase pending state", () => {
    const wrapper = mount(ApprovalModalContent, {
      props: {
        session: {
          ...requiredNoteSession,
          status: { state: "pending" },
        },
        approverNote: "INC-123 reviewed",
        isApproving: false,
      },
      global: {
        stubs: {
          "scale-button": ScaleButtonStub,
          "scale-textarea": true,
        },
      },
    });

    expect(wrapper.find('[data-testid="rejection-reason-input"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="approve-button"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="reject-button"]').exists()).toBe(true);
  });

  it("hides approval controls when a scheduled session is already approved", () => {
    const wrapper = mount(ApprovalModalContent, {
      props: {
        session: {
          ...requiredNoteSession,
          spec: {
            ...requiredNoteSession.spec,
            scheduledStartTime: "2026-02-20T12:00:00Z",
          },
          status: { state: "WaitingForScheduledTime" },
        },
        approverNote: "",
        isApproving: false,
      },
      global: {
        stubs: {
          "scale-button": ScaleButtonStub,
          "scale-textarea": true,
        },
      },
    });

    expect(wrapper.find('[data-testid="scheduled-activation-note"]').text()).toContain("already been approved");
    expect(wrapper.find('[data-testid="rejection-reason-input"]').exists()).toBe(false);
    expect(wrapper.find('[data-testid="approve-button"]').exists()).toBe(false);
    expect(wrapper.find('[data-testid="reject-button"]').exists()).toBe(false);
  });

  it("uses top-level scheduled state fallback for approved scheduled sessions", () => {
    const wrapper = mount(ApprovalModalContent, {
      props: {
        session: {
          ...requiredNoteSession,
          spec: {
            ...requiredNoteSession.spec,
            scheduledStartTime: "2026-02-20T12:00:00Z",
          },
          status: {},
          state: "waiting for scheduled time",
        },
        approverNote: "",
        isApproving: false,
      },
      global: {
        stubs: {
          "scale-button": ScaleButtonStub,
          "scale-textarea": true,
        },
      },
    });

    expect(wrapper.find(".modal-pill").text()).toContain("Approved and awaiting scheduled start");
    expect(wrapper.find('[data-testid="scheduled-activation-note"]').text()).toContain("already been approved");
    expect(wrapper.find('[data-testid="approve-button"]').exists()).toBe(false);
    expect(wrapper.find('[data-testid="reject-button"]').exists()).toBe(false);
  });

  it("hides approval controls for non-pending sessions", () => {
    const wrapper = mount(ApprovalModalContent, {
      props: {
        session: {
          ...requiredNoteSession,
          status: { state: "Approved" },
        },
        approverNote: "INC-123 reviewed",
        isApproving: false,
      },
      global: {
        stubs: {
          "scale-button": ScaleButtonStub,
          "scale-textarea": true,
        },
      },
    });

    expect(wrapper.find('[data-testid="rejection-reason-input"]').exists()).toBe(false);
    expect(wrapper.find('[data-testid="approve-button"]').exists()).toBe(false);
    expect(wrapper.find('[data-testid="reject-button"]').exists()).toBe(false);
  });
});
