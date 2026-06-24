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

function disabledAttribute(selector: string, wrapper: ReturnType<typeof mount>): string | undefined {
  return wrapper.find(selector).attributes("disabled");
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

    expect(disabledAttribute('[data-testid="approve-button"]', wrapper)).toBe("true");
    expect(disabledAttribute('[data-testid="reject-button"]', wrapper)).toBe("true");
    expect(wrapper.find(".approval-note-required").text()).toBe("This field is required.");
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

    expect(disabledAttribute('[data-testid="approve-button"]', wrapper)).toBe("false");
    expect(disabledAttribute('[data-testid="reject-button"]', wrapper)).toBe("false");
    expect(wrapper.find(".approval-note-required").exists()).toBe(false);
  });
});
