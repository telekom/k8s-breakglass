/**
 * Component-level tests for PendingApprovalsView
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mount, flushPromises } from "@vue/test-utils";
import { nextTick, ref } from "vue";
import PendingApprovalsView from "@/views/PendingApprovalsView.vue";
import { AuthKey } from "@/keys";
import { handleAxiosError } from "@/services/logger";
import { pushSuccess } from "@/services/toast";

const mockFetchPendingSessionsForApproval = vi.fn();
const mockApproveBreakglass = vi.fn();
const mockRejectBreakglass = vi.fn();

vi.mock("@/services/breakglass", () => ({
  default: class MockBreakglassService {
    fetchPendingSessionsForApproval = mockFetchPendingSessionsForApproval;
    approveBreakglass = mockApproveBreakglass;
    rejectBreakglass = mockRejectBreakglass;
  },
}));

vi.mock("@/services/toast", () => ({
  pushError: vi.fn(),
  pushSuccess: vi.fn(),
}));

vi.mock("@/services/logger", () => ({
  handleAxiosError: vi.fn(() => ({ message: "network error" })),
  debug: vi.fn(),
  info: vi.fn(),
  warn: vi.fn(),
  error: vi.fn(),
}));

vi.mock("@/composables", () => ({
  formatDateTime: vi.fn((value) => String(value ?? "")),
  formatDuration: vi.fn((value) => String(value ?? "")),
  formatEndTime: vi.fn(() => "end"),
  getUrgency: vi.fn(() => "normal"),
  getTimeRemaining: vi.fn(() => 1000),
  getUrgencyLabel: vi.fn(() => ({ text: "Normal", icon: "content-clock", ariaLabel: "Normal urgency" })),
  getSessionKey: vi.fn((session) => session?.metadata?.name || "session"),
  getSessionState: vi.fn((session) => session?.status?.state || "Pending"),
  getSessionCluster: vi.fn((session) => session?.spec?.cluster || "cluster-a"),
  getSessionGroup: vi.fn((session) => session?.spec?.grantedGroup || "group-a"),
  dedupeSessions: vi.fn((sessions) => sessions),
}));

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason?: unknown) => void;
  const promise = new Promise<T>((promiseResolve, promiseReject) => {
    resolve = promiseResolve;
    reject = promiseReject;
  });
  return { promise, resolve, reject };
}

const SessionSummaryCardStub = {
  template: `
    <article data-testid="session-summary-card">
      <slot name="status" />
      <slot name="chips" />
      <slot name="meta" />
      <slot name="body" />
      <slot name="footer" />
    </article>
  `,
};

const ActionButtonStub = {
  props: ["label", "disabled", "loading", "loadingLabel"],
  emits: ["click"],
  template:
    '<button type="button" data-testid="review-button" :disabled="disabled" @click="$emit(\'click\')">{{ label }}</button>',
};

const ApprovalModalContentStub = {
  props: ["session", "approverNote", "isApproving"],
  emits: ["update:approver-note", "approve", "reject", "cancel"],
  template: `
    <div data-testid="approval-modal-content">
      <button type="button" data-testid="modal-approve" @click="$emit('approve')">Approve</button>
      <button type="button" data-testid="modal-reject" @click="$emit('reject')">Reject</button>
      <button type="button" data-testid="modal-cancel" @click="$emit('cancel')">Cancel</button>
    </div>
  `,
};

const ScaleModalStub = {
  inheritAttrs: false,
  props: ["opened"],
  emits: ["scale-close"],
  template: `
    <div v-if="opened" v-bind="$attrs">
      <button type="button" data-testid="modal-close" @click="$emit('scale-close')">Close</button>
      <slot />
    </div>
  `,
};

describe("PendingApprovalsView (component)", () => {
  const mockAuth = {
    user: ref({ email: "approver@example.com" }),
    token: ref("token"),
    isAuthenticated: ref(true),
  };

  beforeEach(() => {
    mockFetchPendingSessionsForApproval.mockResolvedValue([]);
    mockApproveBreakglass.mockResolvedValue(undefined);
    mockRejectBreakglass.mockResolvedValue(undefined);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  const createWrapper = async () => {
    const wrapper = mount(PendingApprovalsView, {
      global: {
        provide: {
          [AuthKey as symbol]: mockAuth,
        },
        stubs: {
          PageHeader: true,
          EmptyState: true,
          LoadingState: true,
          StatusTag: true,
          ReasonPanel: true,
          ActionButton: ActionButtonStub,
          CountdownTimer: true,
          SessionSummaryCard: SessionSummaryCardStub,
          SessionMetaGrid: true,
          ApprovalModalContent: ApprovalModalContentStub,
          "scale-dropdown-select": true,
          "scale-dropdown-select-option": true,
          "scale-modal": ScaleModalStub,
          "scale-tag": true,
          "scale-icon-alert-warning": true,
          "scale-icon-content-clock": true,
          "scale-icon-content-calendar": true,
          "scale-icon-action-edit": true,
          "scale-button": true,
        },
      },
    });

    await flushPromises();
    return wrapper;
  };

  it("fetches pending sessions on mount", async () => {
    await createWrapper();
    expect(mockFetchPendingSessionsForApproval).toHaveBeenCalledTimes(1);
  });

  it("shows empty state when there are no pending sessions", async () => {
    const wrapper = await createWrapper();
    expect(wrapper.find('[data-testid="empty-state"]').exists()).toBe(true);
  });

  it("announces pending approval result counts as a status update", async () => {
    const wrapper = await createWrapper();
    const status = wrapper.find('[data-testid="toolbar-info"]');

    expect(status.exists()).toBe(true);
    expect(status.attributes("role")).toBe("status");
    expect(status.attributes("aria-live")).toBe("polite");
    expect(status.attributes("aria-atomic")).toBe("true");
    expect(status.text()).toBe("Showing 0 of 0 pending requests");
  });

  it("shows session list when pending sessions exist", async () => {
    mockFetchPendingSessionsForApproval.mockResolvedValueOnce([
      {
        metadata: { name: "session-1", creationTimestamp: "2026-02-01T10:00:00Z" },
        spec: { user: "user@example.com", grantedGroup: "admin", cluster: "cluster-a" },
        status: { state: "Pending", timeoutAt: "2026-02-01T11:00:00Z" },
      },
    ]);

    const wrapper = await createWrapper();
    expect(wrapper.find('[data-testid="pending-sessions-list"]').exists()).toBe(true);
  });

  it("shows error toast when loading sessions fails", async () => {
    mockFetchPendingSessionsForApproval.mockRejectedValueOnce(new Error("network error"));

    const wrapper = await createWrapper();
    expect(handleAxiosError).toHaveBeenCalledWith(
      "PendingApprovalsView",
      expect.any(Error),
      "Failed to fetch pending approvals",
    );
    const errorState = wrapper.findComponent({ name: "EmptyState" });
    expect(errorState.exists()).toBe(true);
    expect(errorState.props("variant")).toBe("error");
    expect(errorState.props("description")).toBe("network error");
  });

  it("keeps the approval modal mounted while rejection is in flight", async () => {
    const session = {
      metadata: { name: "session-1", creationTimestamp: "2026-02-01T10:00:00Z" },
      spec: { user: "requester@example.com", grantedGroup: "admin", cluster: "cluster-a" },
      status: { state: "Pending", timeoutAt: "2026-02-01T11:00:00Z" },
    };
    const rejection = deferred<void>();
    mockFetchPendingSessionsForApproval.mockResolvedValueOnce([session]).mockResolvedValue([]);
    mockRejectBreakglass.mockReturnValueOnce(rejection.promise);

    const wrapper = await createWrapper();

    await wrapper.find('[data-testid="review-button"]').trigger("click");
    const modal = wrapper.find('[data-testid="approval-modal"]');
    expect(modal.exists()).toBe(true);

    await wrapper.find('[data-testid="modal-reject"]').trigger("click");
    modal.element.dispatchEvent(new CustomEvent("scale-close", { bubbles: true, cancelable: true }));
    await nextTick();
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true }));

    expect(wrapper.find('[data-testid="approval-modal-content"]').exists()).toBe(true);

    rejection.resolve();
    await flushPromises();

    expect(vi.mocked(pushSuccess)).toHaveBeenCalledWith("Rejected request for requester@example.com (admin)!");
    expect(wrapper.find('[data-testid="approval-modal-content"]').exists()).toBe(false);
  });
});
