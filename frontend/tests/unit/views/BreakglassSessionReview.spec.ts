/**
 * Component-level tests for BreakglassSessionReview
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mount, flushPromises } from "@vue/test-utils";
import { createRouter, createMemoryHistory } from "vue-router";
import { nextTick, ref } from "vue";
import BreakglassSessionReview from "@/views/BreakglassSessionReview.vue";
import { AuthKey } from "@/keys";
import { pushSuccess } from "@/services/toast";

const mockGetSessionStatus = vi.fn();
const mockApproveReview = vi.fn();
const mockRejectReview = vi.fn();
const mockDropSession = vi.fn();
const mockCancelSession = vi.fn();

type MockUser = {
  email?: string;
  preferred_username?: string;
  expired?: boolean;
  profile?: {
    email?: string;
    preferred_username?: string;
  };
};

const mockUser = ref<MockUser | null>(null);

vi.mock("@/services/auth", () => ({
  useUser: vi.fn(() => mockUser),
}));

vi.mock("@/services/breakglassSession", () => ({
  default: class MockBreakglassSessionService {
    getSessionStatus = mockGetSessionStatus;
    approveReview = mockApproveReview;
    rejectReview = mockRejectReview;
    dropSession = mockDropSession;
    cancelSession = mockCancelSession;
  },
}));

vi.mock("@/services/toast", () => ({
  pushError: vi.fn(),
  pushSuccess: vi.fn(),
}));

vi.mock("@/services/logger", () => ({
  debug: vi.fn(),
  handleAxiosError: vi.fn(),
}));

vi.mock("@/utils/currentTime", () => ({
  default: () => ref(Date.now()),
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

const BreakglassSessionCardStub = {
  props: ["breakglass", "currentUserEmail"],
  emits: ["review"],
  template:
    '<button type="button" data-testid="review-card" @click="$emit(\'review\')">Review <span data-testid="session-card-email">{{ currentUserEmail }}</span></button>',
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

describe("BreakglassSessionReview", () => {
  const mockAuth = {
    user: mockUser,
    token: ref("token"),
    isAuthenticated: ref(true),
  };

  beforeEach(() => {
    mockUser.value = { email: "reviewer@example.com", expired: false };
    mockGetSessionStatus.mockResolvedValue({ status: 200, data: [] });
    mockApproveReview.mockResolvedValue({ status: 200 });
    mockRejectReview.mockResolvedValue({ status: 200 });
    mockDropSession.mockResolvedValue({ status: 200 });
    mockCancelSession.mockResolvedValue({ status: 200 });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  const createWrapper = async (path = "/review") => {
    const router = createRouter({
      history: createMemoryHistory(),
      routes: [{ path: "/review", component: BreakglassSessionReview }],
    });

    await router.push(path);
    await router.isReady();

    const wrapper = mount(BreakglassSessionReview, {
      global: {
        plugins: [router],
        provide: {
          [AuthKey as symbol]: mockAuth,
        },
        stubs: {
          BreakglassSessionCard: BreakglassSessionCardStub,
          ApprovalModalContent: ApprovalModalContentStub,
          "scale-button": true,
          "scale-checkbox": true,
          "scale-text-field": true,
          "scale-modal": ScaleModalStub,
        },
      },
    });

    await flushPromises();
    return wrapper;
  };

  it("loads sessions on mount when user is authenticated", async () => {
    await createWrapper();

    expect(mockGetSessionStatus).toHaveBeenCalledTimes(1);
    expect(mockGetSessionStatus).toHaveBeenCalledWith({
      name: undefined,
      cluster: undefined,
      user: undefined,
      group: undefined,
      mine: true,
      approver: false,
    });
  });

  it("uses approver mode params when route query has approver=true", async () => {
    await createWrapper("/review?approver=true&name=session-1");

    expect(mockGetSessionStatus).toHaveBeenCalledWith(
      expect.objectContaining({
        name: "session-1",
        mine: false,
        approver: true,
      }),
    );
  });

  it("does not fetch sessions and hides page when user is unauthenticated", async () => {
    mockUser.value = null;

    const wrapper = await createWrapper();

    expect(mockGetSessionStatus).not.toHaveBeenCalled();
    expect(wrapper.find('[data-testid="session-review-page"]').exists()).toBe(false);
  });

  it("keeps the review modal mounted while approval is in flight", async () => {
    const session = {
      metadata: { name: "session-1" },
      spec: { user: "requester@example.com", grantedGroup: "admin", cluster: "cluster-a" },
      status: { state: "Active" },
    };
    const approval = deferred<{ status: number }>();
    mockGetSessionStatus
      .mockResolvedValueOnce({ status: 200, data: [session] })
      .mockResolvedValue({ status: 200, data: [] });
    mockApproveReview.mockReturnValueOnce(approval.promise);

    const wrapper = await createWrapper();

    await wrapper.find('[data-testid="review-card"]').trigger("click");
    const modal = wrapper.find('[data-testid="review-modal"]');
    expect(modal.exists()).toBe(true);

    await wrapper.find('[data-testid="modal-approve"]').trigger("click");
    modal.element.dispatchEvent(new CustomEvent("scale-close", { bubbles: true, cancelable: true }));
    await nextTick();
    document.dispatchEvent(new KeyboardEvent("keydown", { key: "Escape", bubbles: true, cancelable: true }));

    expect(wrapper.find('[data-testid="approval-modal-content"]').exists()).toBe(true);

    approval.resolve({ status: 200 });
    await flushPromises();

    expect(vi.mocked(pushSuccess)).toHaveBeenCalledWith("Approved session for requester@example.com");
    expect(wrapper.find('[data-testid="approval-modal-content"]').exists()).toBe(false);
  });

  it("passes profile email to session cards for owner actions", async () => {
    mockUser.value = {
      profile: {
        email: "owner@example.com",
        preferred_username: "owner",
      },
      expired: false,
    };
    mockGetSessionStatus.mockResolvedValueOnce({
      status: 200,
      data: [
        {
          metadata: { name: "owned-active-session" },
          spec: {
            user: "owner@example.com",
            cluster: "prod",
            grantedGroup: "breakglass-admin",
          },
          status: { state: "Active" },
        },
      ],
    });

    const wrapper = await createWrapper();

    expect(wrapper.find('[data-testid="session-card-email"]').text()).toBe("owner@example.com");
  });
});
