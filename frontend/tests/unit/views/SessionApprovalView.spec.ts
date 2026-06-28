/**
 * Tests for SessionApprovalView stability behaviors
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mount, flushPromises, enableAutoUnmount } from "@vue/test-utils";
import { reactive, ref } from "vue";
import SessionApprovalView from "@/views/SessionApprovalView.vue";
import { AuthKey } from "@/keys";
import { pushError, pushSuccess } from "@/services/toast";

const mockPush = vi.fn();
const mockLogin = vi.fn();
const mockGetSessionByName = vi.fn();
const mockApproveReview = vi.fn();
const mockRejectReview = vi.fn();
const mockUser = ref<{ expired?: boolean; email: string } | null>({ expired: false, email: "approver@example.com" });
const mockRoute = reactive({
  params: { sessionName: "session-1" },
  fullPath: "/session/session-1/approve",
});

vi.mock("vue-router", () => ({
  useRoute: () => mockRoute,
  useRouter: () => ({
    push: mockPush,
  }),
}));

vi.mock("@/services/auth", () => ({
  useUser: vi.fn(() => mockUser),
}));

vi.mock("@/services/breakglassSession", () => ({
  default: class MockBreakglassSessionService {
    getSessionByName = mockGetSessionByName;
    approveReview = mockApproveReview;
    rejectReview = mockRejectReview;
  },
}));

vi.mock("@/services/toast", () => ({
  pushError: vi.fn(),
  pushSuccess: vi.fn(),
}));

vi.mock("@/services/logger", () => ({
  debug: vi.fn(),
  error: vi.fn(),
  handleAxiosError: vi.fn().mockReturnValue({ message: "error" }),
}));

enableAutoUnmount(afterEach);

describe("SessionApprovalView", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    mockPush.mockReset();
    mockLogin.mockReset();
    mockGetSessionByName.mockReset();
    mockApproveReview.mockReset();
    mockRejectReview.mockReset();
    mockUser.value = { expired: false, email: "approver@example.com" };
    mockRoute.params.sessionName = "session-1";
    mockRoute.fullPath = "/session/session-1/approve";
  });

  afterEach(() => {
    vi.runOnlyPendingTimers();
    vi.useRealTimers();
    vi.clearAllMocks();
  });

  it("throws when Auth provider is missing", () => {
    expect(() =>
      mount(SessionApprovalView, {
        global: {
          stubs: {
            ApprovalModalContent: true,
            "scale-loading-spinner": true,
            "scale-notification": true,
            "scale-icon-action-circle-close": true,
            "scale-icon-user-file-forbidden": true,
            "scale-button": true,
          },
        },
      }),
    ).toThrow("SessionApprovalView requires an Auth provider");
  });

  it("clears pending redirect timer on unmount after 401 load failure", async () => {
    mockGetSessionByName.mockRejectedValue({ response: { status: 401 } });

    const wrapper = mount(SessionApprovalView, {
      global: {
        provide: {
          [AuthKey as symbol]: {
            login: mockLogin,
            logout: vi.fn(),
          },
        },
        stubs: {
          ApprovalModalContent: true,
          "scale-loading-spinner": true,
          "scale-notification": true,
          "scale-icon-action-circle-close": true,
          "scale-icon-user-file-forbidden": true,
          "scale-button": true,
        },
      },
    });

    await flushPromises();

    // Verify the 401 error path was triggered (session fetch attempted)
    expect(mockGetSessionByName).toHaveBeenCalledTimes(1);

    wrapper.unmount();
    vi.advanceTimersByTime(3500);

    expect(mockPush).not.toHaveBeenCalled();
  });

  it("redirects after 401 load failure when component remains mounted", async () => {
    mockGetSessionByName.mockRejectedValue({ response: { status: 401 } });

    mount(SessionApprovalView, {
      global: {
        provide: {
          [AuthKey as symbol]: {
            login: mockLogin,
            logout: vi.fn(),
          },
        },
        stubs: {
          ApprovalModalContent: true,
          "scale-loading-spinner": true,
          "scale-notification": true,
          "scale-icon-action-circle-close": true,
          "scale-icon-user-file-forbidden": true,
          "scale-button": true,
        },
      },
    });

    await flushPromises();

    vi.advanceTimersByTime(3500);

    expect(mockPush).toHaveBeenCalled();
  });

  it("does not approve or reject direct approval links when a required note is empty", async () => {
    mockGetSessionByName.mockResolvedValue({
      data: {
        session: {
          metadata: { name: "session-1" },
          spec: {
            user: "requester@example.com",
            cluster: "prod",
            grantedGroup: "cluster-admin",
            approvalReasonConfig: {
              mandatory: true,
              description: "Document the incident ticket",
            },
          },
          status: { state: "pending" },
        },
        approvalMeta: {
          canApprove: true,
          canReject: true,
          isRequester: false,
          isApprover: true,
          sessionState: "pending",
        },
      },
    });

    const wrapper = mount(SessionApprovalView, {
      global: {
        provide: {
          [AuthKey as symbol]: {
            login: mockLogin,
            logout: vi.fn(),
          },
        },
        stubs: {
          ApprovalModalContent: {
            template: `
              <button data-testid="emit-approve" @click="$emit('approve')">Approve</button>
              <button data-testid="emit-reject" @click="$emit('reject')">Reject</button>
            `,
          },
          "scale-loading-spinner": true,
          "scale-notification": true,
          "scale-icon-action-circle-close": true,
          "scale-icon-user-file-forbidden": true,
          "scale-button": true,
        },
      },
    });

    await flushPromises();
    await wrapper.find('[data-testid="emit-approve"]').trigger("click");
    await wrapper.find('[data-testid="emit-reject"]').trigger("click");

    expect(mockApproveReview).not.toHaveBeenCalled();
    expect(mockRejectReview).not.toHaveBeenCalled();
    expect(pushError).toHaveBeenCalledTimes(2);
    expect(pushError).toHaveBeenNthCalledWith(1, "Approval note is required for this escalation");
    expect(pushError).toHaveBeenNthCalledWith(2, "Approval note is required for this escalation");
  });

  it("reloads session data when navigating between approval links in the same component", async () => {
    mockGetSessionByName
      .mockResolvedValueOnce(approvalResponse("session-1", "requester-1@example.com"))
      .mockResolvedValueOnce(approvalResponse("session-2", "requester-2@example.com"));

    const wrapper = mount(SessionApprovalView, {
      global: {
        provide: {
          [AuthKey as symbol]: {
            login: mockLogin,
            logout: vi.fn(),
          },
        },
        stubs: {
          ApprovalModalContent: {
            props: ["session"],
            template: '<div data-testid="approval-session">{{ session.metadata.name }} {{ session.spec.user }}</div>',
          },
          "scale-loading-spinner": true,
          "scale-notification": true,
          "scale-icon-action-circle-close": true,
          "scale-icon-user-file-forbidden": true,
          "scale-button": true,
        },
      },
    });

    await flushPromises();
    expect(mockGetSessionByName).toHaveBeenCalledWith("session-1");
    expect(wrapper.find('[data-testid="approval-session"]').text()).toContain("session-1 requester-1@example.com");

    mockRoute.params.sessionName = "session-2";
    mockRoute.fullPath = "/session/session-2/approve";
    await flushPromises();
    await flushPromises();

    expect(mockGetSessionByName).toHaveBeenCalledWith("session-2");
    await vi.waitFor(() => {
      expect(wrapper.find('[data-testid="approval-session"]').text()).toContain("session-2 requester-2@example.com");
    });
  });

  it("clears stale session data and preserves the new route when auth expires before navigation", async () => {
    mockGetSessionByName.mockResolvedValueOnce(approvalResponse("session-1", "requester-1@example.com"));

    const wrapper = mount(SessionApprovalView, {
      global: {
        provide: {
          [AuthKey as symbol]: {
            login: mockLogin,
            logout: vi.fn(),
          },
        },
        stubs: {
          ApprovalModalContent: {
            props: ["session"],
            template: '<div data-testid="approval-session">{{ session.metadata.name }} {{ session.spec.user }}</div>',
          },
          "scale-loading-spinner": true,
          "scale-notification": true,
          "scale-icon-action-circle-close": true,
          "scale-icon-user-file-forbidden": true,
          "scale-button": true,
        },
      },
    });

    await flushPromises();
    expect(wrapper.find('[data-testid="approval-session"]').text()).toContain("session-1 requester-1@example.com");

    mockUser.value = { expired: true, email: "approver@example.com" };
    mockRoute.params.sessionName = "session-2";
    mockRoute.fullPath = "/session/session-2/approve";
    await flushPromises();
    await flushPromises();

    expect(mockGetSessionByName).toHaveBeenCalledTimes(1);
    expect(mockLogin).toHaveBeenCalledWith({ path: "/session/session-2/approve" });
    expect(wrapper.find('[data-testid="approval-session"]').exists()).toBe(false);
    expect(wrapper.text()).toContain("Loading session");
  });

  it("ignores stale approval success after navigating to another approval link", async () => {
    let resolveApprove!: () => void;
    mockGetSessionByName
      .mockResolvedValueOnce(approvalResponse("session-1", "requester-1@example.com"))
      .mockResolvedValueOnce(approvalResponse("session-2", "requester-2@example.com"));
    mockApproveReview.mockReturnValue(
      new Promise<void>((resolve) => {
        resolveApprove = resolve;
      }),
    );

    const wrapper = mount(SessionApprovalView, {
      global: {
        provide: {
          [AuthKey as symbol]: {
            login: mockLogin,
            logout: vi.fn(),
          },
        },
        stubs: {
          ApprovalModalContent: {
            props: ["session"],
            template: `
              <div>
                <div data-testid="approval-session">{{ session.metadata.name }} {{ session.spec.user }}</div>
                <button data-testid="emit-approve" @click="$emit('approve')">Approve</button>
              </div>
            `,
          },
          "scale-loading-spinner": true,
          "scale-notification": true,
          "scale-icon-action-circle-close": true,
          "scale-icon-user-file-forbidden": true,
          "scale-button": true,
        },
      },
    });

    await flushPromises();
    await wrapper.find('[data-testid="emit-approve"]').trigger("click");
    expect(mockApproveReview).toHaveBeenCalledWith(
      expect.objectContaining({
        name: "session-1",
      }),
    );

    mockRoute.params.sessionName = "session-2";
    mockRoute.fullPath = "/session/session-2/approve";
    await flushPromises();
    await flushPromises();

    resolveApprove();
    await flushPromises();

    expect(pushSuccess).not.toHaveBeenCalled();
    expect(mockPush).not.toHaveBeenCalledWith("/sessions");
    await vi.waitFor(() => {
      expect(wrapper.find('[data-testid="approval-session"]').text()).toContain("session-2 requester-2@example.com");
    });
  });
});

function approvalResponse(name: string, requester: string) {
  return {
    data: {
      session: {
        metadata: { name },
        spec: {
          user: requester,
          cluster: "prod",
          grantedGroup: "cluster-admin",
        },
        status: { state: "pending" },
      },
      approvalMeta: {
        canApprove: true,
        canReject: true,
        isRequester: false,
        isApprover: true,
        sessionState: "pending",
      },
    },
  };
}
