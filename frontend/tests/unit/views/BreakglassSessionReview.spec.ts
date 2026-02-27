/**
 * Component-level tests for BreakglassSessionReview
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mount, flushPromises } from "@vue/test-utils";
import { createRouter, createMemoryHistory } from "vue-router";
import { ref } from "vue";
import BreakglassSessionReview from "@/views/BreakglassSessionReview.vue";
import { AuthKey } from "@/keys";

const mockGetSessionStatus = vi.fn();
const mockApproveReview = vi.fn();
const mockRejectReview = vi.fn();
const mockDropSession = vi.fn();
const mockCancelSession = vi.fn();

const mockUser = ref<{ email: string; expired?: boolean } | null>(null);

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
          BreakglassSessionCard: true,
          ApprovalModalContent: true,
          "scale-button": true,
          "scale-checkbox": true,
          "scale-text-field": true,
          "scale-modal": true,
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
});
