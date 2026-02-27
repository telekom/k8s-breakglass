/**
 * Tests for SessionApprovalView stability behaviors
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mount, flushPromises } from "@vue/test-utils";
import { ref } from "vue";
import SessionApprovalView from "@/views/SessionApprovalView.vue";
import { AuthKey } from "@/keys";

const mockPush = vi.fn();
const mockLogin = vi.fn();
const mockGetSessionByName = vi.fn();

vi.mock("vue-router", () => ({
  useRoute: () => ({
    params: { sessionName: "session-1" },
    fullPath: "/session/session-1/approve",
  }),
  useRouter: () => ({
    push: mockPush,
  }),
}));

vi.mock("@/services/auth", () => ({
  useUser: vi.fn().mockReturnValue(ref({ expired: false, email: "approver@example.com" })),
}));

vi.mock("@/services/breakglassSession", () => ({
  default: class MockBreakglassSessionService {
    getSessionByName = mockGetSessionByName;
    approveReview = vi.fn();
    rejectReview = vi.fn();
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

describe("SessionApprovalView", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    mockPush.mockReset();
    mockLogin.mockReset();
    mockGetSessionByName.mockReset();
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
});
