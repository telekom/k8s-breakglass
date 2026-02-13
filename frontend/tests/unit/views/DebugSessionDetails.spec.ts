/**
 * Tests for DebugSessionDetails polling behavior
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { shallowMount, flushPromises } from "@vue/test-utils";
import DebugSessionDetails from "@/views/DebugSessionDetails.vue";
import { AuthKey } from "@/keys";

const mockPush = vi.fn();
const mockGetSession = vi.fn();

vi.mock("vue-router", () => ({
  useRoute: () => ({
    params: { name: "dbg-1" },
  }),
  useRouter: () => ({
    push: mockPush,
  }),
}));

vi.mock("@/services/debugSession", () => ({
  default: class MockDebugSessionService {
    getSession = mockGetSession;
    joinSession = vi.fn();
    leaveSession = vi.fn();
    terminateSession = vi.fn();
    renewSession = vi.fn();
    approveSession = vi.fn();
    rejectSession = vi.fn();
    injectEphemeralContainer = vi.fn();
    createPodCopy = vi.fn();
    createNodeDebugPod = vi.fn();
  },
}));

vi.mock("@/services/toast", () => ({
  pushError: vi.fn(),
  pushSuccess: vi.fn(),
}));

describe("DebugSessionDetails", () => {
  beforeEach(() => {
    vi.useFakeTimers();
    mockPush.mockReset();
    mockGetSession.mockReset();
  });

  afterEach(() => {
    vi.runOnlyPendingTimers();
    vi.useRealTimers();
    vi.clearAllMocks();
  });

  it("stops polling when session leaves active/pending states", async () => {
    mockGetSession
      .mockResolvedValueOnce({
        status: { state: "Active" },
        metadata: { name: "dbg-1" },
        spec: { cluster: "test-cluster" },
      })
      .mockResolvedValueOnce({
        status: { state: "Terminated" },
        metadata: { name: "dbg-1" },
        spec: { cluster: "test-cluster" },
      });

    shallowMount(DebugSessionDetails, {
      global: {
        provide: {
          [AuthKey as symbol]: {
            login: vi.fn(),
            logout: vi.fn(),
            getAccessToken: vi.fn(),
            userManager: { signinSilent: vi.fn() },
          },
        },
      },
    });

    await flushPromises();
    expect(mockGetSession).toHaveBeenCalledTimes(1);

    vi.advanceTimersByTime(10000);
    await flushPromises();
    expect(mockGetSession).toHaveBeenCalledTimes(2);

    vi.advanceTimersByTime(30000);
    await flushPromises();
    expect(mockGetSession).toHaveBeenCalledTimes(2);
    expect(vi.getTimerCount()).toBe(0);
  });
});
