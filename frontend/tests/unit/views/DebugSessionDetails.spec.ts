/**
 * Tests for DebugSessionDetails polling behavior
 *
 * @vitest-environment jsdom
 */

import { ref } from "vue";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { shallowMount, mount, flushPromises } from "@vue/test-utils";
import DebugSessionDetails from "@/views/DebugSessionDetails.vue";
import { AuthKey } from "@/keys";

const mockPush = vi.fn();
const mockGetSession = vi.fn();
const mockCopy = vi.fn().mockResolvedValue(true);
const mockCleanup = vi.fn();
const mockCopied = ref(false);

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

vi.mock("@/services/auth", () => ({
  useUser: vi.fn().mockReturnValue(
    ref({
      profile: {
        email: "test@example.com",
        preferred_username: "testuser",
      },
    }),
  ),
}));

vi.mock("@/composables", async (importOriginal) => {
  const original = (await importOriginal()) as Record<string, unknown>;
  return {
    ...original,
    useClipboard: () => ({
      copy: mockCopy,
      copied: mockCopied,
      error: ref(null),
      cleanup: mockCleanup,
    }),
  };
});

describe("DebugSessionDetails", () => {
  let wrapper: ReturnType<typeof shallowMount> | null = null;

  beforeEach(() => {
    vi.useFakeTimers();
    mockPush.mockReset();
    mockGetSession.mockReset();
  });

  afterEach(() => {
    wrapper?.unmount();
    wrapper = null;
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

    wrapper = shallowMount(DebugSessionDetails, {
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

  it("renders copy button for each running pod and calls clipboard copy", async () => {
    mockGetSession.mockResolvedValue({
      status: {
        state: "Active",
        allowedPods: [
          { name: "pod-1", namespace: "ns-1", phase: "Running" },
          { name: "pod-2", namespace: "ns-2", phase: "Running" },
        ],
      },
      metadata: { name: "dbg-1" },
      spec: { cluster: "test-cluster" },
    });

    wrapper = mount(DebugSessionDetails, {
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

    const copyBtns = wrapper.findAll('[data-testid="copy-exec-btn"]');
    expect(copyBtns.length).toBe(2);

    // Click first copy button and verify clipboard was called with correct command
    await copyBtns[0].trigger("click");
    expect(mockCopy).toHaveBeenCalledWith("kubectl exec -it pod-1 -n ns-1 -- /bin/sh");
  });

  it("calls clipboardCleanup on unmount", async () => {
    mockGetSession.mockResolvedValue({
      status: { state: "Active" },
      metadata: { name: "dbg-1" },
      spec: { cluster: "test-cluster" },
    });

    wrapper = shallowMount(DebugSessionDetails, {
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
    wrapper.unmount();
    wrapper = null;
    expect(mockCleanup).toHaveBeenCalled();
  });
});
