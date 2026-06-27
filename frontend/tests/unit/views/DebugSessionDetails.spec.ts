/**
 * Tests for DebugSessionDetails polling behavior
 *
 * @vitest-environment jsdom
 */

import { reactive, ref } from "vue";
import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { shallowMount, mount, flushPromises } from "@vue/test-utils";
import DebugSessionDetails from "@/views/DebugSessionDetails.vue";
import { AuthKey } from "@/keys";

const mockPush = vi.fn();
const mockGetSession = vi.fn();
const mockJoinSession = vi.fn();
const mockCopy = vi.fn().mockResolvedValue(true);
const mockCleanup = vi.fn();
const mockCopied = ref(false);
const mockRouteParams = reactive<{ name?: string | string[] }>({ name: "dbg-1" });

vi.mock("vue-router", () => ({
  useRoute: () => ({
    params: mockRouteParams,
  }),
  useRouter: () => ({
    push: mockPush,
  }),
}));

vi.mock("@/services/debugSession", () => ({
  default: class MockDebugSessionService {
    getSession = mockGetSession;
    joinSession = mockJoinSession;
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
    mockJoinSession.mockReset();
    mockRouteParams.name = "dbg-1";
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

  it("reloads details when navigating between debug session route names", async () => {
    mockGetSession.mockImplementation(async (name: string) => ({
      status: { state: "Terminated" },
      metadata: { name },
      spec: { cluster: `cluster-${name}` },
    }));

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
    expect(mockGetSession).toHaveBeenCalledWith("dbg-1");
    expect(wrapper.findComponent({ name: "PageHeader" }).props("title")).toBe("dbg-1");

    mockRouteParams.name = "dbg-2";
    await flushPromises();

    expect(mockGetSession).toHaveBeenCalledWith("dbg-2");
    expect(wrapper.findComponent({ name: "PageHeader" }).props("title")).toBe("dbg-2");
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
    await copyBtns[0]!.trigger("click");
    expect(mockCopy).toHaveBeenCalledWith("kubectl exec -it pod-1 -n ns-1 -- /bin/sh");
  });

  it("shows an error state when loading session details fails", async () => {
    mockGetSession.mockRejectedValueOnce(new Error("detail down"));

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
    const errorState = wrapper.findComponent({ name: "EmptyState" });

    expect(errorState.exists()).toBe(true);
    expect(errorState.props("variant")).toBe("error");
    expect(errorState.props("description")).toBe("detail down");
  });

  it("joins active sessions as a viewer", async () => {
    mockGetSession.mockResolvedValue({
      status: {
        state: "Active",
        participants: [],
      },
      metadata: { name: "dbg-1" },
      spec: {
        cluster: "test-cluster",
        requestedBy: "owner@example.com",
      },
    });
    mockJoinSession.mockResolvedValue({});

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
    await wrapper.find('[data-testid="join-session-button"]').trigger("click");
    await flushPromises();

    expect(mockJoinSession).toHaveBeenCalledWith("dbg-1");
  });

  it("shows approval actions only when the API authorizes them", async () => {
    mockGetSession.mockResolvedValue({
      status: { state: "PendingApproval" },
      metadata: { name: "dbg-1" },
      spec: { cluster: "test-cluster", requestedBy: "owner@example.com" },
      canApprove: true,
      canReject: true,
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

    expect(wrapper.find('[data-testid="approve-session-button"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="reject-session-button"]').exists()).toBe(true);
  });

  it("hides approval actions when the API does not authorize them", async () => {
    mockGetSession.mockResolvedValue({
      status: { state: "PendingApproval" },
      metadata: { name: "dbg-1" },
      spec: { cluster: "test-cluster", requestedBy: "test@example.com" },
      canApprove: false,
      canReject: false,
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

    expect(wrapper.find('[data-testid="approve-session-button"]').exists()).toBe(false);
    expect(wrapper.find('[data-testid="reject-session-button"]').exists()).toBe(false);
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

  it("shows error when route param name is empty", async () => {
    mockRouteParams.name = "";

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
    expect(mockGetSession).not.toHaveBeenCalled();
    // With shallowMount, EmptyState is stubbed; check its attributes
    const html = wrapper.html();
    expect(html).toContain("Missing session name in URL");
  });

  it("shows error when route param name is undefined", async () => {
    (mockRouteParams as Record<string, unknown>).name = undefined;

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
    expect(mockGetSession).not.toHaveBeenCalled();
    const html = wrapper.html();
    expect(html).toContain("Missing session name in URL");
  });

  it("shows error when route param name is an array", async () => {
    (mockRouteParams as Record<string, unknown>).name = ["a", "b"];

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
    expect(mockGetSession).not.toHaveBeenCalled();
    const html = wrapper.html();
    expect(html).toContain("Missing session name in URL");
  });
});
