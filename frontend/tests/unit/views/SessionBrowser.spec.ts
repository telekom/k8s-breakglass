/**
 * Tests for SessionBrowser view component
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mount, flushPromises, enableAutoUnmount } from "@vue/test-utils";
import { createRouter, createMemoryHistory } from "vue-router";
import { createPinia } from "pinia";
import { ref } from "vue";
import SessionBrowser from "@/views/SessionBrowser.vue";
import { AuthKey } from "@/keys";
import { useSessionBrowserFilters } from "@/stores/sessionBrowserFilters";
import { decideRejectOrWithdraw } from "@/utils/sessionActions";
import { useUser } from "@/services/auth";

enableAutoUnmount(afterEach);

const { mockSearchSessions } = vi.hoisted(() => ({
  mockSearchSessions: vi.fn(),
}));

// Mock services
vi.mock("@/services/breakglass", () => ({
  default: class MockBreakglassService {
    searchSessions = mockSearchSessions;
    rejectSession = vi.fn().mockResolvedValue({});
    withdrawSession = vi.fn().mockResolvedValue({});
  },
}));

vi.mock("@/services/breakglassSession", () => ({
  default: class MockBreakglassSessionService {
    dropSession = vi.fn().mockResolvedValue({});
  },
}));

vi.mock("@/services/toast", () => ({
  pushError: vi.fn(),
  pushSuccess: vi.fn(),
  reportError: vi.fn(),
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

vi.mock("@/utils/sessionFilters", async (importOriginal) => ({
  ...(await importOriginal<typeof import("@/utils/sessionFilters")>()),
  describeApprover: vi.fn().mockReturnValue("Approved by admin"),
}));

vi.mock("@/utils/sessionActions", () => ({
  decideRejectOrWithdraw: vi.fn().mockReturnValue("reject"),
}));

vi.mock("@/utils/statusStyles", () => ({
  statusToneFor: vi.fn().mockReturnValue("success"),
  statusDescriptionFor: vi.fn().mockReturnValue(""),
}));

vi.mock("@/composables", async (importOriginal) => {
  const original = (await importOriginal()) as Record<string, unknown>;
  return {
    ...original,
    useWithdrawConfirmation: () => ({
      withdrawDialogOpen: ref(false),
      withdrawTarget: ref(null),
      requestWithdraw: vi.fn(),
      confirmWithdraw: vi.fn(),
      cancelWithdraw: vi.fn(),
    }),
  };
});

describe("SessionBrowser", () => {
  let router: ReturnType<typeof createRouter>;

  const mockAuth = {
    user: ref({ email: "test@example.com" }),
    token: ref("test-token"),
    isAuthenticated: ref(true),
    getAccessToken: vi.fn().mockResolvedValue("test-token"),
  };

  beforeEach(() => {
    // The filter store persists state in sessionStorage; isolate each case so
    // a debounced name filter from an earlier test cannot narrow this fixture.
    window.sessionStorage.clear();
    vi.mocked(decideRejectOrWithdraw).mockReturnValue("reject");
    vi.mocked(useUser).mockReturnValue(
      ref({ profile: { email: "test@example.com", preferred_username: "testuser" } }) as ReturnType<typeof useUser>,
    );
    mockSearchSessions.mockResolvedValue([
      {
        metadata: { name: "session-1", namespace: "default" },
        spec: {
          user: "user@example.com",
          cluster: "test-cluster",
          escalatedGroup: "admin-group",
          duration: "2h",
        },
        status: {
          state: "approved",
          startedAt: new Date().toISOString(),
          expiresAt: new Date(Date.now() + 7200000).toISOString(),
        },
      },
      {
        metadata: { name: "session-2", namespace: "default" },
        spec: {
          user: "admin@example.com",
          cluster: "prod-cluster",
          escalatedGroup: "superadmin",
          duration: "1h",
        },
        status: {
          state: "pending",
          timeoutAt: new Date(Date.now() + 3600000).toISOString(),
        },
      },
    ]);
    router = createRouter({
      history: createMemoryHistory(),
      routes: [{ path: "/sessions", name: "sessions", component: SessionBrowser }],
    });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  const createWrapper = async () => {
    await router.push("/sessions");
    await router.isReady();

    const pinia = createPinia();
    const wrapper = mount(SessionBrowser, {
      global: {
        plugins: [router, pinia],
        stubs: {
          EmptyState: true,
          ReasonPanel: true,
          TimelineGrid: true,
          PageHeader: true,
          LoadingState: true,
          SessionCard: true,
          "scale-text-field": true,
          "scale-checkbox": true,
          "scale-button": true,
          "scale-dropdown-select": true,
          "scale-dropdown-select-item": true,
          "scale-tag": true,
          "scale-card": true,
          "scale-divider": true,
        },
        provide: {
          [AuthKey as symbol]: mockAuth,
        },
      },
    });

    await flushPromises();
    return wrapper;
  };

  describe("Initial State", () => {
    it("renders the component", async () => {
      const wrapper = await createWrapper();
      expect(wrapper.exists()).toBe(true);
    });

    it("mounts without throwing errors", async () => {
      expect(async () => {
        await createWrapper();
      }).not.toThrow();
    });

    it("has proper DOM structure", async () => {
      const wrapper = await createWrapper();
      expect(wrapper.element.tagName).toBeDefined();
    });

    it("announces result counts without replacing the heading semantics", async () => {
      const wrapper = await createWrapper();
      const heading = wrapper.find('[data-testid="results-section"] h2');
      const status = wrapper.find('[data-testid="session-results-status"]');

      expect(heading.text()).toBe("Results (2)");
      expect(status.exists()).toBe(true);
      expect(status.attributes("role")).toBe("status");
      expect(status.attributes("aria-live")).toBe("polite");
      expect(status.attributes("aria-atomic")).toBe("true");
      expect(status.classes()).toContain("sr-only");
      expect(status.text()).toBe("Showing 2 of 2 sessions");
    });

    it("uses singular session text when there is one result", async () => {
      mockSearchSessions.mockResolvedValue([
        {
          metadata: { name: "session-1", namespace: "default" },
          spec: {
            user: "user@example.com",
            cluster: "test-cluster",
            escalatedGroup: "admin-group",
            duration: "2h",
          },
          status: {
            state: "approved",
            startedAt: new Date().toISOString(),
            expiresAt: new Date(Date.now() + 7200000).toISOString(),
          },
        },
      ]);

      const wrapper = await createWrapper();
      const status = wrapper.find('[data-testid="session-results-status"]');

      expect(status.text()).toBe("Showing 1 of 1 session");
    });

    it("omits the result count when the search failed", async () => {
      mockSearchSessions.mockRejectedValue(new Error("Request failed with status code 500"));

      const wrapper = await createWrapper();

      expect(wrapper.find('[data-testid="results-section"] h2').text()).toBe("Results");
      expect(wrapper.find('[data-testid="session-results-status"]').exists()).toBe(false);
    });
  });

  describe("Session name filter", () => {
    const renderedNames = (wrapper: Awaited<ReturnType<typeof createWrapper>>) =>
      wrapper.findAll(".session-name").map((el) => el.text());

    const setNameFilter = async (wrapper: Awaited<ReturnType<typeof createWrapper>>, value: string) => {
      const field = wrapper.find('[data-testid="name-filter"]');
      (field.element as HTMLInputElement).value = value;
      await field.trigger("scale-change");
    };

    const applyFilters = async (wrapper: Awaited<ReturnType<typeof createWrapper>>) => {
      await wrapper.find('[data-testid="apply-filters-button"]').trigger("click");
      await flushPromises();
    };

    it("keeps only sessions whose name matches, ignoring case and surrounding whitespace", async () => {
      const wrapper = await createWrapper();
      expect(renderedNames(wrapper).sort()).toEqual(["session-1", "session-2"]);

      await setNameFilter(wrapper, "  SESSION-2 ");
      await applyFilters(wrapper);

      expect(renderedNames(wrapper)).toEqual(["session-2"]);
      expect(wrapper.find('[data-testid="results-section"] h2').text()).toBe("Results (1)");
    });

    it("shows every session again once the name filter is cleared", async () => {
      const wrapper = await createWrapper();
      await setNameFilter(wrapper, "session-1");
      await applyFilters(wrapper);
      expect(renderedNames(wrapper)).toEqual(["session-1"]);

      await setNameFilter(wrapper, "");
      await applyFilters(wrapper);

      expect(renderedNames(wrapper).sort()).toEqual(["session-1", "session-2"]);
    });

    it("filters by the submitted name even if the input changes while loading", async () => {
      const wrapper = await createWrapper();
      const sessions = await mockSearchSessions.mock.results[0]!.value;
      const pending: Array<(value: unknown) => void> = [];
      mockSearchSessions.mockImplementation(() => new Promise((r) => pending.push(r)));

      await setNameFilter(wrapper, "session-1");
      await wrapper.find('[data-testid="apply-filters-button"]').trigger("click");
      await setNameFilter(wrapper, "session-2");
      expect(pending.length).toBeGreaterThan(0);
      pending.forEach((resolve) => resolve(sessions));
      await flushPromises();

      expect(renderedNames(wrapper)).toEqual(["session-1"]);
    });
  });

  it("uses server approvedByMe metadata for the list filter", async () => {
    // The component queries each selected state independently. Return the
    // fixture for every request so the test exercises the client-side
    // approvedByMe filter instead of leaving later state queries undefined.
    mockSearchSessions.mockResolvedValue([
      {
        metadata: { name: "approved" },
        spec: { user: "oidc:opaque" },
        approvedByMe: true,
        status: { state: "Approved" },
      },
      {
        metadata: { name: "other" },
        spec: { user: "oidc:other" },
        approvedByMe: false,
        status: { state: "Approved" },
      },
    ]);
    const wrapper = await createWrapper();
    const filters = useSessionBrowserFilters();
    filters.filters.onlyApprovedByMe = true;
    await flushPromises();

    expect(wrapper.findAll(".session-name").map((item) => item.text())).toEqual(["approved"]);
    expect(wrapper.get('[data-testid="filter-approved-by-me"]').attributes("disabled") ?? "false").toBe("false");
  });

  it.each([false, true])("uses server metadata and legacy fallback with email available: %s", async (hasEmail) => {
    vi.mocked(useUser).mockReturnValue(
      ref({ profile: hasEmail ? { email: "admin@example.com" } : {} }) as ReturnType<typeof useUser>,
    );
    mockSearchSessions.mockResolvedValueOnce([
      {
        metadata: { name: "explicit-true" },
        approvedByMe: true,
        spec: { user: "opaque:true" },
        status: { state: "Approved" },
      },
      {
        metadata: { name: "explicit-false" },
        approvedByMe: false,
        spec: { user: "opaque:false" },
        status: { state: "Approved", approver: "admin@example.com" },
      },
      {
        metadata: { name: "legacy-fallback" },
        spec: { user: "legacy:true" },
        status: { state: "Approved", approver: "admin@example.com" },
      },
    ]);

    const wrapper = await createWrapper();
    const filters = useSessionBrowserFilters();
    filters.filters.onlyApprovedByMe = true;
    await flushPromises();

    expect(wrapper.findAll(".session-name").map((item) => item.text())).toEqual(
      hasEmail ? ["explicit-true", "legacy-fallback"] : ["explicit-true"],
    );
    expect(wrapper.get('[data-testid="filter-approved-by-me"]').attributes("disabled") ?? "false").toBe("false");
  });

  it("uses server ownership metadata for card actions with an opaque username", async () => {
    mockSearchSessions.mockResolvedValueOnce([
      {
        metadata: { name: "owned" },
        spec: { user: "oidc:opaque" },
        approvalMeta: {
          canApprove: false,
          canReject: false,
          isRequester: true,
          isApprover: false,
          sessionState: "Approved",
        },
        status: { state: "Approved", expiresAt: new Date(Date.now() + 7200000).toISOString() },
      },
    ]);
    vi.mocked(decideRejectOrWithdraw).mockReturnValue("withdraw");
    const wrapper = await createWrapper();

    expect(wrapper.find('[data-testid="session-actions"]').text()).toContain("Drop");
  });

  describe("Component Lifecycle", () => {
    it("unmounts cleanly", async () => {
      const wrapper = await createWrapper();
      expect(() => wrapper.unmount()).not.toThrow();
    });

    it("can be remounted", async () => {
      const wrapper1 = await createWrapper();
      wrapper1.unmount();

      const wrapper2 = await createWrapper();
      expect(wrapper2.exists()).toBe(true);
    });
  });
});
