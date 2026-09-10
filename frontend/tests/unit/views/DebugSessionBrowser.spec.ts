/**
 * Tests for DebugSessionBrowser view component
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mount, flushPromises } from "@vue/test-utils";
import { createRouter, createMemoryHistory } from "vue-router";
import { ref } from "vue";
import DebugSessionBrowser from "@/views/DebugSessionBrowser.vue";
import DebugSessionCard from "@/components/DebugSessionCard.vue";
import { AuthKey } from "@/keys";

const mockListSessions = vi.fn().mockResolvedValue({
  sessions: [
    {
      name: "debug-session-1",
      namespace: "default",
      cluster: "test-cluster",
      state: "Active",
      templateRef: "standard-debug",
      requestedBy: "user@example.com",
      createdAt: new Date().toISOString(),
    },
    {
      name: "debug-session-2",
      namespace: "default",
      cluster: "prod-cluster",
      state: "Pending",
      templateRef: "elevated-debug",
      requestedBy: "admin@example.com",
      createdAt: new Date().toISOString(),
    },
  ],
});
const mockJoinSession = vi.fn().mockResolvedValue({});

// Mock debug session service
vi.mock("@/services/debugSession", () => ({
  default: class MockDebugSessionService {
    listSessions = mockListSessions;
    joinSession = mockJoinSession;
    terminateSession = vi.fn().mockResolvedValue({});
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

describe("DebugSessionBrowser", () => {
  let router: ReturnType<typeof createRouter>;

  const mockAuth = {
    user: ref({ email: "test@example.com" }),
    token: ref("test-token"),
    isAuthenticated: ref(true),
    getAccessToken: vi.fn().mockResolvedValue("test-token"),
  };

  beforeEach(() => {
    mockListSessions.mockClear();
    mockJoinSession.mockClear();
    router = createRouter({
      history: createMemoryHistory(),
      routes: [
        { path: "/debug-sessions", name: "debug-sessions", component: DebugSessionBrowser },
        { path: "/debug-sessions/create", name: "debug-create", component: { template: "<div />" } },
        { path: "/debug-sessions/:name", name: "debug-details", component: { template: "<div />" } },
      ],
    });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  const createWrapper = async () => {
    await router.push("/debug-sessions");
    await router.isReady();

    const wrapper = mount(DebugSessionBrowser, {
      global: {
        plugins: [router],
        stubs: {
          PageHeader: true,
          LoadingState: true,
          EmptyState: true,
          DebugSessionCard: {
            inheritAttrs: false,
            props: ["session"],
            emits: ["join"],
            template: '<button :data-testid="`join-${session.name}`" @click="$emit(`join`)">Join</button>',
          },
          "scale-text-field": true,
          "scale-checkbox": true,
          "scale-button": true,
          "scale-dropdown-select": true,
          "scale-dropdown-select-option": true,
        },
        provide: {
          [AuthKey as symbol]: mockAuth,
        },
      },
    });

    await flushPromises();
    return wrapper;
  };

  describe("Initial Loading", () => {
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

    it("renders the refresh button as an accessible icon-only Scale button", async () => {
      const wrapper = await createWrapper();
      const refreshButton = wrapper.find('[data-testid="refresh-button"]');

      expect(refreshButton.exists()).toBe(true);
      expect(refreshButton.attributes("icon-only")).toBe("true");
      expect(refreshButton.attributes("inner-aria-label")).toBe("Refresh debug sessions");
      expect(refreshButton.classes()).toContain("ui-toolbar-icon-control");
    });

    it("announces filtered result counts as a status update", async () => {
      const wrapper = await createWrapper();
      const status = wrapper.find('[data-testid="debug-session-results-status"]');

      expect(status.exists()).toBe(true);
      expect(status.attributes("role")).toBe("status");
      expect(status.attributes("aria-live")).toBe("polite");
      expect(status.attributes("aria-atomic")).toBe("true");
      expect(status.text()).toBe("Showing 2 of 2 debug sessions");
    });

    it("uses singular debug session text when there is one result", async () => {
      mockListSessions.mockResolvedValueOnce({
        sessions: [
          {
            name: "debug-session-1",
            namespace: "default",
            cluster: "test-cluster",
            state: "Active",
            templateRef: "standard-debug",
            requestedBy: "user@example.com",
            createdAt: new Date().toISOString(),
          },
        ],
      });

      const wrapper = await createWrapper();
      const status = wrapper.find('[data-testid="debug-session-results-status"]');

      expect(status.text()).toBe("Showing 1 of 1 debug session");
    });

    it("shows an error state when loading debug sessions fails", async () => {
      mockListSessions.mockRejectedValueOnce(new Error("debug list down"));

      const wrapper = await createWrapper();
      const errorState = wrapper.findComponent({ name: "EmptyState" });

      expect(errorState.exists()).toBe(true);
      expect(errorState.props("variant")).toBe("error");
      expect(errorState.props("description")).toBe("debug list down");
      expect(wrapper.find('[data-testid="debug-session-results-status"]').exists()).toBe(false);
    });

    it("joins sessions as a viewer", async () => {
      const wrapper = await createWrapper();
      await vi.waitFor(() => {
        expect(wrapper.find('[data-testid="join-debug-session-1"]').exists()).toBe(true);
      });

      await wrapper.find('[data-testid="join-debug-session-1"]').trigger("click");
      await flushPromises();

      expect(mockJoinSession).toHaveBeenCalledWith("debug-session-1");
    });

    it("renders rejected sessions through the state filter without active-session actions", async () => {
      mockListSessions.mockResolvedValueOnce({
        sessions: [
          {
            name: "rejected-session",
            namespace: "default",
            cluster: "test-cluster",
            state: "Rejected",
            templateRef: "standard-debug",
            requestedBy: "test@example.com",
            statusMessage: "Rejected by approver",
          },
        ],
      });

      await router.push("/debug-sessions");
      await router.isReady();
      const wrapper = mount(DebugSessionBrowser, {
        global: {
          plugins: [router],
          provide: {[AuthKey as symbol]: mockAuth},
          stubs: {
            PageHeader: true,
            LoadingState: true,
            EmptyState: true,
            DebugSessionCard,
            "scale-button": {
              inheritAttrs: false,
              template: '<button v-bind="$attrs"><slot /></button>',
            },
            "scale-tag": {template: '<span v-bind="$attrs"><slot /></span>'},
            "scale-text-field": true,
            "scale-checkbox": true,
            "scale-modal": true,
            "scale-dropdown-select": true,
            "scale-dropdown-select-item": true,
            "scale-icon-alert-error": true,
          },
        },
      });

      await flushPromises();
      expect(wrapper.find('[data-testid="debug-sessions-empty-state"]').exists()).toBe(true);

      const rejectedFilter = wrapper.find('[data-testid="state-filter-Rejected"]');
      Object.defineProperty(rejectedFilter.element, "checked", {value: true, configurable: true});
      await rejectedFilter.trigger("scale-change");
      await flushPromises();

      const card = wrapper.find(".debug-session-card");
      expect(card.exists()).toBe(true);
      expect(card.find('[data-testid="session-state"]').text()).toBe("Rejected");
      expect(card.find('[data-testid="status-message"]').text()).toContain("Rejected by approver");
      expect(card.find('[data-testid="join-button"]').exists()).toBe(false);
      expect(card.find('[data-testid="leave-button"]').exists()).toBe(false);
      expect(card.find('[data-testid="renew-button"]').exists()).toBe(false);
      expect(card.find('[data-testid="terminate-button"]').exists()).toBe(false);
      expect(card.find('[data-testid="approve-button"]').exists()).toBe(false);
      expect(card.find('[data-testid="reject-button"]').exists()).toBe(false);
    });
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
