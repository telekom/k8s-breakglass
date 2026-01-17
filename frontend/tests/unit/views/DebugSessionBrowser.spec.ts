/**
 * Tests for DebugSessionBrowser view component
 *
 * @jest-environment jsdom
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mount, flushPromises } from "@vue/test-utils";
import { createRouter, createMemoryHistory } from "vue-router";
import { ref } from "vue";
import DebugSessionBrowser from "@/views/DebugSessionBrowser.vue";
import { AuthKey } from "@/keys";

// Mock debug session service
vi.mock("@/services/debugSession", () => ({
  default: class MockDebugSessionService {
    listSessions = vi.fn().mockResolvedValue({
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

// Mock common components
const commonStubs = {
  PageHeader: {
    template: '<div class="page-header"><slot /></div>',
    props: ["title", "subtitle", "badge", "badgeVariant"],
  },
  LoadingState: {
    template: '<div class="loading-state">Loading...</div>',
    props: ["message"],
  },
  EmptyState: {
    template: '<div class="empty-state">No sessions</div>',
    props: ["title", "description", "icon"],
  },
  DebugSessionCard: {
    template: '<div class="debug-session-card">{{ session?.name }}</div>',
    props: ["session", "canTerminate", "terminating"],
  },
  "scale-text-field": {
    template: '<input @input="$emit(\'scaleInput\', $event)" />',
  },
  "scale-checkbox": {
    template: '<input type="checkbox" @change="$emit(\'scaleChange\', $event)" />',
    props: ["checked", "label"],
  },
  "scale-button": {
    template: '<button @click="$emit(\'click\')"><slot /></button>',
    props: ["variant", "disabled"],
  },
  "scale-dropdown-select": {
    template: "<select><slot /></select>",
    props: ["value", "label"],
  },
  "scale-dropdown-select-option": {
    template: "<option><slot /></option>",
    props: ["value"],
  },
};

describe("DebugSessionBrowser", () => {
  let router: ReturnType<typeof createRouter>;

  const mockAuth = {
    user: ref({ email: "test@example.com" }),
    token: ref("test-token"),
    isAuthenticated: ref(true),
    getAccessToken: vi.fn().mockResolvedValue("test-token"),
  };

  beforeEach(() => {
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
        stubs: commonStubs,
        provide: {
          [AuthKey as symbol]: mockAuth,
        },
      },
    });

    await flushPromises();
    return wrapper;
  };

  describe("Initial Loading", () => {
    it("shows loading state initially", () => {
      const wrapper = mount(DebugSessionBrowser, {
        global: {
          plugins: [router],
          stubs: commonStubs,
          provide: {
            [AuthKey as symbol]: mockAuth,
          },
        },
      });

      expect(wrapper.vm.loading).toBe(true);
    });

    it("loads sessions on mount", async () => {
      const wrapper = await createWrapper();
      expect(wrapper.vm.loading).toBe(false);
      expect(wrapper.vm.sessions.length).toBe(2);
    });
  });

  describe("Filtering", () => {
    it("initializes with default filter state", async () => {
      const wrapper = await createWrapper();

      expect(wrapper.vm.filters.mine).toBe(true);
      expect(wrapper.vm.filters.states).toContain("Active");
      expect(wrapper.vm.filters.states).toContain("Pending");
      expect(wrapper.vm.filters.states).toContain("PendingApproval");
    });

    it("filters sessions by state", async () => {
      const wrapper = await createWrapper();

      // The computed filteredSessions should filter based on states
      expect(wrapper.vm.filteredSessions).toBeDefined();
    });

    it("filters sessions by search term", async () => {
      const wrapper = await createWrapper();

      wrapper.vm.filters.search = "test-cluster";
      await flushPromises();

      // filteredSessions should filter by search
      const filtered = wrapper.vm.filteredSessions;
      expect(filtered.every((s: any) => 
        s.name.includes("test-cluster") || 
        s.cluster.includes("test-cluster") ||
        s.templateRef.includes("test-cluster") ||
        s.requestedBy.includes("test-cluster")
      )).toBe(true);
    });
  });

  describe("Refresh", () => {
    it("has refresh functionality", async () => {
      const wrapper = await createWrapper();
      expect(typeof wrapper.vm.refresh).toBe("function");
    });

    it("sets refreshing state during refresh", async () => {
      const wrapper = await createWrapper();

      const refreshPromise = wrapper.vm.refresh();
      expect(wrapper.vm.refreshing).toBe(true);

      await refreshPromise;
      expect(wrapper.vm.refreshing).toBe(false);
    });
  });

  describe("User Email", () => {
    it("computes current user email from profile", async () => {
      const wrapper = await createWrapper();
      expect(wrapper.vm.currentUserEmail).toBe("test@example.com");
    });
  });

  describe("State Options", () => {
    it("provides all state filter options", async () => {
      const wrapper = await createWrapper();

      const stateValues = wrapper.vm.stateOptions.map((opt: { value: string }) => opt.value);
      expect(stateValues).toContain("Active");
      expect(stateValues).toContain("Pending");
      expect(stateValues).toContain("PendingApproval");
      expect(stateValues).toContain("Expired");
      expect(stateValues).toContain("Terminated");
      expect(stateValues).toContain("Failed");
    });
  });
});
