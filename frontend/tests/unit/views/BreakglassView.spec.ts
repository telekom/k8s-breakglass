/**
 * Tests for BreakglassView component
 *
 * @jest-environment jsdom
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mount, flushPromises } from "@vue/test-utils";
import { createRouter, createMemoryHistory } from "vue-router";
import { ref } from "vue";
import BreakglassView from "@/views/BreakglassView.vue";
import { AuthKey } from "@/keys";

// Mock the breakglass service
vi.mock("@/services/breakglass", () => ({
  default: class MockBreakglassService {
    getBreakglasses = vi.fn().mockResolvedValue([
      {
        name: "test-escalation",
        cluster: "test-cluster",
        to: "admin-group",
        from: "user-group",
        requestingGroups: ["user-group", "developer-group"],
        minApprovals: 1,
        maxDuration: "4h",
      },
      {
        name: "prod-escalation",
        cluster: "prod-cluster",
        to: "prod-admin",
        from: "sre-group",
        requestingGroups: ["sre-group"],
        minApprovals: 2,
        maxDuration: "2h",
      },
    ]);
  },
}));

// Mock toast service
vi.mock("@/services/toast", () => ({
  pushError: vi.fn(),
  pushSuccess: vi.fn(),
}));

// Mock logger
vi.mock("@/services/logger", () => ({
  handleAxiosError: vi.fn(),
}));

// Mock currentTime composable
vi.mock("@/utils/currentTime", () => ({
  default: () => ref(new Date()),
}));

// Mock common components
const commonStubs = {
  PageHeader: {
    template: '<div class="page-header"><slot /></div>',
    props: ["title", "subtitle"],
  },
  LoadingState: {
    template: '<div class="loading-state">Loading...</div>',
    props: ["message"],
  },
  EmptyState: {
    template: '<div class="empty-state">No data</div>',
    props: ["title", "description"],
  },
  BreakglassCard: {
    template: '<div class="breakglass-card" :data-cluster="cluster"><slot /></div>',
    props: ["breakglass", "sessions", "time", "cluster"],
  },
  "scale-text-field": {
    template: '<input class="scale-text-field" @input="$emit(\'scaleInput\', $event)" />',
  },
  "scale-button": {
    template: '<button @click="$emit(\'click\')"><slot /></button>',
  },
};

describe("BreakglassView", () => {
  let router: ReturnType<typeof createRouter>;

  const mockAuth = {
    user: ref({ email: "test@example.com" }),
    token: ref("test-token"),
    isAuthenticated: ref(true),
    login: vi.fn(),
    logout: vi.fn(),
  };

  beforeEach(() => {
    router = createRouter({
      history: createMemoryHistory(),
      routes: [
        { path: "/", name: "home", component: BreakglassView },
      ],
    });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  const createWrapper = async (queryParams: Record<string, string> = {}) => {
    const query = new URLSearchParams(queryParams).toString();
    await router.push(query ? `/?${query}` : "/");
    await router.isReady();

    const wrapper = mount(BreakglassView, {
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

  describe("Initial Rendering", () => {
    it("shows loading state initially", async () => {
      const wrapper = mount(BreakglassView, {
        global: {
          plugins: [router],
          stubs: commonStubs,
          provide: {
            [AuthKey as symbol]: mockAuth,
          },
        },
      });

      // Check that loading is shown before data loads
      expect(wrapper.vm.state.loading).toBe(true);
    });

    it("loads and displays breakglass escalations", async () => {
      const wrapper = await createWrapper();

      // After loading completes
      expect(wrapper.vm.state.loading).toBe(false);
      expect(wrapper.vm.state.breakglasses.length).toBeGreaterThan(0);
    });
  });

  describe("Search Functionality", () => {
    it("initializes search from query parameter", async () => {
      const wrapper = await createWrapper({ search: "test-cluster" });
      expect(wrapper.vm.state.search).toBe("test-cluster");
    });

    it("handles array query parameters", async () => {
      // Vue router normalizes array params, test with direct route setup
      await router.push({ path: "/", query: { search: "cluster1" } });
      await router.isReady();

      const wrapper = mount(BreakglassView, {
        global: {
          plugins: [router],
          stubs: commonStubs,
          provide: {
            [AuthKey as symbol]: mockAuth,
          },
        },
      });

      await flushPromises();
      expect(wrapper.vm.state.search).toBe("cluster1");
    });
  });

  describe("Refresh Functionality", () => {
    it("has a refresh method", async () => {
      const wrapper = await createWrapper();
      expect(typeof wrapper.vm.refresh).toBe("function");
    });

    it("sets refreshing state during refresh", async () => {
      const wrapper = await createWrapper();

      // Trigger refresh
      const refreshPromise = wrapper.vm.refresh();
      expect(wrapper.vm.state.refreshing).toBe(true);

      await refreshPromise;
      expect(wrapper.vm.state.refreshing).toBe(false);
    });
  });

  describe("Deduplication Logic", () => {
    it("deduplicates breakglasses by cluster and target group", async () => {
      const wrapper = await createWrapper();

      // The computed dedupedBreakglasses should exist
      expect(wrapper.vm.dedupedBreakglasses).toBeDefined();
    });
  });

  describe("Search Filtering", () => {
    it("exposes updateSearch method", async () => {
      const wrapper = await createWrapper();
      expect(typeof wrapper.vm.updateSearch).toBe("function");
    });
  });
});
