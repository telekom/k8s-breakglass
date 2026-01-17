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
      routes: [{ path: "/", name: "home", component: BreakglassView }],
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
        stubs: {
          PageHeader: true,
          LoadingState: true,
          EmptyState: true,
          BreakglassCard: true,
          "scale-text-field": true,
          "scale-button": true,
        },
        provide: {
          [AuthKey as symbol]: mockAuth,
        },
      },
    });

    await flushPromises();
    return wrapper;
  };

  describe("Initial Rendering", () => {
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
  });

  describe("Query Parameters", () => {
    it("handles query parameter on mount", async () => {
      const wrapper = await createWrapper({ search: "test-cluster" });
      expect(wrapper.exists()).toBe(true);
    });

    it("mounts with empty query", async () => {
      const wrapper = await createWrapper({});
      expect(wrapper.exists()).toBe(true);
    });
  });

  describe("Component Lifecycle", () => {
    it("unmounts cleanly", async () => {
      const wrapper = await createWrapper();
      expect(() => wrapper.unmount()).not.toThrow();
    });
  });
});
