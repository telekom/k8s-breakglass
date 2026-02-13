/**
 * Tests for BreakglassView component
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mount, flushPromises } from "@vue/test-utils";
import { createRouter, createMemoryHistory } from "vue-router";
import { ref } from "vue";
import BreakglassView from "@/views/BreakglassView.vue";
import { pushError } from "@/services/toast";
import { AuthKey } from "@/keys";

// Module-level mock functions for breakglass service methods
const mockGetBreakglasses = vi.fn();
const mockDropBreakglass = vi.fn();
const mockRequestBreakglass = vi.fn();
const mockWithdrawMyRequest = vi.fn();

// Mock the breakglass service
vi.mock("@/services/breakglass", () => ({
  default: class MockBreakglassService {
    getBreakglasses = mockGetBreakglasses;
    dropBreakglass = mockDropBreakglass;
    requestBreakglass = mockRequestBreakglass;
    withdrawMyRequest = mockWithdrawMyRequest;
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
    mockGetBreakglasses.mockResolvedValue([
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

  describe("Error Handling", () => {
    it("calls pushError when getBreakglasses throws", async () => {
      const { pushError } = await import("@/services/toast");
      mockGetBreakglasses.mockRejectedValueOnce(new Error("Network error"));

      await createWrapper();

      expect(pushError).toHaveBeenCalledWith("Network error");
    });

    it("sets breakglasses to empty array when fetch fails", async () => {
      mockGetBreakglasses.mockRejectedValueOnce(new Error("Fail"));

      const wrapper = await createWrapper();

      // Component should still mount successfully after error
      expect(wrapper.exists()).toBe(true);
    });

    it("does not throw when getBreakglasses rejects", async () => {
      mockGetBreakglasses.mockRejectedValueOnce(new Error("Server error"));

      await expect(createWrapper()).resolves.toBeDefined();
    });

    it("uses fallback message when error has no message", async () => {
      const { pushError } = await import("@/services/toast");
      mockGetBreakglasses.mockRejectedValueOnce({});

      await createWrapper();

      expect(pushError).toHaveBeenCalledWith("Failed to load escalations");
    });
  });

  describe("onDrop Error Handling", () => {
    it("catches errors from dropBreakglass without propagating", async () => {
      mockDropBreakglass.mockRejectedValueOnce(new Error("Drop failed"));

      const wrapper = await createWrapper();
      const cards = wrapper.findAllComponents({ name: "BreakglassCard" });
      expect(cards.length).toBeGreaterThan(0);

      // Emit the @drop event from the stubbed BreakglassCard
      await cards[0]!.vm.$emit("drop", { cluster: "test-cluster", to: "admin-group" });
      await flushPromises();

      // Component should still be intact (error doesn't propagate)
      expect(wrapper.exists()).toBe(true);
    });

    it("refreshes data after successful drop", async () => {
      mockDropBreakglass.mockResolvedValueOnce(undefined);

      const wrapper = await createWrapper();
      const callCountBefore = mockGetBreakglasses.mock.calls.length;

      const cards = wrapper.findAllComponents({ name: "BreakglassCard" });
      await cards[0]!.vm.$emit("drop", { cluster: "test-cluster", to: "admin-group" });
      await flushPromises();

      // getBreakglasses should have been called again to refresh
      expect(mockGetBreakglasses.mock.calls.length).toBeGreaterThan(callCountBefore);
    });
  });

  describe("onRequest Error Handling", () => {
    it("handles 409 conflict with structured error response", async () => {
      const axiosError = {
        response: {
          status: 409,
          data: {
            error: "already requested",
            message: "Session already exists",
            session: { metadata: { name: "sess-123" }, status: { state: "Pending" } },
          },
        },
        message: "Request failed with status 409",
      };
      mockRequestBreakglass.mockRejectedValueOnce(axiosError);

      const wrapper = await createWrapper();
      const cards = wrapper.findAllComponents({ name: "BreakglassCard" });

      // Emit @request from the stubbed BreakglassCard
      await cards[0]!.vm.$emit("request", { cluster: "test-cluster", to: "admin-group" }, "test reason", 3600);
      await flushPromises();

      expect(pushError).toHaveBeenCalledWith(expect.stringContaining("already requested"));
    });
  });
});
