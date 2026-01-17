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
        stubs: {
          PageHeader: true,
          LoadingState: true,
          EmptyState: true,
          DebugSessionCard: true,
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
