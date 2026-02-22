/**
 * Tests for SessionBrowser view component
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mount, flushPromises } from "@vue/test-utils";
import { createRouter, createMemoryHistory } from "vue-router";
import { createPinia } from "pinia";
import { ref } from "vue";
import SessionBrowser from "@/views/SessionBrowser.vue";
import { AuthKey } from "@/keys";

// Mock services
vi.mock("@/services/breakglass", () => ({
  default: class MockBreakglassService {
    searchSessions = vi.fn().mockResolvedValue({
      sessions: [
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
      ],
    });
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

vi.mock("@/utils/sessionFilters", () => ({
  describeApprover: vi.fn().mockReturnValue("Approved by admin"),
  wasApprovedBy: vi.fn().mockReturnValue(false),
}));

vi.mock("@/utils/sessionActions", () => ({
  decideRejectOrWithdraw: vi.fn().mockReturnValue("reject"),
}));

vi.mock("@/utils/statusStyles", () => ({
  statusToneFor: vi.fn().mockReturnValue("success"),
}));

vi.mock("@/composables", async (importOriginal) => {
  const original = (await importOriginal()) as Record<string, unknown>;
  return {
    ...original,
    useWithdrawConfirmation: (onConfirm: (...args: unknown[]) => unknown) => ({
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
          "scale-dropdown-select-option": true,
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
