/**
 * Tests for SessionBrowser view component
 *
 * @jest-environment jsdom
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mount, flushPromises } from "@vue/test-utils";
import { createRouter, createMemoryHistory } from "vue-router";
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

// Mock common components
const commonStubs = {
  EmptyState: {
    template: '<div class="empty-state">No sessions</div>',
    props: ["title", "description"],
  },
  ReasonPanel: {
    template: '<div class="reason-panel">{{ reason }}</div>',
    props: ["reason", "label", "variant"],
  },
  TimelineGrid: {
    template: '<div class="timeline-grid"><slot /></div>',
    props: ["items"],
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
  "scale-tag": {
    template: '<span class="scale-tag"><slot /></span>',
    props: ["variant"],
  },
  "scale-card": {
    template: '<div class="scale-card"><slot /></div>',
  },
  "scale-divider": {
    template: '<hr class="scale-divider" />',
  },
};

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
      routes: [
        { path: "/sessions", name: "sessions", component: SessionBrowser },
      ],
    });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  const createWrapper = async () => {
    await router.push("/sessions");
    await router.isReady();

    const wrapper = mount(SessionBrowser, {
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

  describe("Initial State", () => {
    it("starts with loading state", () => {
      const wrapper = mount(SessionBrowser, {
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

    it("has default filter state", async () => {
      const wrapper = await createWrapper();

      expect(wrapper.vm.filters.mine).toBe(true);
      expect(wrapper.vm.filters.approver).toBe(false);
      expect(wrapper.vm.filters.states).toEqual(
        expect.arrayContaining(["approved", "timeout", "withdrawn", "rejected"]),
      );
    });
  });

  describe("Filter Options", () => {
    it("provides all state filter options", async () => {
      const wrapper = await createWrapper();

      const stateValues = wrapper.vm.stateOptions.map((opt: { value: string }) => opt.value);
      expect(stateValues).toContain("approved");
      expect(stateValues).toContain("pending");
      expect(stateValues).toContain("rejected");
      expect(stateValues).toContain("withdrawn");
      expect(stateValues).toContain("timeout");
      expect(stateValues).toContain("active");
      expect(stateValues).toContain("expired");
    });
  });

  describe("Helper Functions", () => {
    it("has startedFor helper", async () => {
      const wrapper = await createWrapper();

      const session = {
        status: { actualStartTime: "2024-01-01T00:00:00Z" },
        metadata: { creationTimestamp: "2024-01-01T00:00:00Z" },
      };

      expect(typeof wrapper.vm.startedFor).toBe("function");
    });

    it("has endedFor helper", async () => {
      const wrapper = await createWrapper();
      expect(typeof wrapper.vm.endedFor).toBe("function");
    });

    it("has reasonEndedLabel helper", async () => {
      const wrapper = await createWrapper();
      expect(typeof wrapper.vm.reasonEndedLabel).toBe("function");
    });
  });

  describe("User Email", () => {
    it("computes current user email", async () => {
      const wrapper = await createWrapper();
      expect(wrapper.vm.currentUserEmail).toBe("test@example.com");
    });
  });

  describe("Session Actions", () => {
    it("tracks action busy state per session", async () => {
      const wrapper = await createWrapper();
      expect(wrapper.vm.actionBusy).toBeDefined();
      expect(typeof wrapper.vm.actionBusy).toBe("object");
    });
  });
});
