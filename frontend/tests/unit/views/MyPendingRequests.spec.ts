/**
 * Tests for MyPendingRequests view component
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mount, flushPromises } from "@vue/test-utils";
import { createRouter, createMemoryHistory } from "vue-router";
import { ref } from "vue";
import MyPendingRequests from "@/views/MyPendingRequests.vue";
import { AuthKey } from "@/keys";
import type { SessionCR } from "@/model/breakglass";

const mocks = await vi.hoisted(async () => {
  const { ref: vueRef } = await import("vue");

  return {
    normalizeState: (state?: string) => (state || "").toLowerCase().replace(/[_\s-]/g, ""),
    requests: vueRef<SessionCR[]>([]),
    loading: vueRef(false),
    error: vueRef(""),
    withdrawTarget: vueRef<SessionCR | null>(null),
    withdrawDialogOpen: vueRef(false),
    loadRequests: vi.fn(),
    requestWithdraw: vi.fn(),
    confirmWithdraw: vi.fn(),
    cancelWithdraw: vi.fn(),
    withdraw: vi.fn(),
    drop: vi.fn(),
  };
});

// Mock services
vi.mock("@/services/breakglass", () => ({
  default: class MockBreakglassService {
    getMyPendingRequests = vi.fn().mockResolvedValue([]);
    withdrawSession = vi.fn().mockResolvedValue({});
  },
}));

vi.mock("@/services/toast", () => ({
  pushError: vi.fn(),
  pushSuccess: vi.fn(),
}));

// Mock composables
vi.mock("@/composables", () => ({
  usePendingRequests: vi.fn().mockReturnValue({
    requests: mocks.requests,
    loading: mocks.loading,
    error: mocks.error,
    loadRequests: mocks.loadRequests,
  }),
  useSessionActions: vi.fn().mockReturnValue({
    isActionRunning: vi.fn().mockReturnValue(false),
    isSessionBusy: vi.fn().mockReturnValue(false),
    handleAction: vi.fn(),
    withdraw: mocks.withdraw,
    drop: mocks.drop,
  }),
  useWithdrawConfirmation: vi.fn((onConfirm) => ({
    withdrawDialogOpen: mocks.withdrawDialogOpen,
    withdrawTarget: mocks.withdrawTarget,
    requestWithdraw: mocks.requestWithdraw,
    confirmWithdraw: async () => {
      mocks.confirmWithdraw();
      if (mocks.withdrawTarget.value) {
        await onConfirm(mocks.withdrawTarget.value);
      }
    },
    cancelWithdraw: mocks.cancelWithdraw,
  })),
  getSessionKey: vi.fn((session) => session.metadata?.name || "key"),
  getSessionState: vi.fn((session) => session.status?.state || "pending"),
  getSessionUser: vi.fn((session) => session.spec?.user || "user@example.com"),
  getSessionCluster: vi.fn((session) => session.spec?.cluster || "test-cluster"),
  getSessionGroup: vi.fn((session) => session.spec?.escalatedGroup || "admin-group"),
  formatDateTime: vi.fn((date) => new Date(date).toLocaleString()),
  isFuture: vi.fn((date) => new Date(date) > new Date()),
  isScheduled: vi.fn((session) => {
    const state = mocks.normalizeState(session.status?.state);
    return state === "waitingforscheduledtime" || state === "scheduled";
  }),
}));

// Mock common components
const commonStubs = {
  PageHeader: {
    template: '<div class="page-header" data-testid="my-requests-header">{{ title }} {{ badge }}<slot /></div>',
    props: ["title", "subtitle", "badge", "badgeVariant"],
  },
  LoadingState: {
    template: '<div class="loading-state" data-testid="my-requests-loading">Loading...</div>',
    props: ["message"],
  },
  ErrorBanner: {
    template: '<div class="error-banner" data-testid="my-requests-error"><slot /></div>',
    props: ["message", "showRetry"],
  },
  EmptyState: {
    template: '<div class="empty-state" data-testid="empty-state">No requests</div>',
    props: ["title", "description", "icon"],
  },
  StatusTag: {
    template: '<span class="status-tag">{{ status }}</span>',
    props: ["status", "tone"],
  },
  ReasonPanel: {
    template: '<div class="reason-panel">{{ reason }}</div>',
    props: ["reason", "label", "variant"],
  },
  ActionButton: {
    template: '<button v-bind="$attrs" class="action-button" @click="$emit(\'click\')">{{ label }}</button>',
    props: ["label", "loadingLabel", "variant", "loading", "disabled"],
  },
  CountdownTimer: {
    template: '<span class="countdown">Countdown</span>',
    props: ["expiresAt"],
  },
  SessionSummaryCard: {
    template:
      '<div class="session-summary-card"><slot /><slot name="status" /><slot name="chips" /><slot name="meta" /><slot name="body" /><slot name="footer" /></div>',
    props: ["eyebrow", "title", "subtitle", "statusTone"],
  },
  SessionMetaGrid: {
    template: '<div class="session-meta-grid"><slot v-for="item in items" :item="item" /></div>',
    props: ["items"],
  },
  "scale-tag": {
    template: '<span class="scale-tag"><slot /></span>',
    props: ["variant"],
  },
  WithdrawConfirmDialog: {
    template:
      '<div v-if="opened" data-testid="withdraw-confirm-modal">{{ heading }} {{ message }} <button data-testid="withdraw-confirm-button" @click="$emit(\'confirm\')">{{ confirmLabel }}</button></div>',
    props: ["opened", "sessionName", "heading", "message", "confirmLabel"],
  },
};

describe("MyPendingRequests", () => {
  let router: ReturnType<typeof createRouter>;

  const mockAuth = {
    user: ref({ email: "test@example.com" }),
    token: ref("test-token"),
    isAuthenticated: ref(true),
  };

  beforeEach(() => {
    mocks.requests.value = [];
    mocks.loading.value = false;
    mocks.error.value = "";
    mocks.withdrawTarget.value = null;
    mocks.withdrawDialogOpen.value = false;
    mocks.loadRequests.mockClear();
    mocks.requestWithdraw.mockClear();
    mocks.confirmWithdraw.mockClear();
    mocks.cancelWithdraw.mockClear();
    mocks.withdraw.mockClear();
    mocks.drop.mockClear();
    router = createRouter({
      history: createMemoryHistory(),
      routes: [{ path: "/my-requests", name: "my-requests", component: MyPendingRequests }],
    });
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  const createWrapper = async () => {
    await router.push("/my-requests");
    await router.isReady();

    const wrapper = mount(MyPendingRequests, {
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

  it("throws a clear error when auth provider is missing", async () => {
    await router.push("/my-requests");
    await router.isReady();

    expect(() => {
      mount(MyPendingRequests, {
        global: {
          plugins: [router],
          stubs: commonStubs,
        },
      });
    }).toThrow("MyPendingRequests view requires an Auth provider");
  });

  describe("Component Structure", () => {
    it("renders the main page container", async () => {
      const wrapper = await createWrapper();
      expect(wrapper.find('[data-testid="my-requests-view"]').exists()).toBe(true);
    });

    it("renders page header", async () => {
      const wrapper = await createWrapper();
      expect(wrapper.find('[data-testid="my-requests-header"]').exists()).toBe(true);
    });

    it("renders requests section", async () => {
      const wrapper = await createWrapper();
      expect(wrapper.find('[data-testid="requests-section"]').exists()).toBe(true);
    });
  });

  describe("Empty State", () => {
    it("shows empty state when no requests", async () => {
      const wrapper = await createWrapper();
      expect(wrapper.find('[data-testid="empty-state"]').exists()).toBe(true);
    });
  });

  describe("Page Header", () => {
    it("displays correct title", async () => {
      const wrapper = await createWrapper();
      const header = wrapper.find('[data-testid="my-requests-header"]');
      expect(header.exists()).toBe(true);
      expect(header.text()).toContain("My Outstanding Requests");
    });
  });

  describe("Scheduled Requests", () => {
    it("renders scheduled outstanding requests with a drop action", async () => {
      const scheduled = {
        metadata: { name: "req-awaiting-activation" },
        spec: {
          user: "test@example.com",
          cluster: "edge-hub",
          grantedGroup: "edge-hotfix",
          scheduledStartTime: "2026-02-20T12:00:00Z",
        },
        status: { state: "WaitingForScheduledTime" },
      } as SessionCR;
      mocks.requests.value = [scheduled];

      const wrapper = await createWrapper();

      expect(wrapper.find('[data-testid="drop-button"]').text()).toBe("Drop");
      expect(wrapper.find('[data-testid="withdraw-button"]').exists()).toBe(false);

      await wrapper.find('[data-testid="drop-button"]').trigger("click");

      expect(mocks.requestWithdraw).toHaveBeenCalledWith(scheduled);
    });

    it("uses drop confirmation copy for scheduled outstanding requests", async () => {
      mocks.withdrawDialogOpen.value = true;
      mocks.withdrawTarget.value = {
        metadata: { name: "req-awaiting-activation" },
        status: { state: "WaitingForScheduledTime" },
      } as SessionCR;

      const wrapper = await createWrapper();
      const modal = wrapper.find('[data-testid="withdraw-confirm-modal"]');

      expect(modal.text()).toContain("Drop Scheduled Session");
      expect(modal.text()).toContain("scheduled start");
      expect(modal.text()).toContain("Drop");
    });

    it("confirms scheduled outstanding requests through the drop action", async () => {
      const scheduled = {
        metadata: { name: "req-awaiting-activation" },
        spec: {
          user: "test@example.com",
          cluster: "edge-hub",
          grantedGroup: "edge-hotfix",
          scheduledStartTime: "2026-02-20T12:00:00Z",
        },
        status: { state: "WaitingForScheduledTime" },
      } as SessionCR;
      mocks.withdrawDialogOpen.value = true;
      mocks.withdrawTarget.value = scheduled;

      const wrapper = await createWrapper();
      await wrapper.find('[data-testid="withdraw-confirm-button"]').trigger("click");

      expect(mocks.drop).toHaveBeenCalledWith(scheduled, { skipConfirm: true });
      expect(mocks.withdraw).not.toHaveBeenCalled();
    });
  });
});
