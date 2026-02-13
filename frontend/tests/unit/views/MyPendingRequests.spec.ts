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
    requests: ref([]),
    loading: ref(false),
    error: ref(""),
    loadRequests: vi.fn(),
  }),
  useSessionActions: vi.fn().mockReturnValue({
    isActionRunning: vi.fn().mockReturnValue(false),
    isSessionBusy: vi.fn().mockReturnValue(false),
    handleAction: vi.fn(),
  }),
  getSessionKey: vi.fn((session) => session.metadata?.name || "key"),
  getSessionState: vi.fn((session) => session.status?.state || "pending"),
  getSessionUser: vi.fn((session) => session.spec?.user || "user@example.com"),
  getSessionCluster: vi.fn((session) => session.spec?.cluster || "test-cluster"),
  getSessionGroup: vi.fn((session) => session.spec?.escalatedGroup || "admin-group"),
  formatDateTime: vi.fn((date) => new Date(date).toLocaleString()),
  isFuture: vi.fn((date) => new Date(date) > new Date()),
}));

// Mock common components
const commonStubs = {
  PageHeader: {
    template: '<div class="page-header" data-testid="my-requests-header"><slot /></div>',
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
    template: '<button class="action-button" @click="$emit(\'click\')">{{ label }}</button>',
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
};

describe("MyPendingRequests", () => {
  let router: ReturnType<typeof createRouter>;

  const mockAuth = {
    user: ref({ email: "test@example.com" }),
    token: ref("test-token"),
    isAuthenticated: ref(true),
  };

  beforeEach(() => {
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
    });
  });
});
