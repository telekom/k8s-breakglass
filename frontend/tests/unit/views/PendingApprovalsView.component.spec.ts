/**
 * Component-level tests for PendingApprovalsView
 *
 * @vitest-environment jsdom
 */

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { mount, flushPromises } from "@vue/test-utils";
import { ref } from "vue";
import PendingApprovalsView from "@/views/PendingApprovalsView.vue";
import { AuthKey } from "@/keys";
import { pushError } from "@/services/toast";

const mockFetchPendingSessionsForApproval = vi.fn();
const mockApproveBreakglass = vi.fn();
const mockRejectBreakglass = vi.fn();

vi.mock("@/services/breakglass", () => ({
  default: class MockBreakglassService {
    fetchPendingSessionsForApproval = mockFetchPendingSessionsForApproval;
    approveBreakglass = mockApproveBreakglass;
    rejectBreakglass = mockRejectBreakglass;
  },
}));

vi.mock("@/services/toast", () => ({
  pushError: vi.fn(),
  pushSuccess: vi.fn(),
}));

vi.mock("@/composables", () => ({
  formatDateTime: vi.fn((value) => String(value ?? "")),
  formatDuration: vi.fn((value) => String(value ?? "")),
  formatEndTime: vi.fn(() => "end"),
  getUrgency: vi.fn(() => "normal"),
  getTimeRemaining: vi.fn(() => 1000),
  getUrgencyLabel: vi.fn(() => ({ text: "Normal", icon: "content-clock", ariaLabel: "Normal urgency" })),
  getSessionKey: vi.fn((session) => session?.metadata?.name || "session"),
  getSessionState: vi.fn((session) => session?.status?.state || "Pending"),
  getSessionCluster: vi.fn((session) => session?.spec?.cluster || "cluster-a"),
  getSessionGroup: vi.fn((session) => session?.spec?.grantedGroup || "group-a"),
  dedupeSessions: vi.fn((sessions) => sessions),
}));

describe("PendingApprovalsView (component)", () => {
  const mockAuth = {
    user: ref({ email: "approver@example.com" }),
    token: ref("token"),
    isAuthenticated: ref(true),
  };

  beforeEach(() => {
    mockFetchPendingSessionsForApproval.mockResolvedValue([]);
    mockApproveBreakglass.mockResolvedValue(undefined);
    mockRejectBreakglass.mockResolvedValue(undefined);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  const createWrapper = async () => {
    const wrapper = mount(PendingApprovalsView, {
      global: {
        provide: {
          [AuthKey as symbol]: mockAuth,
        },
        stubs: {
          PageHeader: true,
          EmptyState: true,
          LoadingState: true,
          StatusTag: true,
          ReasonPanel: true,
          ActionButton: true,
          CountdownTimer: true,
          SessionSummaryCard: true,
          SessionMetaGrid: true,
          ApprovalModalContent: true,
          "scale-dropdown-select": true,
          "scale-dropdown-select-option": true,
          "scale-modal": true,
          "scale-tag": true,
          "scale-icon-alert-warning": true,
          "scale-icon-content-clock": true,
          "scale-icon-content-calendar": true,
          "scale-icon-action-edit": true,
          "scale-button": true,
        },
      },
    });

    await flushPromises();
    return wrapper;
  };

  it("fetches pending sessions on mount", async () => {
    await createWrapper();
    expect(mockFetchPendingSessionsForApproval).toHaveBeenCalledTimes(1);
  });

  it("shows empty state when there are no pending sessions", async () => {
    const wrapper = await createWrapper();
    expect(wrapper.find('[data-testid="empty-state"]').exists()).toBe(true);
  });

  it("shows session list when pending sessions exist", async () => {
    mockFetchPendingSessionsForApproval.mockResolvedValueOnce([
      {
        metadata: { name: "session-1", creationTimestamp: "2026-02-01T10:00:00Z" },
        spec: { user: "user@example.com", grantedGroup: "admin", cluster: "cluster-a" },
        status: { state: "Pending", timeoutAt: "2026-02-01T11:00:00Z" },
      },
    ]);

    const wrapper = await createWrapper();
    expect(wrapper.find('[data-testid="pending-sessions-list"]').exists()).toBe(true);
  });

  it("shows error toast when loading sessions fails", async () => {
    mockFetchPendingSessionsForApproval.mockRejectedValueOnce(new Error("network error"));

    await createWrapper();
    expect(pushError).toHaveBeenCalledWith("Failed to fetch pending approvals");
  });
});
