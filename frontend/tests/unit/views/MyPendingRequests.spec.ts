/**
 * Behavioral tests for MyPendingRequests
 *
 * @vitest-environment jsdom
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mount, flushPromises } from "@vue/test-utils";
import { ref } from "vue";
import MyPendingRequests from "@/views/MyPendingRequests.vue";
import { AuthKey } from "@/keys";
import { pushError } from "@/services/toast";
import type { SessionCR } from "@/model/breakglass";

const mocks = vi.hoisted(() => ({
  fetchMyOutstandingRequests: vi.fn(),
  withdrawMyRequest: vi.fn(),
  dropMySession: vi.fn(),
}));

vi.mock("@/services/breakglass", () => ({
  default: class MockBreakglassService {
    fetchMyOutstandingRequests = mocks.fetchMyOutstandingRequests;
    withdrawMyRequest = mocks.withdrawMyRequest;
    dropMySession = mocks.dropMySession;
  },
}));

vi.mock("@/services/toast", () => {
  const pushError = vi.fn();
  return {
    pushError,
    pushSuccess: vi.fn(),
    reportError: vi.fn((err: unknown, fallback: string) =>
      pushError((err instanceof Error ? err.message : undefined) || fallback),
    ),
  };
});

const stubs = {
  PageHeader: {
    template: '<div data-testid="my-requests-header">{{ title }} {{ badge }}<slot /></div>',
    props: ["title", "subtitle", "badge", "badgeVariant"],
  },
  LoadingState: { template: '<div data-testid="my-requests-loading">Loading...</div>', props: ["message"] },
  ErrorBanner: {
    template: '<div data-testid="my-requests-error">{{ message }}</div>',
    props: ["message", "showRetry"],
  },
  EmptyState: { template: '<div data-testid="empty-state">No requests</div>', props: ["title", "description", "icon"] },
  StatusTag: { template: "<span>{{ status }}</span>", props: ["status", "tone"] },
  ReasonPanel: { template: "<div>{{ reason }}</div>", props: ["reason", "label", "variant"] },
  ActionButton: {
    template:
      '<button v-bind="$attrs" :disabled="disabled" :aria-busy="loading" @click="$emit(\'click\')">{{ loading ? loadingLabel : label }}</button>',
    props: ["label", "loadingLabel", "variant", "loading", "disabled"],
  },
  CountdownTimer: { template: "<span>Countdown</span>", props: ["expiresAt"] },
  SessionSummaryCard: {
    template:
      '<article><slot /><slot name="status" /><slot name="chips" /><slot name="meta" /><slot name="body" /><slot name="footer" /></article>',
    props: ["eyebrow", "title", "subtitle", "statusTone"],
  },
  SessionMetaGrid: { template: '<div><slot v-for="item in items" :item="item" /></div>', props: ["items"] },
  "scale-tag": { template: "<span><slot /></span>", props: ["variant"] },
  WithdrawConfirmDialog: {
    template:
      '<div v-if="opened" data-testid="withdraw-confirm-modal"><span>{{ heading }}</span><span>{{ message }}</span><button data-testid="withdraw-confirm-button" @click="$emit(\'confirm\')">{{ confirmLabel }}</button><button data-testid="withdraw-cancel-button" @click="$emit(\'cancel\')">Cancel</button></div>',
    props: ["opened", "sessionName", "heading", "message", "confirmLabel"],
  },
};

const mockAuth = {
  user: ref({ email: "test@example.com" }),
  token: ref("test-token"),
  isAuthenticated: ref(true),
};

function request(name: string): SessionCR {
  return {
    metadata: { name },
    spec: { user: "test@example.com", cluster: "test-cluster", grantedGroup: "admin-group" },
    status: { state: "Pending" },
  };
}

async function mountView() {
  const wrapper = mount(MyPendingRequests, {
    global: {
      stubs,
      provide: { [AuthKey as symbol]: mockAuth },
    },
  });
  await flushPromises();
  return wrapper;
}

describe("MyPendingRequests", () => {
  beforeEach(() => {
    mocks.fetchMyOutstandingRequests.mockReset().mockResolvedValue([]);
    mocks.withdrawMyRequest.mockReset().mockResolvedValue(undefined);
    mocks.dropMySession.mockReset().mockResolvedValue(undefined);
    vi.mocked(pushError).mockClear();
  });

  afterEach(() => vi.clearAllMocks());

  it("requires the auth provider and renders the empty page", async () => {
    expect(() =>
      mount(MyPendingRequests, {
        global: { stubs },
      }),
    ).toThrow("MyPendingRequests view requires an Auth provider");

    const wrapper = await mountView();

    expect(wrapper.find('[data-testid="my-requests-view"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="my-requests-header"]').text()).toContain("My Outstanding Requests");
    expect(wrapper.find('[data-testid="requests-section"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="empty-state"]').exists()).toBe(true);
  });

  it("loads and renders the current outstanding requests", async () => {
    mocks.fetchMyOutstandingRequests.mockResolvedValue([request("req-1")]);

    const wrapper = await mountView();

    expect(mocks.fetchMyOutstandingRequests).toHaveBeenCalledOnce();
    expect(wrapper.find('[data-testid="pending-request-card-req-1"]').exists()).toBe(true);
  });

  it("requires confirmation, then withdraws and prunes only the withdrawn request", async () => {
    const first = request("req-1");
    mocks.fetchMyOutstandingRequests.mockResolvedValue([first, request("req-2")]);
    let finishWithdrawal!: () => void;
    mocks.withdrawMyRequest.mockImplementation(
      () =>
        new Promise<void>((resolve) => {
          finishWithdrawal = resolve;
        }),
    );

    const wrapper = await mountView();
    await wrapper.find('[data-testid="withdraw-button"]').trigger("click");

    expect(wrapper.find('[data-testid="withdraw-confirm-modal"]').exists()).toBe(true);
    expect(mocks.withdrawMyRequest).not.toHaveBeenCalled();

    await wrapper.find('[data-testid="withdraw-confirm-button"]').trigger("click");
    const withdrawButton = wrapper.find('[data-testid="withdraw-button"]');
    expect(mocks.withdrawMyRequest).toHaveBeenCalledWith(first);
    expect(withdrawButton.text()).toBe("Withdrawing...");
    expect(withdrawButton.attributes("aria-busy")).toBe("true");
    expect(withdrawButton.attributes("disabled")).toBeDefined();

    finishWithdrawal();
    await flushPromises();

    expect(wrapper.find('[data-testid="pending-request-card-req-1"]').exists()).toBe(false);
    expect(wrapper.find('[data-testid="pending-request-card-req-2"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="withdraw-confirm-modal"]').exists()).toBe(false);
  });

  it("keeps the request and confirmation available when withdrawal fails", async () => {
    mocks.fetchMyOutstandingRequests.mockResolvedValue([request("req-1")]);
    mocks.withdrawMyRequest.mockRejectedValue(new Error("withdraw denied"));

    const wrapper = await mountView();
    await wrapper.find('[data-testid="withdraw-button"]').trigger("click");
    await wrapper.find('[data-testid="withdraw-confirm-button"]').trigger("click");
    await flushPromises();

    expect(mocks.withdrawMyRequest).toHaveBeenCalledOnce();
    expect(vi.mocked(pushError)).toHaveBeenCalledWith("withdraw denied");
    expect(wrapper.find('[data-testid="pending-request-card-req-1"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="withdraw-confirm-modal"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="withdraw-button"]').text()).toBe("Withdraw");
    expect(wrapper.find('[data-testid="withdraw-button"]').attributes("disabled")).toBeUndefined();
  });

  it("does not call the API when the user cancels confirmation", async () => {
    mocks.fetchMyOutstandingRequests.mockResolvedValue([request("req-1")]);

    const wrapper = await mountView();
    await wrapper.find('[data-testid="withdraw-button"]').trigger("click");
    await wrapper.find('[data-testid="withdraw-cancel-button"]').trigger("click");

    expect(mocks.withdrawMyRequest).not.toHaveBeenCalled();
    expect(wrapper.find('[data-testid="pending-request-card-req-1"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="withdraw-confirm-modal"]').exists()).toBe(false);
  });

  it("confirms scheduled requests with Drop and prunes them after the drop API succeeds", async () => {
    const scheduled: SessionCR = {
      metadata: { name: "req-scheduled" },
      spec: {
        user: "test@example.com",
        cluster: "test-cluster",
        grantedGroup: "admin-group",
        scheduledStartTime: "2026-10-05T12:00:00Z",
      },
      status: { state: "WaitingForScheduledTime" },
    };
    mocks.fetchMyOutstandingRequests.mockResolvedValue([scheduled]);

    const wrapper = await mountView();

    expect(wrapper.find('[data-testid="drop-button"]').exists()).toBe(true);
    expect(wrapper.find('[data-testid="withdraw-button"]').exists()).toBe(false);
    await wrapper.find('[data-testid="drop-button"]').trigger("click");

    const dialog = wrapper.find('[data-testid="withdraw-confirm-modal"]');
    expect(dialog.text()).toContain("Drop Scheduled Session");
    expect(dialog.text()).toContain(
      "This session is already approved and waiting for its scheduled start. Dropping it will cancel the scheduled activation.",
    );
    expect(mocks.dropMySession).not.toHaveBeenCalled();
    expect(mocks.withdrawMyRequest).not.toHaveBeenCalled();

    await wrapper.find('[data-testid="withdraw-confirm-button"]').trigger("click");
    await flushPromises();

    expect(mocks.dropMySession).toHaveBeenCalledWith(scheduled);
    expect(mocks.withdrawMyRequest).not.toHaveBeenCalled();
    expect(wrapper.find('[data-testid="pending-request-card-req-scheduled"]').exists()).toBe(false);
    expect(wrapper.find('[data-testid="withdraw-confirm-modal"]').exists()).toBe(false);
  });
});
