import { vi, type Mock } from "vitest";
import { usePendingRequests } from "@/composables/usePendingRequests";
import type { SessionCR } from "@/model/breakglass";

type MockService = {
  fetchMyOutstandingRequests: Mock<() => Promise<SessionCR[]>>;
  withdrawMyRequest: Mock<(session: SessionCR) => Promise<void>>;
};

const debugMock = vi.fn();
const warnMock = vi.fn();

vi.mock("@/services/logger", () => ({
  debug: (...args: any[]) => debugMock(...args),
  warn: (...args: any[]) => warnMock(...args),
}));

function createMockService(overrides: Partial<MockService> = {}): MockService {
  return {
    fetchMyOutstandingRequests: vi.fn().mockResolvedValue([]),
    withdrawMyRequest: vi.fn().mockResolvedValue(undefined),
    ...overrides,
  };
}

function sampleRequest(name: string): SessionCR {
  return {
    metadata: { name },
    spec: { grantedGroup: "ops", cluster: "c1", user: "alice" },
    status: { state: "Pending" },
  };
}

describe("usePendingRequests", () => {
  beforeEach(() => {
    debugMock.mockClear();
    warnMock.mockClear();
  });

  it("reports error when service is unavailable", async () => {
    const state = usePendingRequests(null);

    await state.loadRequests();

    expect(state.error.value).toBe("Auth not available");
    expect(state.loading.value).toBe(false);
    expect(warnMock).toHaveBeenCalledWith("usePendingRequests.loadRequests", "Missing BreakglassService instance");
  });

  it("loads pending requests and clears errors", async () => {
    const request = sampleRequest("req-1");
    const service = createMockService({
      fetchMyOutstandingRequests: vi.fn().mockResolvedValue([request]),
    });
    const state = usePendingRequests(service as any);

    await state.loadRequests();

    expect(service.fetchMyOutstandingRequests).toHaveBeenCalledTimes(1);
    expect(state.requests.value).toEqual([request]);
    expect(state.error.value).toBe("");
    expect(debugMock).toHaveBeenCalledWith("usePendingRequests.loadRequests", "Loaded pending requests", { count: 1 });
  });

  it("surfaces fetch failures and logs warning", async () => {
    const service = createMockService({
      fetchMyOutstandingRequests: vi.fn().mockRejectedValue(new Error("boom")),
    });
    const state = usePendingRequests(service as any);

    await state.loadRequests();

    expect(state.error.value).toBe("boom");
    expect(warnMock).toHaveBeenCalledWith("usePendingRequests.loadRequests", "Failed to load pending requests", {
      errorMessage: "boom",
    });
  });

  it("withdraws a request and prunes it locally", async () => {
    const request = sampleRequest("req-1");
    const second = sampleRequest("req-2");
    const service = createMockService();
    const state = usePendingRequests(service as any);
    state.requests.value = [request, second];

    await state.withdrawRequest(request);

    expect(service.withdrawMyRequest).toHaveBeenCalledWith(request);
    expect(state.requests.value).toEqual([second]);
    expect(state.withdrawing.value).toBe("");
    expect(state.error.value).toBe("");
    expect(debugMock).toHaveBeenCalledWith("usePendingRequests.withdrawRequest", "Withdraw complete", {
      sessionName: "req-1",
    });
  });

  it("captures withdraw failures and keeps entry", async () => {
    const request = sampleRequest("req-1");
    const service = createMockService({
      withdrawMyRequest: vi.fn().mockRejectedValue(new Error("nope")),
    });
    const state = usePendingRequests(service as any);
    state.requests.value = [request];

    await state.withdrawRequest(request);

    expect(state.requests.value).toHaveLength(1);
    expect(state.error.value).toBe("nope");
    expect(warnMock).toHaveBeenCalledWith("usePendingRequests.withdrawRequest", "Withdraw failed", {
      sessionName: "req-1",
      errorMessage: "nope",
    });
  });
});
