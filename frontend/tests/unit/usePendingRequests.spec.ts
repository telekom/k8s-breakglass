import { vi, type Mock } from "vitest";
import { usePendingRequests } from "@/composables/usePendingRequests";
import type { SessionCR } from "@/model/breakglass";
import type BreakglassService from "@/services/breakglass";

type MockService = {
  fetchMyOutstandingRequests: Mock<() => Promise<SessionCR[]>>;
};

const debugMock = vi.fn();
const warnMock = vi.fn();

vi.mock("@/services/logger", () => ({
  debug: (...args: unknown[]) => debugMock(...args),
  warn: (...args: unknown[]) => warnMock(...args),
}));

function createMockService(overrides: Partial<MockService> = {}): MockService {
  return {
    fetchMyOutstandingRequests: vi.fn().mockResolvedValue([]),
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

  it("loads outstanding requests and clears errors", async () => {
    const request = sampleRequest("req-1");
    const service = createMockService({
      fetchMyOutstandingRequests: vi.fn().mockResolvedValue([request]),
    });
    const state = usePendingRequests(service as unknown as BreakglassService);

    await state.loadRequests();

    expect(service.fetchMyOutstandingRequests).toHaveBeenCalledTimes(1);
    expect(state.requests.value).toEqual([request]);
    expect(state.error.value).toBe("");
    expect(debugMock).toHaveBeenCalledWith("usePendingRequests.loadRequests", "Loaded outstanding requests", {
      count: 1,
    });
  });

  it("surfaces fetch failures and logs warning", async () => {
    const service = createMockService({
      fetchMyOutstandingRequests: vi.fn().mockRejectedValue(new Error("boom")),
    });
    const state = usePendingRequests(service as unknown as BreakglassService);

    await state.loadRequests();

    expect(state.error.value).toBe("boom");
    expect(warnMock).toHaveBeenCalledWith("usePendingRequests.loadRequests", "Failed to load outstanding requests", {
      errorMessage: "boom",
    });
  });
});
