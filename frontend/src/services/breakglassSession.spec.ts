import { vi, type Mock } from "vitest";
import type { AxiosInstance } from "axios";
import BreakglassSessionService from "./breakglassSession";
import { createAuthenticatedApiClient } from "@/services/httpClient";
import { useErrors } from "@/services/toast";

vi.mock("@/services/httpClient");

const mockedCreateClient = createAuthenticatedApiClient as Mock<typeof createAuthenticatedApiClient>;

type MockAxiosClient = {
  get: Mock;
  post: Mock;
};

type FakeAuth = ConstructorParameters<typeof BreakglassSessionService>[0];

describe("BreakglassSessionService", () => {
  const fakeAuth = { getAccessToken: async () => "fake-token" } as unknown as FakeAuth;
  let mockClient: MockAxiosClient;

  beforeEach(() => {
    mockClient = {
      get: vi.fn(),
      post: vi.fn(),
    };
    mockedCreateClient.mockReturnValue(mockClient as unknown as AxiosInstance);
  });

  afterEach(() => {
    vi.clearAllMocks();
  });

  it("does not toast when getSessionByName fails so the approval view owns the error state", async () => {
    const store = useErrors();
    store.errors.splice(0, store.errors.length);
    const notFound = Object.assign(new Error("Request failed with status code 404"), {
      response: { status: 404, data: {} },
    });
    mockClient.get.mockRejectedValueOnce(notFound);

    const service = new BreakglassSessionService(fakeAuth);

    await expect(service.getSessionByName("missing session")).rejects.toBe(notFound);
    expect(mockClient.get).toHaveBeenCalledWith("/breakglassSessions/missing%20session");
    expect(store.errors).toHaveLength(0);
  });

  it("normalizes malformed session status payloads to an empty list", async () => {
    mockClient.get.mockResolvedValueOnce({ status: 200, data: { items: undefined } });

    const service = new BreakglassSessionService(fakeAuth);
    const response = await service.getSessionStatus({ approver: true, mine: false });

    expect(response.status).toBe(200);
    expect(response.data).toEqual([]);
    expect(mockClient.get).toHaveBeenCalledWith("/breakglassSessions", {
      params: { mine: false, approver: true },
    });
  });

  it("normalizes session status list envelopes", async () => {
    mockClient.get.mockResolvedValueOnce({
      status: 200,
      data: { items: [{ metadata: { name: "session-a" } }], total: 1 },
    });

    const service = new BreakglassSessionService(fakeAuth);
    const response = await service.getSessionStatus({ user: "alice@example.com", cluster: "prod-a" });

    expect(response.status).toBe(200);
    expect(response.data).toEqual([{ metadata: { name: "session-a" } }]);
    expect(mockClient.get).toHaveBeenCalledWith("/breakglassSessions", {
      params: { user: "alice@example.com", cluster: "prod-a", mine: true, approver: false },
    });
  });
});
