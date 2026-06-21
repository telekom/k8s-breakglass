import { vi, type Mock } from "vitest";
import type { AxiosInstance } from "axios";
import BreakglassSessionService from "./breakglassSession";
import { createAuthenticatedApiClient } from "@/services/httpClient";

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
});
