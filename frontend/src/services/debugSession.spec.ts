import { vi, type Mock } from "vitest";
import type { AxiosInstance } from "axios";
import DebugSessionService from "./debugSession";
import { createAuthenticatedApiClient } from "@/services/httpClient";

vi.mock("@/services/httpClient");

const mockedCreateClient = createAuthenticatedApiClient as Mock<typeof createAuthenticatedApiClient>;

type MockAxiosClient = {
  get: Mock;
  post: Mock;
};

type FakeAuth = ConstructorParameters<typeof DebugSessionService>[0];

describe("DebugSessionService", () => {
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

  it("normalizes legacy list responses that return an array", async () => {
    mockClient.get.mockResolvedValueOnce({
      data: [
        {
          name: "debug-prod",
          templateRef: "shell",
          cluster: "prod",
          requestedBy: "alice@example.com",
          state: "Active",
          participants: 1,
          isParticipant: true,
          allowedPods: 2,
        },
      ],
    });

    const service = new DebugSessionService(fakeAuth);
    const result = await service.listSessions({ mine: true });

    expect(result.sessions).toHaveLength(1);
    expect(result.total).toBe(1);
    expect(mockClient.get).toHaveBeenCalledWith("/debugSessions", { params: { mine: true } });
  });

  it("returns an empty list for malformed list payloads", async () => {
    mockClient.get.mockResolvedValueOnce({ data: { sessions: undefined, total: "unknown" } });

    const service = new DebugSessionService(fakeAuth);
    await expect(service.listSessions()).resolves.toEqual({ sessions: [], total: 0 });
  });
});
