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

  it("sends the approval reason to the session action API", async () => {
    mockClient.post.mockResolvedValueOnce({ data: { metadata: { name: "debug-prod" } } });
    const service = new DebugSessionService(fakeAuth);
    await service.approveSession("debug-prod", { reason: "Approved for investigation" });
    expect(mockClient.post).toHaveBeenCalledWith("/debugSessions/debug-prod/approve", {
      reason: "Approved for investigation",
    });
  });

  it.each([
    ["joinSession", "join", undefined],
    ["leaveSession", "leave", undefined],
    ["renewSession", "renew", { extendBy: "1h" }],
  ] as const)("%s resolves to the updated session returned by the API", async (method, action, body) => {
    const updated = { metadata: { name: "debug-prod" }, status: { state: "Active", renewalCount: 1 } };
    mockClient.post.mockResolvedValueOnce({ data: updated });
    const service = new DebugSessionService(fakeAuth);
    const result =
      method === "renewSession"
        ? await service.renewSession("debug-prod", { extendBy: "1h" })
        : await service[method]("debug-prod");
    expect(result).toEqual(updated);
    const expectedArgs =
      body === undefined ? [`/debugSessions/debug-prod/${action}`] : [`/debugSessions/debug-prod/${action}`, body];
    expect(mockClient.post).toHaveBeenCalledWith(...expectedArgs);
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
