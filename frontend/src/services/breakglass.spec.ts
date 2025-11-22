import BreakglassService from "./breakglass";
import axios from "axios";

jest.mock("axios");
const mockedAxios = axios as jest.Mocked<typeof axios>;

describe("BreakglassService", () => {
  const fakeAuth = { getAccessToken: async () => "fake-token" } as any;
  let service: BreakglassService;
  let mockClient: any;

  beforeEach(() => {
    mockClient = {
      get: jest.fn(),
      interceptors: {
        request: { use: jest.fn() },
        response: { use: jest.fn() },
      },
    };
    (mockedAxios.create as jest.Mock).mockReturnValue(mockClient);
    service = new BreakglassService(fakeAuth);
  });

  afterEach(() => {
    jest.clearAllMocks();
  });

  it("maps withdrawn and rejected sessions using status.state", async () => {
    mockClient.get.mockResolvedValueOnce({
      data: [
        {
          metadata: { name: "withdrawn1" },
          spec: { grantedGroup: "g1", cluster: "c1" },
          status: { state: "Withdrawn" },
        },
        {
          metadata: { name: "rejected1" },
          spec: { grantedGroup: "g2", cluster: "c2" },
          status: { state: "Rejected" },
        },
      ],
    });

    const sessions = await service.fetchHistoricalSessions();
    expect(sessions).toEqual(
      expect.arrayContaining([
        expect.objectContaining({ name: "withdrawn1", state: "Withdrawn" }),
        expect.objectContaining({ name: "rejected1", state: "Rejected" }),
      ]),
    );
  });

  it("normalizes active sessions so getBreakglasses() can match them", async () => {
    // fetchAvailableEscalations -> returns one available escalation
    mockClient.get
      .mockResolvedValueOnce({
        data: [
          { spec: { allowed: { groups: ["test-user"], clusters: ["c1"] }, escalatedGroup: "g1", maxValidFor: "1h" } },
        ],
      })
      // fetchActiveSessions -> returns approved session with nested metadata/spec/status
      .mockResolvedValueOnce({
        data: [
          {
            metadata: { name: "s1" },
            spec: { grantedGroup: "g1", cluster: "c1" },
            status: { expiresAt: new Date().toISOString(), state: "Approved" },
          },
        ],
      })
      // fetchMyOutstandingRequests -> none
      .mockResolvedValueOnce({ data: [] })
      // fetchHistoricalSessions -> rejected and withdrawn (two sequential GETs inside helper)
      .mockResolvedValueOnce({ data: [] })
      .mockResolvedValueOnce({ data: [] });

    const service = new BreakglassService({ getAccessToken: async () => "t" } as any);
    const res = await service.getBreakglasses();
    expect(res).toHaveLength(1);
    const first: any = res[0];
    expect(first.sessionActive).not.toBeNull();
    expect(first.sessionActive.metadata).toBeDefined();
    expect(first.sessionActive.spec).toBeDefined();
  });

  it("includes provided reason when requesting breakglass for test-user", async () => {
    const fakeAuth2 = { getAccessToken: async () => "tok", getUserEmail: async () => "test-user@example.com" } as any;
    const mockClient2: any = {
      post: jest.fn(),
      get: jest.fn(),
      interceptors: { request: { use: jest.fn() }, response: { use: jest.fn() } },
    };
    (mockedAxios.create as jest.Mock).mockReturnValueOnce(mockClient2);
    const svc = new BreakglassService(fakeAuth2);
    mockClient2.post.mockResolvedValueOnce({ status: 201 });

    const transition = { cluster: "c1", to: "g1", duration: 3600 } as any;
    await svc.requestBreakglass(transition, "needed for testing");
    expect(mockClient2.post).toHaveBeenCalledWith(
      "/breakglassSessions",
      expect.objectContaining({ reason: "needed for testing", user: "test-user@example.com" }),
    );
  });

  it("includes custom duration when requesting breakglass", async () => {
    const fakeAuth = { getAccessToken: async () => "tok", getUserEmail: async () => "user@example.com" } as any;
    const mockClient: any = {
      post: jest.fn(),
      get: jest.fn(),
      interceptors: { request: { use: jest.fn() }, response: { use: jest.fn() } },
    };
    (mockedAxios.create as jest.Mock).mockReturnValueOnce(mockClient);
    const svc = new BreakglassService(fakeAuth);
    mockClient.post.mockResolvedValueOnce({ status: 201 });

    const transition = { cluster: "c1", to: "g1", duration: 3600 } as any;
    const customDuration = 1800; // 30 minutes instead of 3600
    await svc.requestBreakglass(transition, "testing", customDuration);
    expect(mockClient.post).toHaveBeenCalledWith(
      "/breakglassSessions",
      expect.objectContaining({ duration: 1800, user: "user@example.com" }),
    );
  });

  it("includes scheduled start time when requesting breakglass", async () => {
    const fakeAuth = { getAccessToken: async () => "tok", getUserEmail: async () => "user@example.com" } as any;
    const mockClient: any = {
      post: jest.fn(),
      get: jest.fn(),
      interceptors: { request: { use: jest.fn() }, response: { use: jest.fn() } },
    };
    (mockedAxios.create as jest.Mock).mockReturnValueOnce(mockClient);
    const svc = new BreakglassService(fakeAuth);
    mockClient.post.mockResolvedValueOnce({ status: 201 });

    const transition = { cluster: "c1", to: "g1", duration: 3600 } as any;
    const futureTime = new Date(Date.now() + 3600000).toISOString(); // 1 hour from now
    await svc.requestBreakglass(transition, "scheduled access", 3600, futureTime);
    expect(mockClient.post).toHaveBeenCalledWith(
      "/breakglassSessions",
      expect.objectContaining({
        duration: 3600,
        scheduledStartTime: futureTime,
        user: "user@example.com",
      }),
    );
  });

  it("omits duration when not provided (uses server default)", async () => {
    const fakeAuth = { getAccessToken: async () => "tok", getUserEmail: async () => "user@example.com" } as any;
    const mockClient: any = {
      post: jest.fn(),
      get: jest.fn(),
      interceptors: { request: { use: jest.fn() }, response: { use: jest.fn() } },
    };
    (mockedAxios.create as jest.Mock).mockReturnValueOnce(mockClient);
    const svc = new BreakglassService(fakeAuth);
    mockClient.post.mockResolvedValueOnce({ status: 201 });

    const transition = { cluster: "c1", to: "g1" } as any;
    await svc.requestBreakglass(transition, "needs access");
    // When duration is not provided, it should be 0 or not sent
    expect(mockClient.post).toHaveBeenCalledWith(
      "/breakglassSessions",
      expect.objectContaining({ user: "user@example.com" }),
    );
  });

  it("rejects a breakglass session with reason", async () => {
    const mockClient2: any = {
      post: jest.fn(),
      interceptors: { request: { use: jest.fn() }, response: { use: jest.fn() } },
    };
    (mockedAxios.create as jest.Mock).mockReturnValueOnce(mockClient2);
    const svc = new BreakglassService(fakeAuth);
    mockClient2.post.mockResolvedValueOnce({ status: 200 });

    const result = await svc.rejectBreakglass("test-session", "Not needed");
    expect(mockClient2.post).toHaveBeenCalledWith("/breakglassSessions/test-session/reject", { reason: "Not needed" });
    expect(result.status).toBe(200);
  });

  it("rejects a breakglass session without reason", async () => {
    const mockClient2: any = {
      post: jest.fn(),
      interceptors: { request: { use: jest.fn() }, response: { use: jest.fn() } },
    };
    (mockedAxios.create as jest.Mock).mockReturnValueOnce(mockClient2);
    const svc = new BreakglassService(fakeAuth);
    mockClient2.post.mockResolvedValueOnce({ status: 200 });

    const result = await svc.rejectBreakglass("test-session");
    expect(mockClient2.post).toHaveBeenCalledWith("/breakglassSessions/test-session/reject", {});
    expect(result.status).toBe(200);
  });

  it("rejects a breakglass session and ignores empty reason string", async () => {
    const mockClient2: any = {
      post: jest.fn(),
      interceptors: { request: { use: jest.fn() }, response: { use: jest.fn() } },
    };
    (mockedAxios.create as jest.Mock).mockReturnValueOnce(mockClient2);
    const svc = new BreakglassService(fakeAuth);
    mockClient2.post.mockResolvedValueOnce({ status: 200 });

    const result = await svc.rejectBreakglass("test-session", "   ");
    expect(mockClient2.post).toHaveBeenCalledWith("/breakglassSessions/test-session/reject", {});
    expect(result.status).toBe(200);
  });

  it("approves a breakglass session with reason", async () => {
    const mockClient2: any = {
      post: jest.fn(),
      interceptors: { request: { use: jest.fn() }, response: { use: jest.fn() } },
    };
    (mockedAxios.create as jest.Mock).mockReturnValueOnce(mockClient2);
    const svc = new BreakglassService(fakeAuth);
    mockClient2.post.mockResolvedValueOnce({ status: 200 });

    const result = await svc.approveBreakglass("test-session", "Approved");
    expect(mockClient2.post).toHaveBeenCalledWith("/breakglassSessions/test-session/approve", { reason: "Approved" });
    expect(result.status).toBe(200);
  });

  it("approves a breakglass session without reason", async () => {
    const mockClient2: any = {
      post: jest.fn(),
      interceptors: { request: { use: jest.fn() }, response: { use: jest.fn() } },
    };
    (mockedAxios.create as jest.Mock).mockReturnValueOnce(mockClient2);
    const svc = new BreakglassService(fakeAuth);
    mockClient2.post.mockResolvedValueOnce({ status: 200 });

    const result = await svc.approveBreakglass("test-session");
    expect(mockClient2.post).toHaveBeenCalledWith("/breakglassSessions/test-session/approve", {});
    expect(result.status).toBe(200);
  });
});
