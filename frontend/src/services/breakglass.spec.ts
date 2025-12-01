import { vi, type Mock } from "vitest";
import BreakglassService from "./breakglass";
import { createAuthenticatedApiClient } from "@/services/httpClient";

vi.mock("@/services/httpClient");
const mockedCreateClient = createAuthenticatedApiClient as Mock<typeof createAuthenticatedApiClient>;

describe("BreakglassService", () => {
  const fakeAuth = { getAccessToken: async () => "fake-token" } as any;
  let service: BreakglassService;
  let mockClient: any;

  beforeEach(() => {
    mockClient = {
      get: vi.fn(),
      post: vi.fn(),
      interceptors: {
        request: { use: vi.fn() },
        response: { use: vi.fn() },
      },
    };
    mockedCreateClient.mockReturnValue(mockClient as any);
    service = new BreakglassService(fakeAuth);
  });

  afterEach(() => {
    vi.clearAllMocks();
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

  it("returns an empty list when historical sessions call fails", async () => {
    mockClient.get.mockRejectedValueOnce(new Error("network issue"));

    const sessions = await service.fetchHistoricalSessions();
    expect(sessions).toEqual([]);
    expect(mockClient.get).toHaveBeenCalledTimes(1);
  });

  it("explodes escalations and parses duration strings for all supported units", async () => {
    mockClient.get.mockResolvedValueOnce({
      data: [
        { spec: { allowed: { groups: ["ops"], clusters: ["alpha"] }, escalatedGroup: "ops", maxValidFor: "15s" } },
        { spec: { allowed: { groups: ["db"], clusters: ["beta"] }, escalatedGroup: "db", maxValidFor: "10m" } },
        { spec: { allowed: { groups: ["sec"], clusters: ["gamma"] }, escalatedGroup: "sec", maxValidFor: "2h" } },
        { spec: { allowed: { groups: ["sre"], clusters: ["delta"] }, escalatedGroup: "sre", maxValidFor: "1d" } },
        { spec: { allowed: { groups: ["qa"], clusters: ["epsilon"] }, escalatedGroup: "qa", maxValidFor: "999x" } },
      ],
    });

    const escalations = await (service as any).fetchAvailableEscalations();
    const durationByCluster = new Map(escalations.map((e: any) => [e.cluster, e.duration]));

    expect(durationByCluster.get("alpha")).toBe(15);
    expect(durationByCluster.get("beta")).toBe(600);
    expect(durationByCluster.get("gamma")).toBe(7200);
    expect(durationByCluster.get("delta")).toBe(86400);
    expect(durationByCluster.get("epsilon")).toBe(3600);
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

  it("populates pending and historical matches when combining breakglass sources", async () => {
    const timestamp = new Date().toISOString();
    mockClient.get
      .mockResolvedValueOnce({
        data: [
          { spec: { allowed: { groups: ["ops"], clusters: ["alpha"] }, escalatedGroup: "ops", maxValidFor: "30m" } },
          { spec: { allowed: { groups: ["sec"], clusters: ["beta"] }, escalatedGroup: "sec" } },
        ],
      })
      .mockResolvedValueOnce({ data: [] })
      .mockResolvedValueOnce({
        data: [
          {
            metadata: { name: "pending-1", creationTimestamp: timestamp },
            spec: { grantedGroup: "ops", cluster: "alpha" },
            status: { expiresAt: timestamp, state: "Pending" },
          },
        ],
      })
      .mockResolvedValueOnce({
        data: [
          {
            metadata: { name: "history-1" },
            spec: { grantedGroup: "sec", cluster: "beta" },
            status: { state: "Withdrawn" },
          },
        ],
      });

    const breakglasses = await service.getBreakglasses();
    expect(breakglasses).toHaveLength(2);

    const pendingEntry = breakglasses.find((bg) => bg.cluster === "alpha") as any;
    expect(pendingEntry.state).toBe("Pending");
    expect(pendingEntry.sessionPending.metadata.name).toBe("pending-1");
    expect(pendingEntry.sessionActive).toBeNull();

    const historicalEntry = breakglasses.find((bg) => bg.cluster === "beta") as any;
    expect(historicalEntry.state).toBe("Withdrawn");
    expect(historicalEntry.sessionPending).toBeNull();
    expect(historicalEntry.sessionActive).toBeNull();
  });

  it("includes provided reason when requesting breakglass for test-user", async () => {
    const fakeAuth2 = { getAccessToken: async () => "tok", getUserEmail: async () => "test-user@example.com" } as any;
    const mockClient2: any = {
      post: vi.fn(),
      get: vi.fn(),
      interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
    };
    mockedCreateClient.mockReturnValueOnce(mockClient2);
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
      post: vi.fn(),
      get: vi.fn(),
      interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
    };
    mockedCreateClient.mockReturnValueOnce(mockClient);
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
      post: vi.fn(),
      get: vi.fn(),
      interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
    };
    mockedCreateClient.mockReturnValueOnce(mockClient);
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
      post: vi.fn(),
      get: vi.fn(),
      interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
    };
    mockedCreateClient.mockReturnValueOnce(mockClient);
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
      post: vi.fn(),
      interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
    };
    mockedCreateClient.mockReturnValueOnce(mockClient2);
    const svc = new BreakglassService(fakeAuth);
    mockClient2.post.mockResolvedValueOnce({ status: 200 });

    const result = await svc.rejectBreakglass("test-session", "Not needed");
    expect(mockClient2.post).toHaveBeenCalledWith("/breakglassSessions/test-session/reject", { reason: "Not needed" });
    expect(result.status).toBe(200);
  });

  it("rejects a breakglass session without reason", async () => {
    const mockClient2: any = {
      post: vi.fn(),
      interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
    };
    mockedCreateClient.mockReturnValueOnce(mockClient2);
    const svc = new BreakglassService(fakeAuth);
    mockClient2.post.mockResolvedValueOnce({ status: 200 });

    const result = await svc.rejectBreakglass("test-session");
    expect(mockClient2.post).toHaveBeenCalledWith("/breakglassSessions/test-session/reject", {});
    expect(result.status).toBe(200);
  });

  it("rejects a breakglass session and ignores empty reason string", async () => {
    const mockClient2: any = {
      post: vi.fn(),
      interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
    };
    mockedCreateClient.mockReturnValueOnce(mockClient2);
    const svc = new BreakglassService(fakeAuth);
    mockClient2.post.mockResolvedValueOnce({ status: 200 });

    const result = await svc.rejectBreakglass("test-session", "   ");
    expect(mockClient2.post).toHaveBeenCalledWith("/breakglassSessions/test-session/reject", {});
    expect(result.status).toBe(200);
  });

  it("approves a breakglass session with reason", async () => {
    const mockClient2: any = {
      post: vi.fn(),
      interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
    };
    mockedCreateClient.mockReturnValueOnce(mockClient2);
    const svc = new BreakglassService(fakeAuth);
    mockClient2.post.mockResolvedValueOnce({ status: 200 });

    const result = await svc.approveBreakglass("test-session", "Approved");
    expect(mockClient2.post).toHaveBeenCalledWith("/breakglassSessions/test-session/approve", { reason: "Approved" });
    expect(result.status).toBe(200);
  });

  it("approves a breakglass session without reason", async () => {
    const mockClient2: any = {
      post: vi.fn(),
      interceptors: { request: { use: vi.fn() }, response: { use: vi.fn() } },
    };
    mockedCreateClient.mockReturnValueOnce(mockClient2);
    const svc = new BreakglassService(fakeAuth);
    mockClient2.post.mockResolvedValueOnce({ status: 200 });

    const result = await svc.approveBreakglass("test-session");
    expect(mockClient2.post).toHaveBeenCalledWith("/breakglassSessions/test-session/approve", {});
    expect(result.status).toBe(200);
  });

  it("fetches outstanding requests and falls back to empty arrays on errors", async () => {
    mockClient.get.mockResolvedValueOnce({ data: [{ metadata: { name: "req" } }] });
    const outstanding = await service.fetchMyOutstandingRequests();
    expect(mockClient.get).toHaveBeenCalledWith("/breakglassSessions", {
      params: { mine: true, approver: false, state: "pending" },
    });
    expect(outstanding).toHaveLength(1);

    mockClient.get.mockRejectedValueOnce(new Error("down"));
    const fallback = await service.fetchMyOutstandingRequests();
    expect(fallback).toEqual([]);
  });

  it("normalizes approved sessions when fetching active sessions", async () => {
    mockClient.get.mockResolvedValueOnce({
      data: [
        {
          metadata: { name: "sess" },
          spec: { grantedGroup: "ops", cluster: "c-1" },
          status: { expiresAt: new Date().toISOString(), state: "Approved" },
        },
      ],
    });

    const sessions = await service.fetchActiveSessions();
    expect(sessions[0]).toEqual(
      expect.objectContaining({
        name: "sess",
        group: "ops",
        cluster: "c-1",
        state: "Approved",
        sessionActive: expect.any(Object),
      }),
    );
  });

  it("enriches pending sessions with approval reasons when escalation config matches", async () => {
    mockClient.get
      .mockResolvedValueOnce({
        data: [
          {
            metadata: { name: "pending" },
            spec: { cluster: "c-1", grantedGroup: "ops" },
          },
        ],
      })
      .mockResolvedValueOnce({
        data: [
          {
            spec: {
              allowed: { groups: ["ops"], clusters: ["c-1"] },
              approvers: { groups: ["sec"] },
              escalatedGroup: "ops",
              approvalReason: { mandatory: true, description: "Need manager approval" },
            },
          },
        ],
      });

    const pending = await service.fetchPendingSessionsForApproval();
    const enriched = pending[0] as any;
    expect(enriched.approvalReason).toEqual({ mandatory: true, description: "Need manager approval" });
  });

  it("continues when available escalations cannot be fetched", async () => {
    mockClient.get
      .mockResolvedValueOnce({ data: [{ metadata: { name: "pending" }, spec: {} }] })
      .mockRejectedValueOnce(new Error("config down"));

    const pending = await service.fetchPendingSessionsForApproval();
    expect(pending).toHaveLength(1);
    expect((pending[0] as any).approvalReason).toBeUndefined();
  });

  it("searches sessions with arbitrary parameters and handles failures", async () => {
    mockClient.get.mockResolvedValueOnce({ data: [{ metadata: { name: "s" } }] });
    const results = await service.searchSessions({ mine: true, state: "approved" });
    expect(results).toHaveLength(1);

    mockClient.get.mockRejectedValueOnce(new Error("search boom"));
    const fallback = await service.searchSessions({ mine: true });
    expect(fallback).toEqual([]);
  });

  it("validates requests by passing the token and rethrowing failures", async () => {
    mockClient.get.mockResolvedValueOnce({ status: 200 });
    await service.validateBreakglassRequest("abc");
    expect(mockClient.get).toHaveBeenCalledWith("/breakglassSessions", { params: { token: "abc" } });

    mockClient.get.mockRejectedValueOnce(new Error("bad token"));
    await expect(service.validateBreakglassRequest("abc")).rejects.toThrow("bad token");
  });

  it("drops breakglass sessions using the active session metadata", async () => {
    mockClient.post.mockResolvedValueOnce({ status: 200 });
    const bg = {
      sessionActive: {
        metadata: { name: "session/1" },
      },
    } as any;

    await service.dropBreakglass(bg);
    expect(mockClient.post).toHaveBeenCalledWith("/breakglassSessions/session%2F1/drop", {});

    await expect(service.dropBreakglass({} as any)).rejects.toThrow("Missing session name");
  });

  it("merges approved, timed-out and historical sessions for fetchMySessions", async () => {
    const now = Date.now();
    mockClient.get
      .mockResolvedValueOnce({
        data: [{ metadata: { name: "dup" }, spec: { grantedGroup: "ops", cluster: "c1" }, status: { expiresAt: now } }],
      })
      .mockResolvedValueOnce({
        data: [{ metadata: { name: "dup" }, spec: { grantedGroup: "ops", cluster: "c1" }, status: { expiresAt: now } }],
      })
      .mockResolvedValueOnce({
        data: [
          { metadata: { name: "hist" }, spec: { grantedGroup: "ops", cluster: "c1" }, status: { state: "Rejected" } },
        ],
      });

    const sessions = await service.fetchMySessions();
    const names = sessions.map((s) => s.name);
    expect(names).toContain("dup");
    expect(names).toContain("hist");
    expect(new Set(names).size).toBe(names.length);
  });

  it("returns deduplicated sessions approved by the user", async () => {
    mockClient.get.mockResolvedValueOnce({
      data: [
        { metadata: { name: "same" }, spec: { grantedGroup: "ops", cluster: "c1" }, status: { expiresAt: 1 } },
        { metadata: { name: "same" }, spec: { grantedGroup: "ops", cluster: "c1" }, status: { expiresAt: 1 } },
      ],
    });

    const sessions = await service.fetchSessionsIApproved();
    expect(sessions).toHaveLength(1);
    expect(mockClient.get).toHaveBeenCalledWith("/breakglassSessions", {
      params: { state: "approved,timeout", mine: false, approver: false, approvedByMe: true },
    });
  });

  it("withdraws pending requests and errors when metadata is missing", async () => {
    mockClient.post.mockResolvedValueOnce({ status: 204 });
    await service.withdrawMyRequest({ metadata: { name: "pending" } } as any);
    expect(mockClient.post).toHaveBeenCalledWith("/breakglassSessions/pending/withdraw", {});

    await expect(service.withdrawMyRequest({ metadata: {} } as any)).rejects.toThrow("Missing session name");
  });

  it("rethrows errors when withdrawing requests fails", async () => {
    mockClient.post.mockRejectedValueOnce(new Error("withdraw failed"));

    await expect(service.withdrawMyRequest({ metadata: { name: "oops" } } as any)).rejects.toThrow("withdraw failed");
    expect(mockClient.post).toHaveBeenCalledWith("/breakglassSessions/oops/withdraw", {});
  });

  it("sends payloads via testButton helper", async () => {
    mockClient.post.mockResolvedValueOnce({ status: 200 });
    await service.testButton("user", "cluster");
    expect(mockClient.post).toHaveBeenCalledWith("/test", { user: "user", cluster: "cluster" });
  });
});
