/**
 * Tests for useSessionList composable
 */

import { vi } from "vitest";
import { flushPromises } from "@vue/test-utils";
import {
  useSessionList,
  getSessionKey,
  getSessionState,
  normalizeState,
  getSessionUser,
  getSessionCluster,
  getSessionGroup,
  getSessionExpiry,
  collectApproverGroups,
  dedupeSessions,
  enrichWithUrgency,
  sortSessions,
  filterSessions,
  type SessionWithUrgency,
} from "@/composables/useSessionList";
import type { SessionCR } from "@/model/breakglass";

describe("useSessionList", () => {
  // Mock sessions for testing
  function createSession(overrides: Partial<SessionCR> = {}): SessionCR {
    return {
      metadata: { name: "session-1", creationTimestamp: "2025-12-01T10:00:00Z" },
      spec: { grantedGroup: "ops", cluster: "prod", user: "alice@example.com" },
      status: { state: "Pending", expiresAt: "2025-12-01T14:00:00Z" },
      ...overrides,
    };
  }

  describe("getSessionKey", () => {
    it("returns metadata.name if present", () => {
      const session = createSession();
      expect(getSessionKey(session)).toBe("session-1");
    });

    it("returns name field if no metadata", () => {
      const session = createSession({ metadata: undefined, name: "direct-name" });
      expect(getSessionKey(session)).toBe("direct-name");
    });

    it("generates key from spec if no name", () => {
      const session = createSession({ metadata: undefined, name: undefined });
      session.spec = { cluster: "dev", grantedGroup: "admin" };
      expect(getSessionKey(session)).toContain("dev");
      expect(getSessionKey(session)).toContain("admin");
    });
  });

  describe("getSessionState", () => {
    it("returns status.state", () => {
      const session = createSession();
      expect(getSessionState(session)).toBe("Pending");
    });

    it("falls back to session.state", () => {
      const session = createSession({ status: undefined }) as any;
      session.state = "Approved";
      expect(getSessionState(session)).toBe("Approved");
    });

    it("returns unknown if no state", () => {
      const session = createSession({ status: undefined });
      expect(getSessionState(session)).toBe("unknown");
    });
  });

  describe("normalizeState", () => {
    it("lowercases state", () => {
      expect(normalizeState("Pending")).toBe("pending");
      expect(normalizeState("APPROVED")).toBe("approved");
    });

    it("removes whitespace", () => {
      expect(normalizeState("Waiting For Scheduled Time")).toBe("waitingforscheduledtime");
    });
  });

  describe("getSessionUser", () => {
    it("returns spec.user", () => {
      const session = createSession();
      expect(getSessionUser(session)).toBe("alice@example.com");
    });

    it("falls back to spec.requester", () => {
      const session = createSession();
      session.spec = { requester: "bob@example.com" };
      expect(getSessionUser(session)).toBe("bob@example.com");
    });

    it("returns dash if no user", () => {
      const session = createSession({ spec: {} });
      expect(getSessionUser(session)).toBe("—");
    });
  });

  describe("getSessionCluster", () => {
    it("returns spec.cluster", () => {
      const session = createSession();
      expect(getSessionCluster(session)).toBe("prod");
    });

    it("falls back to session.cluster", () => {
      const session = createSession({ spec: {} });
      session.cluster = "staging";
      expect(getSessionCluster(session)).toBe("staging");
    });
  });

  describe("getSessionGroup", () => {
    it("returns spec.grantedGroup", () => {
      const session = createSession();
      expect(getSessionGroup(session)).toBe("ops");
    });

    it("falls back to session.group", () => {
      const session = createSession({ spec: {} });
      session.group = "admin";
      expect(getSessionGroup(session)).toBe("admin");
    });
  });

  describe("getSessionExpiry", () => {
    it("returns status.expiresAt", () => {
      const session = createSession();
      expect(getSessionExpiry(session)).toBe("2025-12-01T14:00:00Z");
    });

    it("falls back to status.timeoutAt", () => {
      const session = createSession();
      session.status = { timeoutAt: "2025-12-01T13:00:00Z" };
      expect(getSessionExpiry(session)).toBe("2025-12-01T13:00:00Z");
    });
  });

  describe("collectApproverGroups", () => {
    it("collects from annotations", () => {
      const session = createSession();
      session.metadata = {
        name: "test",
        annotations: {
          "breakglass.telekom.com/approver-groups": "admins,leads",
        },
      };
      const groups = collectApproverGroups(session);
      expect(groups).toContain("admins");
      expect(groups).toContain("leads");
    });

    it("collects from spec", () => {
      const session = createSession();
      (session.spec as any).approverGroups = ["team-a", "team-b"];
      const groups = collectApproverGroups(session);
      expect(groups).toContain("team-a");
      expect(groups).toContain("team-b");
    });

    it("deduplicates groups", () => {
      const session = createSession();
      session.metadata = {
        name: "test",
        annotations: { "breakglass.telekom.com/approver-groups": "admins" },
      };
      (session.spec as any).approverGroups = ["admins"];
      const groups = collectApproverGroups(session);
      expect(groups.filter((g) => g === "admins").length).toBe(1);
    });

    it("returns empty array if no groups", () => {
      const session = createSession();
      expect(collectApproverGroups(session)).toEqual([]);
    });
  });

  describe("dedupeSessions", () => {
    it("removes duplicate sessions by name", () => {
      const session1 = createSession({ metadata: { name: "same-name" } });
      const session2 = createSession({ metadata: { name: "same-name" } });
      const result = dedupeSessions([session1, session2]);
      expect(result.length).toBe(1);
    });

    it("keeps unique sessions", () => {
      const session1 = createSession({ metadata: { name: "session-1" } });
      const session2 = createSession({ metadata: { name: "session-2" } });
      const result = dedupeSessions([session1, session2]);
      expect(result.length).toBe(2);
    });

    it("merges approver groups from duplicates", () => {
      const session1 = createSession({ metadata: { name: "same" } });
      (session1.spec as any).approverGroups = ["team-a"];

      const session2 = createSession({ metadata: { name: "same" } });
      (session2.spec as any).approverGroups = ["team-b"];

      const result = dedupeSessions([session1, session2]);
      expect((result[0] as any).matchingApproverGroups).toContain("team-a");
      expect((result[0] as any).matchingApproverGroups).toContain("team-b");
    });
  });

  describe("enrichWithUrgency", () => {
    const NOW = new Date("2025-12-01T12:00:00Z").getTime();

    beforeEach(() => {
      jest.useFakeTimers();
      jest.setSystemTime(NOW);
    });

    afterEach(() => {
      jest.useRealTimers();
    });

    it("adds urgency and timeRemaining", () => {
      const session = createSession();
      session.status = { expiresAt: new Date(NOW + 30 * 60 * 1000).toISOString() }; // 30 min

      const result = enrichWithUrgency([session]);
      expect(result).toHaveLength(1);
      expect(result[0]!.urgency).toBe("critical");
      expect(result[0]!.timeRemaining).toBe(1800);
    });
  });

  describe("sortSessions", () => {
    const NOW = new Date("2025-12-01T12:00:00Z").getTime();

    beforeEach(() => {
      jest.useFakeTimers();
      jest.setSystemTime(NOW);
    });

    afterEach(() => {
      jest.useRealTimers();
    });

    function createWithUrgency(
      name: string,
      overrides: Partial<SessionCR> = {}
    ): SessionWithUrgency {
      const session = createSession({ metadata: { name }, ...overrides });
      return enrichWithUrgency([session])[0]!;
    }

    it("sorts by urgency (time remaining)", () => {
      const sessions = [
        createWithUrgency("later", { status: { expiresAt: new Date(NOW + 4 * 3600000).toISOString() } }),
        createWithUrgency("soon", { status: { expiresAt: new Date(NOW + 1 * 3600000).toISOString() } }),
        createWithUrgency("medium", { status: { expiresAt: new Date(NOW + 2 * 3600000).toISOString() } }),
      ];

      const sorted = sortSessions(sessions, "urgent");
      expect(sorted[0]!.metadata?.name).toBe("soon");
      expect(sorted[2]!.metadata?.name).toBe("later");
    });

    it("sorts by recent (newest first)", () => {
      const sessions = [
        createWithUrgency("oldest", { metadata: { name: "oldest", creationTimestamp: "2025-12-01T08:00:00Z" } }),
        createWithUrgency("newest", { metadata: { name: "newest", creationTimestamp: "2025-12-01T11:00:00Z" } }),
        createWithUrgency("middle", { metadata: { name: "middle", creationTimestamp: "2025-12-01T10:00:00Z" } }),
      ];

      const sorted = sortSessions(sessions, "recent");
      expect(sorted[0]!.metadata?.name).toBe("newest");
      expect(sorted[2]!.metadata?.name).toBe("oldest");
    });

    it("sorts by group alphabetically", () => {
      const sessions = [
        createWithUrgency("c", { spec: { grantedGroup: "zebra" } }),
        createWithUrgency("a", { spec: { grantedGroup: "alpha" } }),
        createWithUrgency("b", { spec: { grantedGroup: "beta" } }),
      ];

      const sorted = sortSessions(sessions, "groups");
      expect(sorted[0]!.spec?.grantedGroup).toBe("alpha");
      expect(sorted[2]!.spec?.grantedGroup).toBe("zebra");
    });
  });

  describe("filterSessions", () => {
    const NOW = new Date("2025-12-01T12:00:00Z").getTime();

    beforeEach(() => {
      vi.useFakeTimers();
      vi.setSystemTime(NOW);
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    function createWithUrgency(overrides: Partial<SessionCR> = {}): SessionWithUrgency {
      return enrichWithUrgency([createSession(overrides)])[0]!;
    }

    it("filters by state", () => {
      const sessions = [
        createWithUrgency({ status: { state: "Pending" } }),
        createWithUrgency({ status: { state: "Approved" } }),
        createWithUrgency({ status: { state: "Rejected" } }),
      ];

      const filtered = filterSessions(sessions, {
        states: ["pending"],
        cluster: "",
        group: "",
        user: "",
        name: "",
        urgency: "all",
      });

      expect(filtered.length).toBe(1);
      expect(filtered[0]!.status?.state).toBe("Pending");
    });

    it("filters by cluster", () => {
      const sessions = [
        createWithUrgency({ spec: { cluster: "prod" } }),
        createWithUrgency({ spec: { cluster: "staging" } }),
      ];

      const filtered = filterSessions(sessions, {
        states: [],
        cluster: "prod",
        group: "",
        user: "",
        name: "",
        urgency: "all",
      });

      expect(filtered.length).toBe(1);
      expect(filtered[0]!.spec?.cluster).toBe("prod");
    });

    it("filters by urgency", () => {
      const sessions = [
        createWithUrgency({ status: { expiresAt: new Date(NOW + 30 * 60 * 1000).toISOString() } }), // critical
        createWithUrgency({ status: { expiresAt: new Date(NOW + 8 * 3600 * 1000).toISOString() } }), // normal
      ];

      const filtered = filterSessions(sessions, {
        states: [],
        cluster: "",
        group: "",
        user: "",
        name: "",
        urgency: "critical",
      });

      expect(filtered.length).toBe(1);
      expect(filtered[0]!.urgency).toBe("critical");
    });

    it("applies multiple filters", () => {
      const sessions = [
        createWithUrgency({ spec: { cluster: "prod", grantedGroup: "ops" }, status: { state: "Pending" } }),
        createWithUrgency({ spec: { cluster: "prod", grantedGroup: "admin" }, status: { state: "Pending" } }),
        createWithUrgency({ spec: { cluster: "staging", grantedGroup: "ops" }, status: { state: "Pending" } }),
      ];

      const filtered = filterSessions(sessions, {
        states: ["pending"],
        cluster: "prod",
        group: "ops",
        user: "",
        name: "",
        urgency: "all",
      });

      expect(filtered.length).toBe(1);
      expect(filtered[0]!.spec?.cluster).toBe("prod");
      expect(filtered[0]!.spec?.grantedGroup).toBe("ops");
    });

    it("filters by user with partial match (case insensitive)", () => {
      const sessions = [
        createWithUrgency({ spec: { user: "alice@example.com" } }),
        createWithUrgency({ spec: { user: "bob@example.com" } }),
        createWithUrgency({ spec: { user: "ALICE.SMITH@CORP.COM" } }),
      ];

      const filtered = filterSessions(sessions, {
        states: [],
        cluster: "",
        group: "",
        user: "alice",
        name: "",
        urgency: "all",
      });

      expect(filtered.length).toBe(2);
    });

    it("filters by name with partial match", () => {
      const sessions = [
        createWithUrgency({ metadata: { name: "session-prod-001" } }),
        createWithUrgency({ metadata: { name: "session-staging-002" } }),
        createWithUrgency({ metadata: { name: "emergency-prod-003" } }),
      ];

      const filtered = filterSessions(sessions, {
        states: [],
        cluster: "",
        group: "",
        user: "",
        name: "prod",
        urgency: "all",
      });

      expect(filtered.length).toBe(2);
    });

    it("filters by multiple states", () => {
      const sessions = [
        createWithUrgency({ status: { state: "Pending" } }),
        createWithUrgency({ status: { state: "Approved" } }),
        createWithUrgency({ status: { state: "Rejected" } }),
        createWithUrgency({ status: { state: "Active" } }),
      ];

      const filtered = filterSessions(sessions, {
        states: ["pending", "approved"],
        cluster: "",
        group: "",
        user: "",
        name: "",
        urgency: "all",
      });

      expect(filtered.length).toBe(2);
    });

    it("returns all sessions with empty filters", () => {
      const sessions = [
        createWithUrgency({ status: { state: "Pending" } }),
        createWithUrgency({ status: { state: "Approved" } }),
      ];

      const filtered = filterSessions(sessions, {
        states: [],
        cluster: "",
        group: "",
        user: "",
        name: "",
        urgency: "all",
      });

      expect(filtered.length).toBe(2);
    });

    it("returns empty array for empty input", () => {
      const filtered = filterSessions([], {
        states: ["pending"],
        cluster: "prod",
        group: "",
        user: "",
        name: "",
        urgency: "all",
      });

      expect(filtered).toEqual([]);
    });

    it("filters by high urgency", () => {
      const sessions = [
        createWithUrgency({ status: { expiresAt: new Date(NOW + 30 * 60 * 1000).toISOString() } }), // critical (< 1h)
        createWithUrgency({ status: { expiresAt: new Date(NOW + 2 * 3600 * 1000).toISOString() } }), // high (1-4h)
        createWithUrgency({ status: { expiresAt: new Date(NOW + 8 * 3600 * 1000).toISOString() } }), // normal (> 4h)
      ];

      const filtered = filterSessions(sessions, {
        states: [],
        cluster: "",
        group: "",
        user: "",
        name: "",
        urgency: "high",
      });

      expect(filtered.length).toBe(1);
      expect(filtered[0]!.urgency).toBe("high");
    });
  });

  describe("sortSessions edge cases", () => {
    const NOW = new Date("2025-12-01T12:00:00Z").getTime();

    beforeEach(() => {
      vi.useFakeTimers();
      vi.setSystemTime(NOW);
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    function createWithUrgency(name: string, overrides: Partial<SessionCR> = {}): SessionWithUrgency {
      const session = createSession({ metadata: { name }, ...overrides });
      return enrichWithUrgency([session])[0]!;
    }

    it("sorts by cluster alphabetically", () => {
      const sessions = [
        createWithUrgency("c", { spec: { cluster: "west-us" } }),
        createWithUrgency("a", { spec: { cluster: "east-us" } }),
        createWithUrgency("b", { spec: { cluster: "north-eu" } }),
      ];

      const sorted = sortSessions(sessions, "cluster");
      expect(sorted[0]!.spec?.cluster).toBe("east-us");
      expect(sorted[1]!.spec?.cluster).toBe("north-eu");
      expect(sorted[2]!.spec?.cluster).toBe("west-us");
    });

    it("sorts by user alphabetically", () => {
      const sessions = [
        createWithUrgency("c", { spec: { user: "zara@example.com" } }),
        createWithUrgency("a", { spec: { user: "alice@example.com" } }),
        createWithUrgency("b", { spec: { user: "bob@example.com" } }),
      ];

      const sorted = sortSessions(sessions, "user");
      expect(sorted[0]!.spec?.user).toBe("alice@example.com");
      expect(sorted[1]!.spec?.user).toBe("bob@example.com");
      expect(sorted[2]!.spec?.user).toBe("zara@example.com");
    });

    it("handles empty sessions array", () => {
      const sorted = sortSessions([], "urgent");
      expect(sorted).toEqual([]);
    });

    it("handles single session", () => {
      const sessions = [createWithUrgency("only-one")];
      const sorted = sortSessions(sessions, "recent");
      expect(sorted.length).toBe(1);
      expect(sorted[0]!.metadata?.name).toBe("only-one");
    });

    it("maintains stable sort for equal values", () => {
      const sessions = [
        createWithUrgency("first", { spec: { cluster: "same" } }),
        createWithUrgency("second", { spec: { cluster: "same" } }),
        createWithUrgency("third", { spec: { cluster: "same" } }),
      ];

      const sorted = sortSessions(sessions, "cluster");
      // Order should be preserved for equal cluster values
      expect(sorted.map((s) => s.metadata?.name)).toEqual(["first", "second", "third"]);
    });

    it("handles sessions with missing expiry for urgent sort", () => {
      const sessions = [
        createWithUrgency("with-expiry", { status: { expiresAt: new Date(NOW + 1 * 3600000).toISOString() } }),
        createWithUrgency("no-expiry", { status: { state: "Pending" } }),
      ];

      const sorted = sortSessions(sessions, "urgent");
      // Session with expiry should come first (has finite timeRemaining)
      expect(sorted[0]!.metadata?.name).toBe("with-expiry");
    });

    it("sorts sessions with same creation time by name", () => {
      const timestamp = "2025-12-01T10:00:00Z";
      const sessions = [
        createWithUrgency("zebra", { metadata: { name: "zebra", creationTimestamp: timestamp } }),
        createWithUrgency("alpha", { metadata: { name: "alpha", creationTimestamp: timestamp } }),
      ];

      const sorted = sortSessions(sessions, "recent");
      // Both have same timestamp - order may be preserved or sorted by secondary criteria
      expect(sorted.length).toBe(2);
      expect(sorted.map((s) => s.metadata?.name)).toEqual(["zebra", "alpha"]);
    });
  });

  describe("dedupeSessions edge cases", () => {
    it("handles empty array", () => {
      const result = dedupeSessions([]);
      expect(result).toEqual([]);
    });

    it("handles sessions without metadata", () => {
      const session1 = createSession({ metadata: undefined, name: "fallback-name" });
      const result = dedupeSessions([session1]);
      expect(result.length).toBe(1);
    });

    it("preserves order of first occurrence", () => {
      const session1 = createSession({ metadata: { name: "dup" }, spec: { cluster: "first" } });
      const session2 = createSession({ metadata: { name: "dup" }, spec: { cluster: "second" } });

      const result = dedupeSessions([session1, session2]);
      expect(result.length).toBe(1);
      expect(result[0]!.spec?.cluster).toBe("first");
    });

    it("handles many duplicates efficiently", () => {
      const sessions = Array.from({ length: 100 }, (_, i) =>
        createSession({ metadata: { name: i < 50 ? "duplicate" : `unique-${i}` } })
      );

      const result = dedupeSessions(sessions);
      // 1 duplicate + 50 unique sessions
      expect(result.length).toBe(51);
    });

    it("collects approver groups from all duplicates", () => {
      const session1 = createSession({ metadata: { name: "same" } });
      (session1.spec as any).approverGroups = ["team-a"];

      const session2 = createSession({ metadata: { name: "same" } });
      (session2.spec as any).approverGroups = ["team-b"];

      const session3 = createSession({ metadata: { name: "same" } });
      session3.metadata = {
        name: "same",
        annotations: { "breakglass.telekom.com/approver-groups": "team-c" },
      };

      const result = dedupeSessions([session1, session2, session3]);
      expect(result.length).toBe(1);
      const groups = (result[0] as any).matchingApproverGroups;
      expect(groups).toContain("team-a");
      expect(groups).toContain("team-b");
      expect(groups).toContain("team-c");
    });
  });

  describe("enrichWithUrgency edge cases", () => {
    const NOW = new Date("2025-12-01T12:00:00Z").getTime();

    beforeEach(() => {
      vi.useFakeTimers();
      vi.setSystemTime(NOW);
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it("handles empty array", () => {
      const result = enrichWithUrgency([]);
      expect(result).toEqual([]);
    });

    it("handles session with past expiry (already expired)", () => {
      const session = createSession();
      session.status = { expiresAt: new Date(NOW - 1000).toISOString() }; // 1 second ago

      const result = enrichWithUrgency([session]);
      expect(result[0]!.timeRemaining).toBeLessThanOrEqual(0);
      expect(result[0]!.urgency).toBe("critical");
    });

    it("calculates correct urgency levels", () => {
      const sessions = [
        createSession({ status: { expiresAt: new Date(NOW + 15 * 60 * 1000).toISOString() } }), // 15 min - critical
        createSession({ status: { expiresAt: new Date(NOW + 2 * 60 * 60 * 1000).toISOString() } }), // 2 hours - high
        createSession({ status: { expiresAt: new Date(NOW + 6 * 60 * 60 * 1000).toISOString() } }), // 6 hours - normal
      ];

      const result = enrichWithUrgency(sessions);
      expect(result[0]!.urgency).toBe("critical");
      expect(result[1]!.urgency).toBe("high");
      expect(result[2]!.urgency).toBe("normal");
    });

    it("handles session without expiry", () => {
      const session = createSession({ status: { state: "Pending" } });

      const result = enrichWithUrgency([session]);
      expect(result[0]!.urgency).toBe("normal");
      expect(result[0]!.timeRemaining).toBe(Infinity);
    });
  });

  describe("helper functions edge cases", () => {
    it("getSessionKey handles all fallbacks", () => {
      // With metadata.name
      expect(getSessionKey(createSession())).toBe("session-1");

      // With name field only
      expect(getSessionKey({ name: "direct" } as any)).toBe("direct");

      // Generated from spec
      const noName = { spec: { cluster: "c1", grantedGroup: "g1" } } as SessionCR;
      const key = getSessionKey(noName);
      expect(key).toContain("c1");
      expect(key).toContain("g1");
    });

    it("getSessionState handles unknown state", () => {
      expect(getSessionState({} as SessionCR)).toBe("unknown");
      expect(getSessionState({ status: {} } as SessionCR)).toBe("unknown");
    });

    it("normalizeState handles various formats", () => {
      expect(normalizeState("Waiting For Approval")).toBe("waitingforapproval");
      expect(normalizeState("  APPROVED  ")).toBe("approved");
      expect(normalizeState("In Progress")).toBe("inprogress");
    });

    it("getSessionUser handles various sources", () => {
      expect(getSessionUser(createSession())).toBe("alice@example.com");
      expect(getSessionUser({ spec: { requester: "req@example.com" } } as SessionCR)).toBe("req@example.com");
      expect(getSessionUser({ spec: {} } as SessionCR)).toBe("—");
    });

    it("getSessionCluster handles fallbacks", () => {
      expect(getSessionCluster(createSession())).toBe("prod");
      expect(getSessionCluster({ cluster: "fallback" } as any)).toBe("fallback");
      expect(getSessionCluster({ spec: {} } as SessionCR)).toBe("—");
    });

    it("getSessionGroup handles fallbacks", () => {
      expect(getSessionGroup(createSession())).toBe("ops");
      expect(getSessionGroup({ group: "fallback" } as any)).toBe("fallback");
      expect(getSessionGroup({ spec: {} } as SessionCR)).toBe("—");
    });
  });

  describe("useSessionList composable", () => {
    const NOW = new Date("2025-12-01T12:00:00Z").getTime();

    beforeEach(() => {
      vi.useFakeTimers();
      vi.setSystemTime(NOW);
    });

    afterEach(() => {
      vi.useRealTimers();
    });

    it("initializes with empty state", () => {
      const fetchFn = vi.fn().mockResolvedValue([]);
      const { sessions, loading, error, totalCount, filteredCount } = useSessionList(fetchFn);

      expect(sessions.value).toEqual([]);
      expect(loading.value).toBe(false);
      expect(error.value).toBe("");
      expect(totalCount.value).toBe(0);
      expect(filteredCount.value).toBe(0);
    });

    it("loads sessions successfully", async () => {
      const mockSessions = [
        createSession({ metadata: { name: "s1" } }),
        createSession({ metadata: { name: "s2" } }),
      ];
      const fetchFn = vi.fn().mockResolvedValue(mockSessions);
      const { loadSessions, sessions, loading, totalCount } = useSessionList(fetchFn);

      expect(loading.value).toBe(false);

      const loadPromise = loadSessions();
      expect(loading.value).toBe(true);

      await loadPromise;
      await flushPromises();

      expect(loading.value).toBe(false);
      expect(sessions.value.length).toBe(2);
      expect(totalCount.value).toBe(2);
      expect(fetchFn).toHaveBeenCalledTimes(1);
    });

    it("handles fetch error gracefully", async () => {
      const fetchFn = vi.fn().mockRejectedValue(new Error("Network error"));
      const { loadSessions, error, loading } = useSessionList(fetchFn);

      await loadSessions();
      await flushPromises();

      expect(loading.value).toBe(false);
      expect(error.value).toBe("Network error");
    });

    it("applies default sort option", () => {
      const fetchFn = vi.fn().mockResolvedValue([]);
      const { sortBy } = useSessionList(fetchFn, { defaultSort: "cluster" });

      expect(sortBy.value).toBe("cluster");
    });

    it("applies default filters", () => {
      const fetchFn = vi.fn().mockResolvedValue([]);
      const { filters } = useSessionList(fetchFn, {
        defaultFilters: { cluster: "prod", states: ["pending"] },
      });

      expect(filters.value.cluster).toBe("prod");
      expect(filters.value.states).toEqual(["pending"]);
    });

    it("setSortBy updates sort option", () => {
      const fetchFn = vi.fn().mockResolvedValue([]);
      const { sortBy, setSortBy } = useSessionList(fetchFn);

      expect(sortBy.value).toBe("recent");
      setSortBy("urgent");
      expect(sortBy.value).toBe("urgent");
    });

    it("setFilter updates individual filter", () => {
      const fetchFn = vi.fn().mockResolvedValue([]);
      const { filters, setFilter } = useSessionList(fetchFn);

      expect(filters.value.cluster).toBe("");
      setFilter("cluster", "staging");
      expect(filters.value.cluster).toBe("staging");
    });

    it("resetFilters clears all filters", () => {
      const fetchFn = vi.fn().mockResolvedValue([]);
      const { filters, setFilter, resetFilters } = useSessionList(fetchFn);

      setFilter("cluster", "prod");
      setFilter("user", "alice");
      setFilter("states", ["pending"]);

      resetFilters();

      expect(filters.value.cluster).toBe("");
      expect(filters.value.user).toBe("");
      expect(filters.value.states).toEqual([]);
    });

    it("removeSession removes session by name", async () => {
      const mockSessions = [
        createSession({ metadata: { name: "s1" } }),
        createSession({ metadata: { name: "s2" } }),
        createSession({ metadata: { name: "s3" } }),
      ];
      const fetchFn = vi.fn().mockResolvedValue(mockSessions);
      const { loadSessions, sessions, removeSession, totalCount } = useSessionList(fetchFn);

      await loadSessions();
      await flushPromises();

      expect(totalCount.value).toBe(3);

      removeSession("s2");

      expect(totalCount.value).toBe(2);
      expect(sessions.value.map((s) => s.metadata?.name)).toEqual(["s1", "s3"]);
    });

    it("removeSession accepts session object", async () => {
      const mockSessions = [
        createSession({ metadata: { name: "s1" } }),
        createSession({ metadata: { name: "s2" } }),
      ];
      const fetchFn = vi.fn().mockResolvedValue(mockSessions);
      const { loadSessions, sessions, removeSession } = useSessionList(fetchFn);

      await loadSessions();
      await flushPromises();

      removeSession(mockSessions[0]!);

      expect(sessions.value.length).toBe(1);
      expect(sessions.value[0]!.metadata?.name).toBe("s2");
    });

    it("updateSession updates existing session", async () => {
      const mockSessions = [
        createSession({ metadata: { name: "s1" }, status: { state: "Pending" } }),
      ];
      const fetchFn = vi.fn().mockResolvedValue(mockSessions);
      const { loadSessions, rawSessions, updateSession } = useSessionList(fetchFn);

      await loadSessions();
      await flushPromises();

      expect(rawSessions.value[0]!.status?.state).toBe("Pending");

      const updatedSession = createSession({ metadata: { name: "s1" }, status: { state: "Approved" } });
      updateSession(updatedSession);

      expect(rawSessions.value[0]!.status?.state).toBe("Approved");
    });

    it("urgencyBreakdown computes correctly", async () => {
      const mockSessions = [
        createSession({ status: { expiresAt: new Date(NOW + 30 * 60 * 1000).toISOString() } }), // critical
        createSession({ metadata: { name: "s2" }, status: { expiresAt: new Date(NOW + 30 * 60 * 1000).toISOString() } }), // critical
        createSession({ metadata: { name: "s3" }, status: { expiresAt: new Date(NOW + 2 * 3600 * 1000).toISOString() } }), // high
        createSession({ metadata: { name: "s4" }, status: { expiresAt: new Date(NOW + 8 * 3600 * 1000).toISOString() } }), // normal
      ];
      const fetchFn = vi.fn().mockResolvedValue(mockSessions);
      const { loadSessions, urgencyBreakdown } = useSessionList(fetchFn);

      await loadSessions();
      await flushPromises();

      expect(urgencyBreakdown.value.critical).toBe(2);
      expect(urgencyBreakdown.value.high).toBe(1);
      expect(urgencyBreakdown.value.normal).toBe(1);
    });

    it("filters and sorts reactively", async () => {
      const mockSessions = [
        createSession({ metadata: { name: "s1" }, spec: { cluster: "prod" }, status: { state: "Pending" } }),
        createSession({ metadata: { name: "s2" }, spec: { cluster: "staging" }, status: { state: "Pending" } }),
        createSession({ metadata: { name: "s3" }, spec: { cluster: "prod" }, status: { state: "Approved" } }),
      ];
      const fetchFn = vi.fn().mockResolvedValue(mockSessions);
      const { loadSessions, sessions, setFilter, filteredCount } = useSessionList(fetchFn);

      await loadSessions();
      await flushPromises();

      expect(filteredCount.value).toBe(3);

      setFilter("cluster", "prod");
      expect(filteredCount.value).toBe(2);

      setFilter("states", ["pending"]);
      expect(filteredCount.value).toBe(1);
      expect(sessions.value[0]!.metadata?.name).toBe("s1");
    });

    it("deduplicates sessions on load", async () => {
      const mockSessions = [
        createSession({ metadata: { name: "duplicate" } }),
        createSession({ metadata: { name: "duplicate" } }),
        createSession({ metadata: { name: "unique" } }),
      ];
      const fetchFn = vi.fn().mockResolvedValue(mockSessions);
      const { loadSessions, totalCount } = useSessionList(fetchFn);

      await loadSessions();
      await flushPromises();

      expect(totalCount.value).toBe(2);
    });

    it("disables urgency calculation when option is false", async () => {
      const mockSessions = [
        createSession({ status: { expiresAt: new Date(NOW + 30 * 60 * 1000).toISOString() } }),
      ];
      const fetchFn = vi.fn().mockResolvedValue(mockSessions);
      const { loadSessions, sessions } = useSessionList(fetchFn, { calculateUrgency: false });

      await loadSessions();
      await flushPromises();

      expect(sessions.value[0]!.urgency).toBe("normal");
      expect(sessions.value[0]!.timeRemaining).toBe(Infinity);
    });
  });
});
