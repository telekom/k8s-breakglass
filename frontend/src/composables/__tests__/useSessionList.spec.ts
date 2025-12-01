/**
 * Tests for useSessionList composable
 */

import { vi } from "vitest";
import {
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
  });
});
