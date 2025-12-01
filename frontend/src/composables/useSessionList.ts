/**
 * Composable for managing session lists with filtering, sorting, and pagination
 */

import { ref, computed, type Ref, type ComputedRef } from "vue";
import type { SessionCR } from "@/model/breakglass";
import { getTimeRemaining, getUrgency, type UrgencyLevel } from "./useUrgency";
import { debug, warn } from "@/services/logger";

const TAG = "useSessionList";

export type SortOption = "urgent" | "recent" | "groups" | "cluster" | "user";
export type SessionState =
  | "pending"
  | "approved"
  | "active"
  | "rejected"
  | "withdrawn"
  | "timeout"
  | "expired"
  | "scheduled";

export interface SessionWithUrgency extends SessionCR {
  urgency: UrgencyLevel;
  timeRemaining: number;
  matchingApproverGroups?: string[];
}

export interface SessionListFilters {
  states: SessionState[];
  cluster: string;
  group: string;
  user: string;
  name: string;
  urgency: "all" | UrgencyLevel;
}

export interface SessionListOptions {
  /** Initial sort option */
  defaultSort?: SortOption;
  /** Initial filters */
  defaultFilters?: Partial<SessionListFilters>;
  /** Enable urgency calculation */
  calculateUrgency?: boolean;
}

const DEFAULT_FILTERS: SessionListFilters = {
  states: [],
  cluster: "",
  group: "",
  user: "",
  name: "",
  urgency: "all",
};

/**
 * Extract session name for keying
 */
export function getSessionKey(session: SessionCR): string {
  return (
    session.metadata?.name ||
    session.name ||
    `${session.spec?.cluster || "unknown"}-${session.spec?.grantedGroup || "unknown"}-${session.metadata?.creationTimestamp || ""}`
  );
}

/**
 * Get session state from CR
 */
export function getSessionState(session: SessionCR): string {
  return session.status?.state || (session as any).state || "unknown";
}

/**
 * Normalize session state for comparison
 */
export function normalizeState(state: string): string {
  return state.toLowerCase().replace(/\s+/g, "");
}

/**
 * Get session user/requester
 */
export function getSessionUser(session: SessionCR): string {
  return session.spec?.user || session.spec?.requester || (session as any).user || "—";
}

/**
 * Get session cluster
 */
export function getSessionCluster(session: SessionCR): string {
  return session.spec?.cluster || session.cluster || "—";
}

/**
 * Get session granted group
 */
export function getSessionGroup(session: SessionCR): string {
  return session.spec?.grantedGroup || session.group || "—";
}

/**
 * Get session expiry time
 */
export function getSessionExpiry(session: SessionCR): string | undefined {
  return session.status?.expiresAt || session.status?.timeoutAt;
}

/**
 * Get session start time
 */
export function getSessionStarted(session: SessionCR): string | undefined {
  return (
    (session as any).started ||
    session.status?.actualStartTime ||
    (session.status as any)?.startedAt ||
    session.metadata?.creationTimestamp ||
    (session as any).createdAt
  );
}

/**
 * Get session end time (only for non-active sessions)
 */
export function getSessionEnded(session: SessionCR): string | undefined {
  const state = normalizeState(getSessionState(session));
  if (state === "approved" || state === "active") {
    return undefined;
  }
  return session.status?.endedAt || session.status?.expiresAt || (session as any).ended;
}

/**
 * Collect approver groups from various session fields
 */
export function collectApproverGroups(session: SessionCR): string[] {
  const groups = new Set<string>();

  const tryAdd = (value?: string | string[]) => {
    if (!value) return;
    if (Array.isArray(value)) {
      value.filter(Boolean).forEach((v) => groups.add(String(v)));
    } else {
      String(value)
        .split(/[\s,]+/)
        .map((v) => v.trim())
        .filter(Boolean)
        .forEach((v) => groups.add(v));
    }
  };

  // Check annotations
  tryAdd(session.metadata?.annotations?.["breakglass.telekom.com/approver-groups"]);
  tryAdd(session.metadata?.annotations?.["breakglass.t-caas.telekom.com/approver-groups"]);

  // Check labels
  tryAdd(session.metadata?.labels?.["breakglass.telekom.com/approver-groups"]);
  tryAdd(session.metadata?.labels?.["breakglass.t-caas.telekom.com/approver-groups"]);

  // Check spec
  tryAdd((session.spec as any)?.approverGroup);
  tryAdd((session.spec as any)?.approverGroups);

  // Check status
  tryAdd((session.status as any)?.approverGroup);
  tryAdd((session.status as any)?.approverGroups);

  return Array.from(groups).sort();
}

/**
 * Deduplicate sessions by name/key
 */
export function dedupeSessions(sessions: SessionCR[]): SessionCR[] {
  const map = new Map<string, SessionCR>();

  sessions.forEach((session) => {
    const key = getSessionKey(session);
    const existing = map.get(key);

    if (!existing) {
      const clone = { ...session } as SessionCR & { matchingApproverGroups?: string[] };
      const groups = collectApproverGroups(session);
      if (groups.length) {
        clone.matchingApproverGroups = groups;
      }
      map.set(key, clone);
      return;
    }

    // Merge approver groups
    const existingGroups = new Set<string>((existing as any).matchingApproverGroups || []);
    collectApproverGroups(session).forEach((g) => existingGroups.add(g));
    if (existingGroups.size) {
      (existing as any).matchingApproverGroups = Array.from(existingGroups).sort();
    }
  });

  return Array.from(map.values());
}

/**
 * Enrich sessions with urgency information
 */
export function enrichWithUrgency(sessions: SessionCR[]): SessionWithUrgency[] {
  return sessions.map((session) => ({
    ...session,
    urgency: getUrgency(getSessionExpiry(session)),
    timeRemaining: getTimeRemaining(getSessionExpiry(session)),
  }));
}

/**
 * Sort sessions by various criteria
 */
export function sortSessions(sessions: SessionWithUrgency[], sortBy: SortOption): SessionWithUrgency[] {
  const sorted = [...sessions];

  switch (sortBy) {
    case "urgent":
      sorted.sort((a, b) => a.timeRemaining - b.timeRemaining);
      break;
    case "recent":
      sorted.sort((a, b) => {
        const timeA = new Date(getSessionStarted(a) || a.metadata?.creationTimestamp || 0).getTime();
        const timeB = new Date(getSessionStarted(b) || b.metadata?.creationTimestamp || 0).getTime();
        return timeB - timeA;
      });
      break;
    case "groups":
      sorted.sort((a, b) => getSessionGroup(a).localeCompare(getSessionGroup(b)));
      break;
    case "cluster":
      sorted.sort((a, b) => getSessionCluster(a).localeCompare(getSessionCluster(b)));
      break;
    case "user":
      sorted.sort((a, b) => getSessionUser(a).localeCompare(getSessionUser(b)));
      break;
  }

  return sorted;
}

/**
 * Filter sessions by criteria
 */
export function filterSessions(sessions: SessionWithUrgency[], filters: SessionListFilters): SessionWithUrgency[] {
  return sessions.filter((session) => {
    // Filter by states
    if (filters.states.length > 0) {
      const state = normalizeState(getSessionState(session));
      if (!filters.states.some((s) => normalizeState(s) === state)) {
        return false;
      }
    }

    // Filter by cluster
    if (filters.cluster.trim()) {
      const cluster = getSessionCluster(session).toLowerCase();
      if (!cluster.includes(filters.cluster.toLowerCase().trim())) {
        return false;
      }
    }

    // Filter by group
    if (filters.group.trim()) {
      const group = getSessionGroup(session).toLowerCase();
      if (!group.includes(filters.group.toLowerCase().trim())) {
        return false;
      }
    }

    // Filter by user
    if (filters.user.trim()) {
      const user = getSessionUser(session).toLowerCase();
      if (!user.includes(filters.user.toLowerCase().trim())) {
        return false;
      }
    }

    // Filter by name
    if (filters.name.trim()) {
      const name = getSessionKey(session).toLowerCase();
      if (!name.includes(filters.name.toLowerCase().trim())) {
        return false;
      }
    }

    // Filter by urgency
    if (filters.urgency !== "all") {
      if (session.urgency !== filters.urgency) {
        return false;
      }
    }

    return true;
  });
}

/**
 * Main composable for session list management
 */
export function useSessionList<T extends SessionCR = SessionCR>(
  fetchFn: () => Promise<T[]>,
  options: SessionListOptions = {}
) {
  const { defaultSort = "recent", defaultFilters = {}, calculateUrgency = true } = options;

  // State
  const rawSessions = ref<T[]>([]) as Ref<T[]>;
  const loading = ref(false);
  const error = ref("");
  const sortBy = ref<SortOption>(defaultSort);
  const filters = ref<SessionListFilters>({ ...DEFAULT_FILTERS, ...defaultFilters });

  // Computed: sessions with urgency
  const sessionsWithUrgency: ComputedRef<SessionWithUrgency[]> = computed(() => {
    if (!calculateUrgency) {
      return rawSessions.value.map((s) => ({
        ...s,
        urgency: "normal" as UrgencyLevel,
        timeRemaining: Infinity,
      }));
    }
    return enrichWithUrgency(rawSessions.value);
  });

  // Computed: filtered sessions
  const filteredSessions = computed(() => {
    return filterSessions(sessionsWithUrgency.value, filters.value);
  });

  // Computed: sorted sessions
  const sortedSessions = computed(() => {
    return sortSessions(filteredSessions.value, sortBy.value);
  });

  // Computed: counts
  const totalCount = computed(() => rawSessions.value.length);
  const filteredCount = computed(() => filteredSessions.value.length);

  // Computed: urgency breakdown
  const urgencyBreakdown = computed(() => {
    const counts = { critical: 0, high: 0, normal: 0 };
    sessionsWithUrgency.value.forEach((s) => {
      counts[s.urgency]++;
    });
    return counts;
  });

  // Actions
  async function loadSessions() {
    loading.value = true;
    error.value = "";
    debug(`${TAG}.loadSessions`, "Loading sessions");

    try {
      const data = await fetchFn();
      rawSessions.value = dedupeSessions(data) as T[];
      debug(`${TAG}.loadSessions`, "Loaded sessions", { count: data.length });
    } catch (err: any) {
      const message = err?.message || "Failed to load sessions";
      error.value = message;
      warn(`${TAG}.loadSessions`, "Failed to load sessions", { errorMessage: message });
    } finally {
      loading.value = false;
    }
  }

  function resetFilters() {
    filters.value = { ...DEFAULT_FILTERS };
  }

  function setFilter<K extends keyof SessionListFilters>(key: K, value: SessionListFilters[K]) {
    filters.value[key] = value;
  }

  function setSortBy(option: SortOption) {
    sortBy.value = option;
  }

  function removeSession(sessionOrName: SessionCR | string) {
    const name = typeof sessionOrName === "string" ? sessionOrName : getSessionKey(sessionOrName);
    rawSessions.value = rawSessions.value.filter((s) => getSessionKey(s) !== name);
  }

  function updateSession(session: T) {
    const key = getSessionKey(session);
    const index = rawSessions.value.findIndex((s) => getSessionKey(s) === key);
    if (index >= 0) {
      rawSessions.value[index] = session;
    }
  }

  return {
    // State
    sessions: sortedSessions,
    rawSessions,
    loading,
    error,
    sortBy,
    filters,

    // Computed
    totalCount,
    filteredCount,
    urgencyBreakdown,

    // Actions
    loadSessions,
    resetFilters,
    setFilter,
    setSortBy,
    removeSession,
    updateSession,
  };
}
