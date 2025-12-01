/**
 * Composables index - exports all composable hooks
 */

// Existing composables
export { usePendingRequests } from "./usePendingRequests";

// Duration utilities
export {
  useDuration,
  parseDurationString,
  formatDuration,
  formatDurationFromSeconds,
  computeEndTime,
  formatEndTime,
  type ParsedDuration,
} from "./useDuration";

// Urgency utilities
export {
  useUrgency,
  useUrgencyUtils,
  getTimeRemaining,
  getUrgency,
  getUrgencyLabel,
  getUrgencyLabelString,
  getUrgencyDescription,
  isExpired,
  isFuture,
  type UrgencyLevel,
  type UrgencyLabel,
  type UrgencyConfig,
} from "./useUrgency";

// Date formatting utilities
export {
  useDateFormatting,
  formatDateTime,
  formatDateOnly,
  formatTimeOnly,
  formatTimeCompact,
  formatWithTimezone,
  formatRelativeTime,
  isValidDate,
  nowISO,
  type DateValue,
} from "./useDateFormatting";

// Session list management
export {
  useSessionList,
  getSessionKey,
  getSessionState,
  normalizeState,
  getSessionUser,
  getSessionCluster,
  getSessionGroup,
  getSessionExpiry,
  getSessionStarted,
  getSessionEnded,
  collectApproverGroups,
  dedupeSessions,
  enrichWithUrgency,
  sortSessions,
  filterSessions,
  type SortOption,
  type SessionState,
  type SessionWithUrgency,
  type SessionListFilters,
  type SessionListOptions,
} from "./useSessionList";

// Session actions
export {
  useSessionActions,
  isPending,
  isActive,
  isScheduled,
  type SessionActionType,
  type SessionActionConfig,
  type ActionHandlers,
  type ActionPermissions,
} from "./useSessionActions";

// Multi-IDP management
export {
  useMultiIDP,
  type UseMultiIDPOptions,
  type UseMultiIDPReturn,
} from "./useMultiIDP";
