export interface Breakglass extends AvailableBreakglass, ActiveBreakglass {}

export interface AvailableBreakglass {
  from: string; // source role/group user has (base role for escalation)
  cluster: string; // cluster name escalation applies to
  to: string; // escalated (granted) group
  duration: number; // seconds
  selfApproval: boolean; // true if no approvers defined
  approvalGroups: string[]; // approver groups (if any)
  requestingGroups?: string[]; // optional array of groups that can request this escalation
  // optional reason configuration shown to requesters
  requestReason?: { mandatory?: boolean; description?: string };
  // optional reason configuration shown to approvers
  approvalReason?: { mandatory?: boolean; description?: string };
}

export interface ActiveBreakglass {
  group: string; // active session granted group (mirror of 'to')
  expiry: number; // unix epoch seconds (0 if inactive)
  cluster: string; // cluster name the active session applies to
  state: string; // session state (e.g., Active, Available, etc.)
  // optional full session objects for more advanced UI actions
  sessionActive?: SessionCR;
  sessionPending?: SessionCR;
  // optional metadata for normalized historical/approved shapes
  name?: string;
  metadata?: SessionMetadata;
  spec?: SessionSpec;
  status?: SessionStatus;
  started?: string;
  ended?: string;
  reasonEnded?: string;
}

export interface SessionMetadata {
  name?: string;
  creationTimestamp?: string;
  annotations?: Record<string, string>;
  labels?: Record<string, string>;
  [key: string]: unknown;
}

export interface SessionSpec {
  grantedGroup?: string;
  cluster?: string;
  user?: string;
  denyPolicyRefs?: string[];
  requestReason?: string;
  idleTimeout?: string;
  requester?: string;
  approverGroup?: string | string[];
  approverGroups?: string | string[];
  scheduledStartTime?: string;
  identityProviderName?: string;
  // Snapshots of escalation config at session creation time
  requestReasonConfig?: { mandatory?: boolean; description?: string };
  approvalReasonConfig?: { mandatory?: boolean; description?: string };
  [key: string]: unknown;
}

export interface SessionStatus {
  approvedAt?: string;
  rejectedAt?: string;
  expiresAt?: string;
  timeoutAt?: string;
  retainedUntil?: string;
  state?: string;
  approver?: string;
  approvers?: string[];
  reasonEnded?: string;
  lastActivity?: string;
  activityCount?: number;
  actualStartTime?: string;
  startedAt?: string;
  endedAt?: string;
  reason?: string;
  withdrawnAt?: string;
  approvalReason?: string;
  approverGroup?: string | string[];
  approverGroups?: string | string[];
  conditions?: Array<{ type?: string; message?: string; lastTransitionTime?: string }>;
  [key: string]: unknown;
}

export interface SessionCR {
  name?: string;
  metadata?: SessionMetadata;
  spec?: SessionSpec;
  status?: SessionStatus;
  // convenience fields sometimes present in older payloads
  group?: string;
  cluster?: string;
  expiry?: number;
  user?: string;
  started?: string;
  ended?: string;
  createdAt?: string;
  state?: string;
  terminationReason?: string;
  [key: string]: unknown;
}
