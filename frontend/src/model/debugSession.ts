/**
 * Debug Session types for the frontend
 */

// Debug Session states - matches backend api/v1alpha1/debug_session_types.go
export type DebugSessionState =
  | "Pending"
  | "PendingApproval"
  | "Active"
  | "Expired"
  | "Terminated"
  | "Failed"
  | "Rejected";

// Debug Session modes
export type DebugSessionMode = "workload" | "kubectl-debug" | "hybrid";

// Workload types for debug sessions
export type DebugWorkloadType = "DaemonSet" | "Deployment";

// Participant roles
export type ParticipantRole = "owner" | "participant" | "viewer";

// Participant status
export interface DebugSessionParticipant {
  user: string;
  displayName?: string;
  email?: string;
  role: ParticipantRole;
  joinedAt?: string;
  leftAt?: string;
}

// Debug pod info in status
export interface DebugPodInfo {
  name: string;
  namespace: string;
  nodeName: string;
  ready: boolean;
  phase: string;
}

// Constraints from template
export interface SessionConstraints {
  maxDuration?: string;
  defaultDuration?: string;
  allowRenewal?: boolean;
  maxRenewals?: number;
  renewalDuration?: string;
}

// Kubectl debug settings
export interface KubectlDebugSettings {
  ephemeralContainers?: {
    enabled: boolean;
  };
  nodeDebug?: {
    enabled: boolean;
  };
  podCopy?: {
    enabled: boolean;
  };
}

// API response types
export interface DebugSessionSummary {
  name: string;
  templateRef: string;
  cluster: string;
  requestedBy: string;
  requestedByDisplayName?: string;
  state: DebugSessionState;
  statusMessage?: string;
  startsAt?: string;
  expiresAt?: string;
  participants: number;
  allowedPods: number;
}

export interface DebugSessionTemplateResponse {
  name: string;
  displayName: string;
  description: string;
  mode: DebugSessionMode;
  workloadType?: DebugWorkloadType;
  podTemplateRef: string;
  targetNamespace: string;
  constraints: SessionConstraints;
  allowedClusters?: string[];
  allowedGroups?: string[];
  requiresApproval: boolean;
}

export interface DebugPodTemplateResponse {
  name: string;
  displayName: string;
  description: string;
  containers: number;
}

// Full DebugSession CRD representation
export interface DebugSession {
  metadata: {
    name: string;
    namespace?: string;
    creationTimestamp?: string;
    labels?: Record<string, string>;
    annotations?: Record<string, string>;
  };
  spec: {
    templateRef: string;
    cluster: string;
    requestedBy: string;
    requestedByDisplayName?: string;
    requestedByEmail?: string;
    requestedDuration?: string;
    reason?: string;
    nodeSelector?: Record<string, string>;
    scheduledStartTime?: string;
  };
  status?: {
    state: DebugSessionState;
    message?: string;
    startsAt?: string;
    expiresAt?: string;
    terminatedAt?: string;
    terminatedBy?: string;
    terminationReason?: string;
    renewalCount?: number;
    participants?: DebugSessionParticipant[];
    allowedPods?: DebugPodInfo[];
    approvedBy?: string;
    approvedAt?: string;
    rejectedBy?: string;
    rejectedAt?: string;
    rejectionReason?: string;
    workloadName?: string;
    workloadNamespace?: string;
  };
}

// Request types for API calls
export interface CreateDebugSessionRequest {
  templateRef: string;
  cluster: string;
  requestedDuration?: string;
  reason?: string;
  nodeSelector?: Record<string, string>;
  scheduledStartTime?: string;
}

export interface JoinDebugSessionRequest {
  role?: ParticipantRole;
}

export interface RenewDebugSessionRequest {
  extendBy: string;
}

export interface ApproveDebugSessionRequest {
  reason?: string;
}

export interface RejectDebugSessionRequest {
  reason: string;
}

// List response types
export interface DebugSessionListResponse {
  sessions: DebugSessionSummary[];
  total: number;
}

export interface DebugSessionTemplateListResponse {
  templates: DebugSessionTemplateResponse[];
  total: number;
}

export interface DebugPodTemplateListResponse {
  templates: DebugPodTemplateResponse[];
  total: number;
}

// Query parameters for list endpoint
export interface DebugSessionSearchParams {
  cluster?: string;
  state?: string;
  user?: string;
  mine?: boolean;
}

// ============================================================================
// Kubectl-Debug API Request/Response Types
// ============================================================================

// Request to inject an ephemeral container into a target pod
export interface InjectEphemeralContainerRequest {
  namespace: string;
  podName: string;
  containerName: string;
  image: string;
  command?: string[];
}

// Response from injecting an ephemeral container
export interface InjectEphemeralContainerResponse {
  success: boolean;
  message: string;
  containerName: string;
}

// Request to create a copy of a pod for debugging
export interface CreatePodCopyRequest {
  namespace: string;
  podName: string;
  debugImage?: string;
}

// Response from creating a pod copy
export interface CreatePodCopyResponse {
  copyName: string;
  copyNamespace: string;
}

// Request to create a debug pod on a node
export interface CreateNodeDebugPodRequest {
  nodeName: string;
}

// Response from creating a node debug pod
export interface CreateNodeDebugPodResponse {
  podName: string;
  namespace: string;
}
