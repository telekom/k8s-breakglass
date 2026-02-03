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

// Container status details for debug pods
export interface PodContainerStatus {
  waitingReason?: string;
  waitingMessage?: string;
  restartCount?: number;
  lastTerminationReason?: string;
}

// Debug pod info in status
export interface DebugPodInfo {
  name: string;
  namespace: string;
  nodeName: string;
  ready: boolean;
  phase: string;
  containerStatus?: PodContainerStatus;
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
  schedulingOptions?: SchedulingOptionsResponse;
  namespaceConstraints?: NamespaceConstraintsResponse;
  hasAvailableClusters: boolean; // True if at least one cluster is available for deployment
  availableClusterCount?: number; // Number of clusters user can deploy to
}

// Scheduling options for debug sessions
export interface SchedulingOptionsResponse {
  required: boolean;
  options: SchedulingOptionResponse[];
}

export interface SchedulingOptionResponse {
  name: string;
  displayName: string;
  description?: string;
  default?: boolean;
}

// Namespace constraints for debug sessions
export interface NamespaceConstraintsResponse {
  allowedPatterns?: string[];
  allowedLabelSelectors?: NamespaceSelectorTermResponse[];
  deniedPatterns?: string[];
  deniedLabelSelectors?: NamespaceSelectorTermResponse[];
  defaultNamespace?: string;
  allowUserNamespace: boolean;
}

// Label selector term for namespace constraints
export interface NamespaceSelectorTermResponse {
  matchLabels?: Record<string, string>;
  matchExpressions?: NamespaceSelectorRequirementResponse[];
}

// Label selector requirement
export interface NamespaceSelectorRequirementResponse {
  key: string;
  operator: "In" | "NotIn" | "Exists" | "DoesNotExist";
  values?: string[];
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
  bindingRef?: string; // Optional: explicit binding selection as "namespace/name" when multiple match
  requestedDuration?: string;
  reason?: string;
  nodeSelector?: Record<string, string>;
  scheduledStartTime?: string;
  targetNamespace?: string;
  selectedSchedulingOption?: string;
}

// Response from creating/getting a debug session
export interface DebugSessionDetailResponse extends DebugSession {
  // Warnings contains non-critical issues or notes about defaults that were applied
  warnings?: string[];
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

// ============================================================================
// Template Cluster Details API Types
// ============================================================================

// Response from GET /debugSessions/templates/:name/clusters
export interface TemplateClustersResponse {
  templateName: string;
  templateDisplayName: string;
  clusters: AvailableClusterDetail[];
}

// Detailed cluster availability information for a template.
// When multiple bindings match a cluster, bindingOptions contains all available options.
export interface AvailableClusterDetail {
  name: string;
  displayName?: string;
  environment?: string;
  location?: string;
  site?: string;
  tenant?: string;
  bindingRef?: BindingReference; // Default/primary binding (backward compat)
  bindingOptions?: BindingOption[]; // All available binding options
  constraints?: SessionConstraints;
  schedulingConstraints?: SchedulingConstraintsSummary;
  schedulingOptions?: SchedulingOptionsResponse;
  namespaceConstraints?: NamespaceConstraintsResponse;
  impersonation?: ImpersonationSummary;
  requiredAuxiliaryResourceCategories?: string[];
  approval?: ApprovalInfo;
  status?: ClusterStatusInfo;
}

// A single binding option with its resolved configuration
export interface BindingOption {
  bindingRef: BindingReference;
  displayName?: string;
  constraints?: SessionConstraints;
  schedulingConstraints?: SchedulingConstraintsSummary;
  schedulingOptions?: SchedulingOptionsResponse;
  namespaceConstraints?: NamespaceConstraintsResponse;
  impersonation?: ImpersonationSummary;
  requiredAuxiliaryResourceCategories?: string[];
  approval?: ApprovalInfo;
  requestReason?: ReasonConfigInfo;
  approvalReason?: ReasonConfigInfo;
  notification?: NotificationConfigInfo;
}

// Reference to the cluster binding that provides access
export interface BindingReference {
  name: string;
  namespace: string;
  displayName?: string;
  displayNamePrefix?: string;
}

// Summary of scheduling constraints from binding/template
export interface SchedulingConstraintsSummary {
  nodeSelector?: Record<string, string>;
  tolerations?: TolerationSummary[];
  deniedNodes?: string[];
  deniedNodeLabels?: Record<string, string>;
}

// Toleration summary
export interface TolerationSummary {
  key: string;
  operator: string;
  value?: string;
  effect?: string;
}

// Impersonation configuration summary
export interface ImpersonationSummary {
  enabled: boolean;
  serviceAccountRef?: string;
}

// Approval requirements from binding/template
export interface ApprovalInfo {
  required: boolean;
  approverGroups?: string[];
}

// Cluster health status
export interface ClusterStatusInfo {
  healthy: boolean;
  lastChecked?: string;
  message?: string;
}

// Reason configuration for request/approval
export interface ReasonConfigInfo {
  mandatory: boolean;
  description?: string;
  minLength?: number;
  maxLength?: number;
  suggestedReasons?: string[];
}

// Notification configuration
export interface NotificationConfigInfo {
  enabled: boolean;
}
