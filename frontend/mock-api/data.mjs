import { randomUUID } from "crypto";

export const CURRENT_USER_EMAIL = "mock.user@breakglass.dev";
export const PARTNER_USER_EMAIL = "partner.user@breakglass.dev";
export const MOCK_APPROVER_GROUPS = ["dtcaas-platform_emergency", "platform-oncall", "prod-approvers"];

// ============================================================================
// DEBUG SESSION MOCK DATA
// ============================================================================

const debugPodTemplates = new Map();
const debugSessionTemplates = new Map();
const debugSessions = new Map();

// Debug Pod Templates
const mockDebugPodTemplates = [
  {
    metadata: {
      name: "netshoot-base",
      creationTimestamp: new Date().toISOString(),
    },
    spec: {
      displayName: "Netshoot Debug Pod",
      description: "Network troubleshooting tools including curl, dig, nmap, tcpdump",
      template: {
        spec: {
          containers: [
            {
              name: "netshoot",
              image: "nicolaka/netshoot:latest",
              command: ["sleep", "infinity"],
              securityContext: {
                runAsNonRoot: false,
                capabilities: {
                  add: ["NET_ADMIN", "SYS_PTRACE"],
                },
              },
            },
          ],
          tolerations: [{ operator: "Exists" }],
        },
      },
    },
  },
  {
    metadata: {
      name: "alpine-minimal",
      creationTimestamp: new Date().toISOString(),
    },
    spec: {
      displayName: "Alpine Minimal",
      description: "Lightweight Alpine Linux container for basic debugging",
      template: {
        spec: {
          containers: [
            {
              name: "alpine",
              image: "alpine:3.19",
              command: ["sleep", "infinity"],
              securityContext: {
                runAsNonRoot: true,
                runAsUser: 1000,
              },
              resources: {
                requests: { cpu: "100m", memory: "128Mi" },
                limits: { cpu: "500m", memory: "256Mi" },
              },
            },
          ],
        },
      },
    },
  },
  {
    metadata: {
      name: "busybox-tools",
      creationTimestamp: new Date().toISOString(),
    },
    spec: {
      displayName: "BusyBox Tools",
      description: "BusyBox with common Unix utilities",
      template: {
        spec: {
          containers: [
            {
              name: "busybox",
              image: "busybox:1.36",
              command: ["sleep", "infinity"],
            },
          ],
        },
      },
    },
  },
];

// Debug Session Templates
const mockDebugSessionTemplates = [
  {
    metadata: {
      name: "standard-debug",
      creationTimestamp: new Date().toISOString(),
    },
    spec: {
      displayName: "Standard Debug Access",
      description: "Network debugging tools deployed as DaemonSet on all nodes",
      mode: "workload",
      workloadType: "DaemonSet",
      podTemplateRef: "netshoot-base",
      targetNamespace: "breakglass-debug",
      constraints: {
        maxDuration: "4h",
        defaultDuration: "1h",
        allowRenewal: true,
        maxRenewals: 3,
        renewalDuration: "1h",
      },
      allowedClusters: ["production-*", "staging-*", "t-sec-1st.dtmd11"],
      allowedGroups: ["sre-team", "platform-oncall", "dtcaas-platform_emergency"],
      requiresApproval: true,
      approverGroups: ["platform-oncall", "security-leads"],
    },
  },
  {
    metadata: {
      name: "ephemeral-debug",
      creationTimestamp: new Date().toISOString(),
    },
    spec: {
      displayName: "Ephemeral Container Debug",
      description: "Inject ephemeral containers into running pods for live debugging",
      mode: "kubectl-debug",
      podTemplateRef: "alpine-minimal",
      targetNamespace: "breakglass-debug",
      kubectlDebug: {
        ephemeralContainers: { enabled: true },
        nodeDebug: { enabled: false },
        podCopy: { enabled: true },
      },
      constraints: {
        maxDuration: "2h",
        defaultDuration: "30m",
        allowRenewal: true,
        maxRenewals: 2,
      },
      allowedClusters: ["*"],
      allowedGroups: ["developers", "sre-team"],
      requiresApproval: false,
    },
  },
  {
    metadata: {
      name: "node-debug",
      creationTimestamp: new Date().toISOString(),
    },
    spec: {
      displayName: "Node-Level Debug",
      description: "Full node access with host namespaces for deep debugging",
      mode: "hybrid",
      workloadType: "DaemonSet",
      podTemplateRef: "netshoot-base",
      targetNamespace: "breakglass-debug",
      kubectlDebug: {
        ephemeralContainers: { enabled: true },
        nodeDebug: { enabled: true },
        podCopy: { enabled: false },
      },
      constraints: {
        maxDuration: "1h",
        defaultDuration: "30m",
        allowRenewal: false,
        maxRenewals: 0,
      },
      allowedClusters: ["staging-*"],
      allowedGroups: ["sre-team"],
      requiresApproval: true,
      approverGroups: ["security-leads"],
    },
  },
  {
    metadata: {
      name: "lab-debug",
      creationTimestamp: new Date().toISOString(),
    },
    spec: {
      displayName: "Lab Cluster Debug",
      description: "Unrestricted debug access for lab environments",
      mode: "workload",
      workloadType: "Deployment",
      podTemplateRef: "busybox-tools",
      targetNamespace: "debug-sessions",
      constraints: {
        maxDuration: "8h",
        defaultDuration: "2h",
        allowRenewal: true,
        maxRenewals: 5,
      },
      allowedClusters: ["lab-*", "dev-*"],
      allowedGroups: ["developers", "qa-team"],
      requiresApproval: false,
    },
  },
];

// Initialize debug pod templates
mockDebugPodTemplates.forEach((t) => debugPodTemplates.set(t.metadata.name, t));

// Initialize debug session templates
mockDebugSessionTemplates.forEach((t) => debugSessionTemplates.set(t.metadata.name, t));

// Mock debug sessions
function baseDebugSession({
  name,
  templateRef = "standard-debug",
  cluster = "t-sec-1st.dtmd11",
  requestedBy = CURRENT_USER_EMAIL,
  state = "Pending",
  reason = "Investigating network connectivity issues",
  requestedDuration = "1h",
  expiresInMinutes = 60,
  participants = [],
  allowedPods = [],
  renewalCount = 0,
  approvedBy,
  rejectedBy,
  rejectionReason,
  scheduledStartTime,
}) {
  const creationTimestamp = new Date(Date.now() - 30 * 60 * 1000).toISOString();
  const startsAt = scheduledStartTime || (state === "Active" ? new Date(Date.now() - 15 * 60 * 1000).toISOString() : undefined);
  const expiresAt = state === "Active" || state === "PendingApproval" 
    ? new Date(Date.now() + expiresInMinutes * 60 * 1000).toISOString()
    : state === "Expired" 
      ? new Date(Date.now() - 30 * 60 * 1000).toISOString()
      : undefined;

  return {
    metadata: {
      name,
      namespace: "breakglass-system",
      creationTimestamp,
    },
    spec: {
      templateRef,
      cluster,
      requestedBy,
      requestedDuration,
      reason,
      ...(scheduledStartTime && { scheduledStartTime }),
    },
    status: {
      state,
      startsAt,
      expiresAt,
      renewalCount,
      participants: [
        { user: requestedBy, role: "owner", joinedAt: creationTimestamp },
        ...participants,
      ],
      allowedPods,
      ...(approvedBy && { approvedBy, approvedAt: new Date(Date.now() - 20 * 60 * 1000).toISOString() }),
      ...(rejectedBy && { rejectedBy, rejectedAt: new Date().toISOString(), rejectionReason }),
    },
    mock: {
      owner: requestedBy,
    },
  };
}

const mockDebugSessions = [
  baseDebugSession({
    name: "debug-network-001",
    templateRef: "standard-debug",
    cluster: "t-sec-1st.dtmd11",
    state: "Active",
    reason: "Investigating pod network connectivity issues in production",
    expiresInMinutes: 45,
    approvedBy: "approver@breakglass.dev",
    allowedPods: [
      { name: "netshoot-abc12", namespace: "breakglass-debug", nodeName: "node-1", ready: true, phase: "Running" },
      { name: "netshoot-def34", namespace: "breakglass-debug", nodeName: "node-2", ready: true, phase: "Running" },
    ],
    participants: [
      { user: PARTNER_USER_EMAIL, role: "participant", joinedAt: new Date(Date.now() - 10 * 60 * 1000).toISOString() },
    ],
  }),
  baseDebugSession({
    name: "debug-pending-approval",
    templateRef: "node-debug",
    cluster: "staging-eu-west-1",
    state: "PendingApproval",
    reason: "Need node-level access for kernel debugging",
    expiresInMinutes: 120,
  }),
  baseDebugSession({
    name: "debug-ephemeral-002",
    templateRef: "ephemeral-debug",
    cluster: "production-us-east-1",
    state: "Active",
    reason: "Attaching debugger to crashing pod",
    expiresInMinutes: 20,
    renewalCount: 1,
    allowedPods: [
      { name: "debug-target-pod", namespace: "app-namespace", nodeName: "node-3", ready: true, phase: "Running" },
    ],
  }),
  baseDebugSession({
    name: "debug-expired-001",
    templateRef: "standard-debug",
    cluster: "t-sec-1st.dtmd11",
    state: "Expired",
    requestedBy: PARTNER_USER_EMAIL,
    reason: "Previous debugging session that expired",
    expiresInMinutes: -60,
    approvedBy: CURRENT_USER_EMAIL,
  }),
  baseDebugSession({
    name: "debug-rejected-001",
    templateRef: "node-debug",
    cluster: "production-critical",
    state: "Failed",
    reason: "Requested node access without proper justification",
    rejectedBy: "security-lead@breakglass.dev",
    rejectionReason: "Insufficient justification for node-level access",
  }),
  baseDebugSession({
    name: "debug-terminated-001",
    templateRef: "lab-debug",
    cluster: "lab-cluster-01",
    state: "Terminated",
    reason: "Lab testing completed early",
  }),
  baseDebugSession({
    name: "debug-scheduled-001",
    templateRef: "standard-debug",
    cluster: "production-apac",
    state: "Pending",
    reason: "Scheduled maintenance window debugging",
    scheduledStartTime: new Date(Date.now() + 2 * 60 * 60 * 1000).toISOString(),
  }),
];

// Initialize debug sessions
mockDebugSessions.forEach((s) => debugSessions.set(s.metadata.name, s));

// Debug Session API functions
export function listDebugSessions(query = {}) {
  const clusterFilter = query.cluster;
  const stateFilter = query.state;
  const userFilter = query.user;
  const mine = query.mine === "true";

  let results = Array.from(debugSessions.values()).filter((session) => {
    if (clusterFilter && session.spec.cluster !== clusterFilter) return false;
    if (stateFilter && session.status.state.toLowerCase() !== stateFilter.toLowerCase()) return false;
    if (userFilter && session.spec.requestedBy !== userFilter) return false;
    if (mine && session.mock?.owner !== CURRENT_USER_EMAIL) return false;
    return true;
  });

  return {
    sessions: results.map((s) => ({
      name: s.metadata.name,
      templateRef: s.spec.templateRef,
      cluster: s.spec.cluster,
      requestedBy: s.spec.requestedBy,
      state: s.status.state,
      startsAt: s.status.startsAt,
      expiresAt: s.status.expiresAt,
      participants: s.status.participants?.length || 0,
      allowedPods: s.status.allowedPods?.length || 0,
    })),
    total: results.length,
  };
}

export function findDebugSession(name) {
  return debugSessions.get(name);
}

export function createDebugSession(body = {}) {
  const name = `debug-${randomUUID().slice(0, 8)}`;
  const session = baseDebugSession({
    name,
    templateRef: body.templateRef || "standard-debug",
    cluster: body.cluster || "t-sec-1st.dtmd11",
    requestedBy: CURRENT_USER_EMAIL,
    reason: body.reason || "Debug session created via UI",
    requestedDuration: body.requestedDuration || "1h",
    scheduledStartTime: body.scheduledStartTime,
    state: "Pending",
  });
  debugSessions.set(name, session);
  return session;
}

export function updateDebugSessionState(name, state, opts = {}) {
  const session = debugSessions.get(name);
  if (!session) return null;
  
  session.status.state = state;
  
  if (state === "Active") {
    session.status.approvedBy = opts.approvedBy || CURRENT_USER_EMAIL;
    session.status.approvedAt = new Date().toISOString();
    session.status.startsAt = new Date().toISOString();
    session.status.expiresAt = new Date(Date.now() + 60 * 60 * 1000).toISOString();
    session.status.allowedPods = [
      { name: `netshoot-${randomUUID().slice(0, 5)}`, namespace: "breakglass-debug", nodeName: "node-1", ready: true, phase: "Running" },
    ];
  }
  
  if (state === "Failed" || state === "Rejected") {
    session.status.rejectedBy = opts.rejectedBy || CURRENT_USER_EMAIL;
    session.status.rejectedAt = new Date().toISOString();
    session.status.rejectionReason = opts.reason || "Rejected via mock API";
  }
  
  if (state === "Terminated") {
    session.status.terminatedBy = CURRENT_USER_EMAIL;
    session.status.terminatedAt = new Date().toISOString();
    session.status.terminationReason = opts.reason || "Terminated by user";
  }
  
  return session;
}

export function joinDebugSession(name, role = "viewer") {
  const session = debugSessions.get(name);
  if (!session) return null;
  
  const existing = session.status.participants?.find((p) => p.user === CURRENT_USER_EMAIL);
  if (!existing) {
    session.status.participants = session.status.participants || [];
    session.status.participants.push({
      user: CURRENT_USER_EMAIL,
      role,
      joinedAt: new Date().toISOString(),
    });
  }
  
  return session;
}

export function leaveDebugSession(name) {
  const session = debugSessions.get(name);
  if (!session) return null;
  
  const participant = session.status.participants?.find((p) => p.user === CURRENT_USER_EMAIL);
  if (participant && participant.role !== "owner") {
    participant.leftAt = new Date().toISOString();
  }
  
  return session;
}

export function renewDebugSession(name, extendBy = "1h") {
  const session = debugSessions.get(name);
  if (!session) return null;
  
  // Parse extendBy (simple parsing for mock)
  const hours = parseInt(extendBy) || 1;
  session.status.expiresAt = new Date(Date.now() + hours * 60 * 60 * 1000).toISOString();
  session.status.renewalCount = (session.status.renewalCount || 0) + 1;
  
  return session;
}

export function listDebugSessionTemplates(userGroups = []) {
  // In real API, this filters by user's group membership
  // For mock, we return all templates
  const templates = Array.from(debugSessionTemplates.values()).map((t) => ({
    name: t.metadata.name,
    displayName: t.spec.displayName,
    description: t.spec.description,
    mode: t.spec.mode,
    workloadType: t.spec.workloadType,
    podTemplateRef: t.spec.podTemplateRef,
    targetNamespace: t.spec.targetNamespace,
    constraints: t.spec.constraints,
    allowedClusters: t.spec.allowedClusters,
    allowedGroups: t.spec.allowedGroups,
    requiresApproval: t.spec.requiresApproval,
  }));

  return {
    templates,
    total: templates.length,
  };
}

export function findDebugSessionTemplate(name) {
  return debugSessionTemplates.get(name);
}

export function listDebugPodTemplates() {
  const templates = Array.from(debugPodTemplates.values()).map((t) => ({
    name: t.metadata.name,
    displayName: t.spec.displayName,
    description: t.spec.description,
    containers: t.spec.template?.spec?.containers?.length || 0,
  }));

  return {
    templates,
    total: templates.length,
  };
}

export function findDebugPodTemplate(name) {
  return debugPodTemplates.get(name);
}

const buildGroupRange = (prefix, count) =>
  Array.from({ length: count }, (_, idx) => `${prefix}-${String(idx + 1).padStart(2, "0")}`);

const LARGE_APPROVER_STACK = buildGroupRange("mega-approver", 24);
const LARGE_REQUESTER_STACK = buildGroupRange("mega-requester", 18);

const now = () => new Date();
const minutesFromNow = (minutes) => new Date(now().getTime() + minutes * 60 * 1000).toISOString();

const azureIssuer = "https://login.microsoftonline.com/partners-tenant/v2.0";
const sandboxKeycloakIssuer = "https://keycloak.sandbox.telekom.de/auth/realms/dev";

export const runtimeConfig = {
  frontend: {
    oidcAuthority: "https://keycloak.das-schiff.telekom.de/auth/realms/schiff",
    oidcClientID: "breakglass-ui",
    brandingName: "Breakglass Dev Preview",
    uiFlavour: "telekom",
    featureFlags: {
      multiIDP: true,
      approvalsV2: true,
    },
  },
};

export const identityProviderConfig = {
  type: "Keycloak",
  clientID: "breakglass-ui",
  keycloak: {
    baseURL: "https://keycloak.das-schiff.telekom.de/auth",
    realm: "schiff",
  },
};

export const multiIDPConfig = {
  identityProviders: [
    {
      name: "production-keycloak",
      displayName: "Production Keycloak",
      issuer: "https://keycloak.das-schiff.telekom.de/auth/realms/schiff",
      enabled: true,
    },
    {
      name: "partners-azuread",
      displayName: "Partners Azure AD",
      issuer: azureIssuer,
      enabled: true,
    },
    {
      name: "sandbox-keycloak",
      displayName: "Sandbox Keycloak",
      issuer: sandboxKeycloakIssuer,
      enabled: true,
    },
    {
      name: "legacy-ldap",
      displayName: "Legacy LDAP",
      issuer: "ldaps://ldap.telekom.de:636",
      enabled: false,
    },
  ],
  escalationIDPMapping: {
    "t-sec-1st.dtmd11::dtcaas-platform_emergency": ["production-keycloak"],
    "lab-cluster::dtcaas-lab": ["production-keycloak", "partners-azuread"],
    "global-platform::platform-superuser": [],
    "edge-hub::edge-hotfix": ["sandbox-keycloak", "partners-azuread"],
    "ops-lab::legacy-ops": ["legacy-ldap"],
  },
};

export const breakglassEscalations = [
  {
    metadata: {
      name: "t-sec-1st.dtmd11",
      creationTimestamp: minutesFromNow(-90),
    },
    spec: {
      allowed: {
        clusters: ["t-sec-1st.dtmd11"],
        groups: ["dtcaas-platform_emergency"],
      },
      approvers: {
        groups: ["platform-oncall", "prod-approvers"],
      },
      escalatedGroup: "cluster-admin",
      maxValidFor: "2h0m0s",
      retainFor: "72h0m0s",
      requestReason: {
        mandatory: true,
        description: "Approver note is required for emergency access.",
      },
      approvalReason: {
        mandatory: true,
        description: "Document why the escalation is safe to approve.",
      },
    },
  },
  {
    metadata: {
      name: "lab-cluster",
      creationTimestamp: minutesFromNow(-240),
    },
    spec: {
      allowed: {
        clusters: ["lab-cluster"],
        groups: ["dtcaas-lab"],
      },
      approvers: {
        groups: ["lab-approvers"],
      },
      escalatedGroup: "lab-admin",
      maxValidFor: "4h0m0s",
      retainFor: "24h0m0s",
      requestReason: {
        mandatory: false,
        description: "Optional reason for lab work.",
      },
    },
  },
  {
    metadata: {
      name: "global-platform",
      creationTimestamp: minutesFromNow(-360),
    },
    spec: {
      allowed: {
        clusters: ["global-platform-eu", "global-platform-us", "global-platform-apac"],
        groups: ["platform-superuser", "platform-superuser-emea"],
      },
      approvers: {
        groups: ["security-leads"],
        users: ["lead.oncall@breakglass.dev"],
      },
      escalatedGroup: "platform-superuser",
      maxValidFor: "1h30m0s",
      retainFor: "168h0m0s",
      requestReason: {
        mandatory: true,
        description: "Explain the platform incident and mitigation plan.",
      },
      approvalReason: {
        mandatory: false,
        description: "Optional justification for complex approvals.",
      },
    },
  },
  {
    metadata: {
      name: "edge-hub",
      creationTimestamp: minutesFromNow(-60),
    },
    spec: {
      allowed: {
        clusters: ["edge-hub"],
        groups: ["edge-hotfix", "edge-breakglass"],
      },
      approvers: {
        groups: buildGroupRange("edge-approver", 6),
      },
      escalatedGroup: "edge-hotfix",
      maxValidFor: "30m0s",
      retainFor: "48h0m0s",
      requestReason: {
        mandatory: false,
        description: "Optional reason for emergency fixes.",
      },
      approvalReason: {
        mandatory: true,
        description: "Document why edge access is required.",
      },
    },
  },
  {
    metadata: {
      name: "ops-lab",
      creationTimestamp: minutesFromNow(-15),
    },
    spec: {
      allowed: {
        clusters: ["ops-lab"],
        groups: LARGE_REQUESTER_STACK,
      },
      approvers: {
        groups: LARGE_APPROVER_STACK,
      },
      escalatedGroup: "legacy-ops",
      maxValidFor: "6h0m0s",
      retainFor: "12h0m0s",
      requestReason: {
        mandatory: false,
        description: "Legacy lab access does not require a reason.",
      },
    },
  },
];

const sessions = new Map();

function baseSession({
  name,
  user = CURRENT_USER_EMAIL,
  cluster,
  group,
  state = "Pending",
  expiresInMinutes = 120,
  requestReason = "Hotfix rollout",
  approverGroups = MOCK_APPROVER_GROUPS,
  approvers = [CURRENT_USER_EMAIL, "backup.approver@breakglass.dev"],
  approvedBy = [],
  approvalReason,
  scheduledStartTime,
  duration = "2h0m0s",
  identityProviderName,
  identityProviderIssuer,
  metadataAnnotations = {},
  metadataLabels = {},
  statusOverrides = {},
  specOverrides = {},
  mockOverrides = {},
}) {
  const resolvedIdentityProviderName =
    identityProviderName === undefined ? "production-keycloak" : identityProviderName;
  const resolvedIdentityProviderIssuer =
    identityProviderIssuer === undefined
      ? "https://keycloak.das-schiff.telekom.de/auth/realms/schiff"
      : identityProviderIssuer;

  const creationTimestamp = minutesFromNow(-45);
  const expiresAt = minutesFromNow(expiresInMinutes);
  const metadata = {
    name,
    creationTimestamp,
    annotations: {
      "breakglass.telekom.com/approver-groups": approverGroups.join(","),
      ...metadataAnnotations,
    },
  };
  if (Object.keys(metadataLabels).length > 0) {
    metadata.labels = metadataLabels;
  }

  const spec = {
    user,
    grantedGroup: group,
    cluster,
    maxValidFor: duration,
    ...specOverrides,
  };
  if (requestReason !== undefined) {
    spec.requestReason = requestReason;
  }
  if (scheduledStartTime) {
    spec.scheduledStartTime = scheduledStartTime;
  }
  if (resolvedIdentityProviderName !== null) {
    spec.identityProviderName = resolvedIdentityProviderName;
  }
  if (resolvedIdentityProviderIssuer !== null) {
    spec.identityProviderIssuer = resolvedIdentityProviderIssuer;
  }

  const status = {
    state,
    expiresAt,
    approvalReason: approvalReason?.description,
    approverGroups,
    ...statusOverrides,
  };

  const mock = {
    approvers,
    owner: user,
    approvedBy,
    ...mockOverrides,
  };

  return {
    metadata,
    spec,
    status,
    mock,
  };
}

const permutationSessions = [
  baseSession({
    name: "req-t-sec-1st-001",
    cluster: "t-sec-1st.dtmd11",
    group: "dtcaas-platform_emergency",
    state: "Pending",
    requestReason: "Emergency fix for stuck job",
    approvalReason: { description: "High-impact change" },
  }),
  baseSession({
    name: "req-t-sec-1st-approval",
    cluster: "t-sec-1st.dtmd11",
    group: "dtcaas-platform_emergency",
    state: "Approved",
    expiresInMinutes: 30,
    requestReason: "Investigate CPU spikes",
    approvers: [CURRENT_USER_EMAIL],
    approvedBy: [CURRENT_USER_EMAIL],
    statusOverrides: {
      approvedAt: minutesFromNow(-20),
      startedAt: minutesFromNow(-15),
    },
  }),
  baseSession({
    name: "req-lab-001",
    cluster: "lab-cluster",
    group: "dtcaas-lab",
    state: "Rejected",
    requestReason: "Test scenario that was rejected",
    approverGroups: ["lab-approvers"],
    approvers: [CURRENT_USER_EMAIL],
    statusOverrides: {
      reason: "Policy violation detected",
    },
  }),
  baseSession({
    name: "req-lab-timeout",
    cluster: "lab-cluster",
    group: "dtcaas-lab",
    state: "Timeout",
    requestReason: "Expired session",
    approverGroups: ["lab-approvers"],
    expiresInMinutes: -10,
    statusOverrides: {
      reason: "Approval window elapsed",
    },
  }),
  baseSession({
    name: "req-awaiting-activation",
    cluster: "edge-hub",
    group: "edge-hotfix",
    state: "WaitingForScheduledTime",
    scheduledStartTime: minutesFromNow(60),
    requestReason: "Scheduled rollout during maintenance",
    statusOverrides: {
      state: "WaitingForScheduledTime",
    },
  }),
  baseSession({
    name: "req-scheduled-pending",
    cluster: "global-platform-eu",
    group: "platform-superuser",
    state: "Pending",
    scheduledStartTime: minutesFromNow(25),
    requestReason: "Prefill tokens before release",
  }),
  baseSession({
    name: "req-scheduled-active",
    cluster: "global-platform-us",
    group: "platform-superuser",
    state: "Approved",
    scheduledStartTime: minutesFromNow(-45),
    expiresInMinutes: 90,
    statusOverrides: {
      approvedAt: minutesFromNow(-50),
      startedAt: minutesFromNow(-40),
    },
  }),
  baseSession({
    name: "req-withdrawn-user",
    cluster: "t-sec-1st.dtmd11",
    group: "dtcaas-platform_emergency",
    state: "Withdrawn",
    requestReason: "Duplicate submission",
    statusOverrides: {
      reason: "Requester withdrew after duplicate",
    },
  }),
  baseSession({
    name: "req-expired-auto",
    cluster: "global-platform-apac",
    group: "platform-superuser-emea",
    state: "Expired",
    expiresInMinutes: -240,
    statusOverrides: {
      endedAt: minutesFromNow(-120),
    },
  }),
  baseSession({
    name: "req-approvaltimeout",
    cluster: "edge-hub",
    group: "edge-breakglass",
    state: "ApprovalTimeout",
    expiresInMinutes: -30,
    statusOverrides: {
      reason: "Approvers did not respond in time",
    },
  }),
  baseSession({
    name: "req-dropped-audit",
    cluster: "lab-cluster",
    group: "dtcaas-lab",
    state: "Dropped",
    statusOverrides: {
      reason: "Session dropped by security",
    },
  }),
  baseSession({
    name: "req-disabled-idp",
    cluster: "ops-lab",
    group: "legacy-ops",
    state: "Pending",
    identityProviderName: "legacy-ldap",
    identityProviderIssuer: "ldaps://ldap.telekom.de:636",
    requestReason: "Legacy maintenance",
  }),
  baseSession({
    name: "req-azure-idp",
    cluster: "lab-cluster",
    group: "dtcaas-lab",
    state: "Pending",
    identityProviderName: "partners-azuread",
    identityProviderIssuer: azureIssuer,
    approverGroups: ["lab-approvers"],
  }),
  baseSession({
    name: "req-many-approver-groups",
    cluster: "global-platform-eu",
    group: "platform-superuser",
    state: "Pending",
    approverGroups: LARGE_APPROVER_STACK,
    requestReason: "Simulate UI with many approver groups",
    metadataAnnotations: {
      "breakglass.t-caas.telekom.com/approver-groups": LARGE_APPROVER_STACK.join(" "),
    },
  }),
  baseSession({
    name: "req-single-approver",
    cluster: "edge-hub",
    group: "edge-hotfix",
    state: "Pending",
    approverGroups: ["edge-single"],
    requestReason: undefined,
  }),
  baseSession({
    name: "req-no-idp",
    cluster: "global-platform-apac",
    group: "platform-superuser",
    state: "Pending",
    identityProviderName: null,
    identityProviderIssuer: null,
    requestReason: "Testing missing IDP configuration",
  }),
  baseSession({
    name: "req-non-owner",
    cluster: "edge-hub",
    group: "edge-breakglass",
    state: "Pending",
    user: PARTNER_USER_EMAIL,
    approvers: ["approver.partner@breakglass.dev"],
    approvedBy: [],
    metadataLabels: {
      "breakglass.telekom.com/approver-groups": "partner-ops,partner-oncall",
    },
  }),
  baseSession({
    name: "req-optional-approval",
    cluster: "ops-lab",
    group: "legacy-ops",
    state: "Pending",
    requestReason: undefined,
    approvalReason: { description: "Approver justification optional" },
  }),
];

const STRESS_STATE_ROTATION = [
  "Pending",
  "Approved",
  "Rejected",
  "Withdrawn",
  "Timeout",
  "ApprovalTimeout",
  "Expired",
  "WaitingForScheduledTime",
];

const stressSessions = LARGE_REQUESTER_STACK.map((group, index) => {
  const state = STRESS_STATE_ROTATION[index % STRESS_STATE_ROTATION.length];
  const scheduledStartTime = state === "WaitingForScheduledTime" ? minutesFromNow(15 + index * 2) : undefined;
  const expiresInMinutes =
    state === "Expired" ? -60 - index : state === "ApprovalTimeout" ? -30 : state === "Timeout" ? -10 : 90 + index * 2;
  const approvalReason = index % 2 === 0 ? { description: "Stress approval reason" } : undefined;
  const identityProviderName =
    index % 4 === 0
      ? "production-keycloak"
      : index % 4 === 1
        ? "sandbox-keycloak"
        : index % 4 === 2
          ? "partners-azuread"
          : null;
  const identityProviderIssuer =
    identityProviderName === "partners-azuread"
      ? azureIssuer
      : identityProviderName === "sandbox-keycloak"
        ? sandboxKeycloakIssuer
        : undefined;

  return baseSession({
    name: `req-stress-${String(index + 1).padStart(2, "0")}`,
    cluster: index % 3 === 0 ? "global-platform-eu" : index % 3 === 1 ? "edge-hub" : "lab-cluster",
    group,
    state,
    scheduledStartTime,
    expiresInMinutes,
    requestReason: index % 2 === 0 ? `Stress reason ${index + 1}` : undefined,
    approverGroups: buildGroupRange(`stress-approver-${index + 1}`, (index % 12) + 1),
    approvers:
      index % 2 === 0
        ? [CURRENT_USER_EMAIL, "approver.secondary@breakglass.dev"]
        : ["approver.secondary@breakglass.dev"],
    approvedBy: state === "Approved" ? [CURRENT_USER_EMAIL] : [],
    approvalReason,
    identityProviderName,
    identityProviderIssuer,
    metadataAnnotations: {
      "breakglass.telekom.com/approver-groups": buildGroupRange("anno", (index % 6) + 1).join(","),
    },
    metadataLabels: {
      "breakglass.telekom.com/approver-groups": buildGroupRange("label", (index % 4) + 1).join(","),
    },
    statusOverrides:
      state === "WaitingForScheduledTime"
        ? { state: "WaitingForScheduledTime" }
        : state === "Approved"
          ? { approvedAt: minutesFromNow(-10 * index), startedAt: minutesFromNow(-5 * index) }
          : {},
  });
});

const seedSessions = [...permutationSessions, ...stressSessions];

const initialSessions = seedSessions.map((session) => cloneSession(session));
initialSessions.forEach((session) => {
  sessions.set(session.metadata.name, session);
});

function cloneSession(session) {
  return JSON.parse(JSON.stringify(session));
}

function matchesStateFilter(session, states) {
  if (!states || states.length === 0) return true;
  const state = (session.status?.state || "").toLowerCase();
  return states.includes(state);
}

function parseStates(raw) {
  if (!raw) return [];
  return String(raw)
    .split(",")
    .map((entry) => entry.trim().toLowerCase())
    .filter(Boolean);
}

function parseScaleHint(value) {
  if (value === undefined) return 0;
  const parsed = parseInt(String(value), 10);
  if (Number.isNaN(parsed)) {
    console.warn("[mock-api] Invalid scale hint value:", value);
    return 0;
  }
  return Math.max(parsed, 0);
}

function generateScaleDataset(count) {
  return Array.from({ length: count }, (_, idx) => {
    const state = STRESS_STATE_ROTATION[idx % STRESS_STATE_ROTATION.length];
    return baseSession({
      name: `mock-scale-${idx + 1}`,
      cluster: `scale-cluster-${(idx % 5) + 1}`,
      group: `scale-group-${(idx % 20) + 1}`,
      state,
      approverGroups: buildGroupRange(`scale-approver-${idx + 1}`, (idx % 15) + 1),
      requestReason: idx % 2 === 0 ? `Scale reason ${idx + 1}` : undefined,
      metadataAnnotations: {
        "mock.breakglass.telekom.com/scale": "true",
      },
      metadataLabels: {
        "breakglass.telekom.com/approver-groups": buildGroupRange("scale-label", (idx % 3) + 1).join(","),
      },
      approvers: idx % 2 === 0 ? [CURRENT_USER_EMAIL, "scale.oncall@breakglass.dev"] : ["scale.oncall@breakglass.dev"],
      approvedBy: state === "Approved" ? [CURRENT_USER_EMAIL] : [],
    });
  });
}

export function listSessions(query = {}) {
  const states = parseStates(query.state);
  const mine = query.mine === "true";
  const approver = query.approver === "true";
  const approvedByMe = query.approvedByMe === "true";
  const clusterFilter = query.cluster;
  const userFilter = query.user;
  const groupFilter = query.group;
  const nameFilter = query.name;
  const scaleTarget = parseScaleHint(query.mockScale ?? query.scaleCount ?? query.total);

  let results = Array.from(sessions.values())
    .filter((session) => {
      if (!matchesStateFilter(session, states)) return false;
      if (mine && session.mock?.owner !== CURRENT_USER_EMAIL) return false;
      if (approver && !(session.mock?.approvers || []).includes(CURRENT_USER_EMAIL)) return false;
      if (approvedByMe && !(session.mock?.approvedBy || []).includes(CURRENT_USER_EMAIL)) return false;
      if (clusterFilter && session.spec?.cluster !== clusterFilter) return false;
      if (userFilter && session.spec?.user !== userFilter) return false;
      if (groupFilter && session.spec?.grantedGroup !== groupFilter) return false;
      if (nameFilter && session.metadata?.name !== nameFilter) return false;
      return true;
    })
    .map((session) => cloneSession(session));

  if (scaleTarget > 0 && scaleTarget > results.length) {
    const synthetic = generateScaleDataset(scaleTarget - results.length).map((session) => cloneSession(session));
    results = results.concat(synthetic);
  }

  return results;
}

function secondsToDuration(seconds = 3600) {
  const hrs = Math.floor(seconds / 3600);
  const mins = Math.floor((seconds % 3600) / 60);
  const secs = seconds % 60;
  return `${hrs}h${String(mins).padStart(2, "0")}m${String(secs).padStart(2, "0")}s`;
}

export function createSessionFromRequest(body = {}) {
  const name = body.name || `mock-${randomUUID().slice(0, 8)}`;
  const durationSeconds = body.duration ?? 7200;
  const session = baseSession({
    name,
    user: body.user || CURRENT_USER_EMAIL,
    cluster: body.cluster || "t-sec-1st.dtmd11",
    group: body.group || "dtcaas-platform_emergency",
    requestReason: body.reason || "Local mock request",
    duration: secondsToDuration(durationSeconds),
    approverGroups: body.approverGroups || MOCK_APPROVER_GROUPS,
    approvers: body.approvers || [CURRENT_USER_EMAIL],
    scheduledStartTime: body.scheduledStartTime,
  });
  sessions.set(name, session);
  return cloneSession(session);
}

export function findSession(name) {
  return sessions.get(name);
}

export function updateSessionState(name, state, opts = {}) {
  const session = sessions.get(name);
  if (!session) return null;
  session.status.state = state;
  if (state === "Approved") {
    session.status.approvedAt = minutesFromNow(0);
    session.status.expiresAt = minutesFromNow(120);
    const approvedBy = new Set(session.mock?.approvedBy || []);
    approvedBy.add(CURRENT_USER_EMAIL);
    session.mock.approvedBy = Array.from(approvedBy);
  }
  if (state === "Rejected") {
    session.status.reason = opts.reason || "Rejected via mock API";
  }
  if (state === "Withdrawn") {
    session.status.reason = opts.reason || "Withdrawn via mock API";
  }
  if (state === "Dropped") {
    session.status.reason = opts.reason || "Session dropped";
  }
  if (state === "Timeout" || state === "ApprovalTimeout") {
    session.status.reason = opts.reason || "Approval window elapsed";
  }
  session.status.updatedAt = minutesFromNow(0);
  return cloneSession(session);
}

export function resetSessions() {
  sessions.clear();
  initialSessions.forEach((session) => sessions.set(session.metadata.name, cloneSession(session)));
}
