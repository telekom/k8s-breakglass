# Debug Sessions

Debug Sessions provide temporary, controlled access to debug pods deployed on target clusters. Unlike breakglass escalations which grant RBAC privileges, debug sessions deploy actual workloads (DaemonSets/Deployments) or enable `kubectl debug` operations with fine-grained controls.

**Type Definitions:**
- [`DebugSession`](../api/v1alpha1/debug_session_types.go)
- [`DebugSessionTemplate`](../api/v1alpha1/debug_session_template_types.go)
- [`DebugPodTemplate`](../api/v1alpha1/debug_pod_template_types.go)

## Overview

Debug sessions are designed for scenarios where engineers need:
- Direct shell access to nodes or pods for troubleshooting
- Network debugging tools in a controlled environment
- Ephemeral containers for live debugging without restarting pods
- Collaborative debugging with terminal sharing

The feature consists of three main resource types:

| Resource | Scope | Purpose |
|----------|-------|---------|
| `DebugPodTemplate` | Cluster | Defines the pod specification (containers, volumes, security context) |
| `DebugSessionTemplate` | Cluster | Defines session behavior (mode, permissions, constraints, approval) |
| `DebugSession` | Namespaced | Represents an active or past debug session instance |

## Session Modes

Debug sessions support three operational modes:

### Workload Mode (default)

Deploys debug pods as a DaemonSet or Deployment to the target cluster:

```yaml
mode: workload
workloadType: DaemonSet  # or Deployment
```

**Use cases:**
- Node-level debugging requiring host namespaces
- Running debug tools on all or selected nodes
- Network troubleshooting across the cluster

### Kubectl Debug Mode

Enables ephemeral container injection and pod copying via `kubectl debug`:

```yaml
mode: kubectl-debug
kubectlDebug:
  ephemeralContainers:
    enabled: true
  nodeDebug:
    enabled: true
  podCopy:
    enabled: true
```

**Use cases:**
- Debugging running pods without restart
- Attaching debug containers to production workloads
- Node-level debugging with `kubectl debug node`

### Hybrid Mode

Combines both workload deployment and kubectl debug capabilities:

```yaml
mode: hybrid
workloadType: DaemonSet
kubectlDebug:
  ephemeralContainers:
    enabled: true
```

**Use cases:**
- Maximum flexibility for complex debugging scenarios
- Teams needing both persistent debug pods and ad-hoc debugging

## Session State Machine

Debug sessions follow a strict state machine:

```
┌─────────┐     ┌──────────────────┐     ┌────────┐
│ Pending │────▶│ PendingApproval  │────▶│ Active │
└─────────┘     └──────────────────┘     └────────┘
     │                   │                    │
     │                   │                    │
     ▼                   ▼                    ▼
 ┌────────┐          ┌────────┐          ┌─────────┐
 │ Failed │          │ Failed │          │ Expired │
 └────────┘          └────────┘          └─────────┘
                                              │
                                              │
                                          ┌──────────────┐
                                          │ Terminated   │
                                          └──────────────┘
```

| State | Description | Valid for Access |
|-------|-------------|------------------|
| `Pending` | Session is being set up | ❌ |
| `PendingApproval` | Waiting for approver action | ❌ |
| `Active` | Debug pods running, access granted | ✅ |
| `Expired` | Session duration exceeded | ❌ |
| `Terminated` | Manually ended by owner or admin | ❌ |
| `Failed` | Setup failed or rejected | ❌ |

## Resource Definitions

### DebugPodTemplate

Defines the pod specification for debug workloads:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugPodTemplate
metadata:
  name: standard-debug-pod
spec:
  displayName: "Standard Debug Pod"
  description: "General-purpose debug pod with common tools"
  template:
    spec:
      containers:
        - name: debug
          image: alpine:latest
          command: ["sleep", "infinity"]
          securityContext:
            runAsNonRoot: true
            runAsUser: 1000
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 256Mi
      tolerations:
        - operator: Exists  # Run on any node
```

### DebugSessionTemplate

Defines session behavior and permissions:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionTemplate
metadata:
  name: standard-debug
spec:
  displayName: "Standard Debug Session"
  description: "Standard debug access for SRE team"
  mode: workload
  
  # Reference pod template
  podTemplateRef:
    name: standard-debug-pod
  
  # Workload configuration
  workloadType: DaemonSet
  targetNamespace: breakglass-debug
  
  # Access control
  allowed:
    groups:
      - sre-team
      - platform-engineering
    clusters:
      - "prod-*"
      - "staging-*"
  
  # Approval workflow
  approvers:
    groups:
      - sre-leads
    autoApproveFor:
      groups:
        - sre-leads
      clusters:
        - "staging-*"
  
  # Session constraints
  constraints:
    maxDuration: "4h"
    defaultDuration: "1h"
    allowRenewal: true
    maxRenewals: 3
  
  # Optional: Terminal sharing
  terminalSharing:
    enabled: true
    method: tmux
  
  # Optional: Audit logging
  audit:
    logCommands: true
    sidecar:
      image: audit-logger:v1
```

### DebugSession

Created when a user requests a debug session:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSession
metadata:
  name: debug-session-abc123
  namespace: breakglass
spec:
  cluster: prod-cluster-1
  templateRef: standard-debug
  requestedBy: engineer@example.com
  requestedDuration: "2h"
  reason: "Investigating network latency issues on node pool"
  nodeSelector:
    node-pool: application
  invitedParticipants:
    - peer@example.com
status:
  state: Active
  startsAt: "2024-01-15T10:00:00Z"
  expiresAt: "2024-01-15T12:00:00Z"
  renewalCount: 0
  participants:
    - user: engineer@example.com
      role: owner
      joinedAt: "2024-01-15T10:00:00Z"
  allowedPods:
    - namespace: breakglass-debug
      name: debug-session-abc123-ds-xyz
      nodeName: node-1
      ready: true
  deployedResources:
    - apiVersion: apps/v1
      kind: DaemonSet
      name: debug-session-abc123-ds
      namespace: breakglass-debug
```

## Kubectl Debug Configuration

### Ephemeral Containers

Allow injecting ephemeral containers into running pods:

```yaml
kubectlDebug:
  ephemeralContainers:
    enabled: true
    allowedNamespaces:
      - "app-*"
      - "services-*"
    deniedNamespaces:
      - "kube-system"
      - "breakglass"
    allowedImages:
      - "alpine:*"
      - "busybox:*"
      - "debug-tools:*"
    requireImageDigest: false
    maxCapabilities:
      - NET_ADMIN
      - SYS_PTRACE
    allowPrivileged: false
    requireNonRoot: true
```

### Node Debugging

Allow debugging nodes directly:

```yaml
kubectlDebug:
  nodeDebug:
    enabled: true
    allowedImages:
      - "alpine:*"
      - "debug-tools:*"
    hostNamespaces:
      hostNetwork: true
      hostPID: true
      hostIPC: false
    nodeSelector:
      node-role.kubernetes.io/worker: ""
```

### Pod Copy Debugging

Allow creating debug copies of pods:

```yaml
kubectlDebug:
  podCopy:
    enabled: true
    targetNamespace: debug-copies
    labels:
      debug-copy: "true"
    ttl: "2h"
```

## Session Constraints

Control session duration and renewal:

```yaml
constraints:
  # Maximum total session duration
  maxDuration: "8h"
  
  # Default duration if not specified
  defaultDuration: "2h"
  
  # Allow session renewal
  allowRenewal: true
  
  # Maximum number of renewals
  maxRenewals: 3
  
  # Require additional approval for renewals
  requireApprovalForRenewal: false
```

## Terminal Sharing

Enable collaborative debugging with terminal sharing:

```yaml
terminalSharing:
  enabled: true
  method: tmux  # or "screen"
  maxParticipants: 5
  readOnlyParticipants: false
```

When enabled, participants can attach to shared terminals:
- Owner starts the debug session
- Participants join using the `attachCommand` from status
- All participants see the same terminal output

## Approval Workflow

### Automatic Approval

Sessions can be auto-approved based on user groups or target clusters:

```yaml
approvers:
  groups:
    - sre-leads
  autoApproveFor:
    groups:
      - sre-leads      # SRE leads are auto-approved
    clusters:
      - "dev-*"        # All dev clusters are auto-approved
      - "staging-*"    # All staging clusters are auto-approved
```

### Manual Approval

For production clusters or sensitive templates:

```yaml
approvers:
  groups:
    - sre-leads
    - security-team
  # No autoApproveFor means all sessions need explicit approval
```

The approval workflow:
1. User creates session → State: `Pending`
2. Controller checks approval rules → State: `PendingApproval` (or auto-approved)
3. Approver approves/rejects → State: `Active` or `Failed`
4. Session runs until expiry or termination

## Participant Roles

Debug sessions support multiple participant roles:

| Role | Capabilities |
|------|--------------|
| `owner` | Full control, can terminate session, invite others |
| `participant` | Can use debug pods, view terminal |
| `viewer` | Read-only access, can observe terminal sharing |

## Audit Logging

Enable command logging for compliance:

```yaml
audit:
  logCommands: true
  excludePatterns:
    - "history"
    - "clear"
  sidecar:
    image: audit-logger:v1
    resources:
      requests:
        cpu: 50m
        memory: 64Mi
```

## API Endpoints

Debug sessions can be managed via the REST API:

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/v1/debug-sessions` | List all debug sessions |
| `GET` | `/api/v1/debug-sessions/{name}` | Get a specific session |
| `POST` | `/api/v1/debug-sessions` | Create a new session |
| `POST` | `/api/v1/debug-sessions/{name}/join` | Join an existing session |
| `POST` | `/api/v1/debug-sessions/{name}/renew` | Renew session duration |
| `POST` | `/api/v1/debug-sessions/{name}/terminate` | Terminate session |
| `POST` | `/api/v1/debug-sessions/{name}/approve` | Approve session |
| `POST` | `/api/v1/debug-sessions/{name}/reject` | Reject session |
| `GET` | `/api/v1/debug-session-templates` | List available templates |
| `GET` | `/api/v1/debug-pod-templates` | List pod templates |

## Sample Configurations

### Minimal Debug Template

Basic debug access for development:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugPodTemplate
metadata:
  name: minimal-debug-pod
spec:
  displayName: "Minimal Debug Pod"
  template:
    spec:
      containers:
        - name: debug
          image: busybox:latest
          command: ["sleep", "infinity"]
---
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionTemplate
metadata:
  name: minimal-debug
spec:
  displayName: "Minimal Debug"
  mode: workload
  podTemplateRef:
    name: minimal-debug-pod
  workloadType: Deployment
  replicas: 1
  targetNamespace: breakglass-debug
  allowed:
    groups:
      - developers
  constraints:
    maxDuration: "2h"
    defaultDuration: "30m"
```

### Network Debug Template

Privileged networking tools for SRE:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugPodTemplate
metadata:
  name: network-debug-pod
spec:
  displayName: "Network Debug Pod"
  description: "Pod with network troubleshooting tools"
  template:
    spec:
      hostNetwork: true
      hostPID: true
      containers:
        - name: debug
          image: nicolaka/netshoot:latest
          command: ["sleep", "infinity"]
          securityContext:
            privileged: true
      tolerations:
        - operator: Exists
---
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionTemplate
metadata:
  name: network-debug
spec:
  displayName: "Network Debug"
  description: "Privileged network debugging on all nodes"
  mode: workload
  podTemplateRef:
    name: network-debug-pod
  workloadType: DaemonSet
  targetNamespace: breakglass-debug
  allowed:
    groups:
      - network-sre
    clusters:
      - "*"
  approvers:
    groups:
      - sre-leads
  constraints:
    maxDuration: "4h"
    defaultDuration: "1h"
    allowRenewal: true
    maxRenewals: 2
  terminalSharing:
    enabled: true
    method: tmux
  audit:
    logCommands: true
```

### Ephemeral Container Debug Template

For debugging running pods without deploying new workloads:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionTemplate
metadata:
  name: ephemeral-debug
spec:
  displayName: "Ephemeral Container Debug"
  description: "Inject debug containers into running pods"
  mode: kubectl-debug
  kubectlDebug:
    ephemeralContainers:
      enabled: true
      allowedNamespaces:
        - "app-*"
        - "services-*"
      deniedNamespaces:
        - "kube-system"
        - "breakglass"
      allowedImages:
        - "alpine:*"
        - "busybox:*"
        - "nicolaka/netshoot:*"
      requireNonRoot: true
      allowPrivileged: false
  allowed:
    groups:
      - developers
      - sre-team
  constraints:
    maxDuration: "2h"
    defaultDuration: "30m"
```

### Hybrid Debug Template

Maximum flexibility for complex scenarios:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugPodTemplate
metadata:
  name: hybrid-debug-pod
spec:
  displayName: "Hybrid Debug Pod"
  template:
    spec:
      containers:
        - name: debug
          image: debug-tools:v2
          command: ["sleep", "infinity"]
---
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionTemplate
metadata:
  name: hybrid-debug
spec:
  displayName: "Hybrid Debug"
  description: "Combined workload and kubectl debug capabilities"
  mode: hybrid
  podTemplateRef:
    name: hybrid-debug-pod
  workloadType: DaemonSet
  targetNamespace: breakglass-debug
  kubectlDebug:
    ephemeralContainers:
      enabled: true
      allowedNamespaces:
        - "*"
      deniedNamespaces:
        - "kube-system"
    nodeDebug:
      enabled: true
      hostNamespaces:
        hostNetwork: true
        hostPID: true
    podCopy:
      enabled: true
      ttl: "1h"
  allowed:
    groups:
      - sre-team
  approvers:
    groups:
      - sre-leads
    autoApproveFor:
      clusters:
        - "dev-*"
  constraints:
    maxDuration: "4h"
    defaultDuration: "1h"
    allowRenewal: true
    maxRenewals: 3
```

## Best Practices

### Security

1. **Use least privilege**: Start with minimal permissions and add as needed
2. **Require approval for production**: Configure approvers for sensitive clusters
3. **Limit session duration**: Set appropriate maxDuration constraints
4. **Use image allowlists**: Restrict which images can be used
5. **Enable audit logging**: Track all debug activity for compliance

### Operations

1. **Create role-specific templates**: Different templates for different use cases
2. **Use node selectors**: Limit debug pod placement to relevant nodes
3. **Enable terminal sharing**: Facilitate collaborative debugging
4. **Set sensible renewals**: Allow renewals but with limits

### Cleanup

1. **Monitor expired sessions**: Sessions clean up automatically
2. **Review long-running sessions**: Set alerts for sessions approaching max duration
3. **Use termination**: Actively terminate sessions when done

## Troubleshooting

### Session stuck in Pending

- Check if `DebugSessionTemplate` exists and is configured correctly
- Verify `DebugPodTemplate` is referenced correctly
- Check controller logs for errors

### Session stuck in PendingApproval

- Verify approver groups/users are configured
- Check if user is in autoApproveFor groups
- Contact an approver to approve/reject

### Debug pods not starting

- Check target namespace exists on target cluster
- Verify cluster connectivity (ClusterConfig)
- Check resource quotas and limits
- Review pod events for errors

### Cannot exec into debug pods

- Verify session is in `Active` state
- Check `allowedPods` in status
- Ensure pod is `ready: true`
- Verify RBAC permissions on target cluster

## Related Resources

- [Breakglass Session](breakglass-session.md) - Traditional privilege escalation
- [Cluster Config](cluster-config.md) - Target cluster configuration
- [Deny Policy](deny-policy.md) - Blocking specific operations
- [API Reference](api-reference.md) - Full API documentation

## Implementation Status

The debug session feature is fully implemented and ready for use. Below is the current status:

### ✅ Implemented Features

| Feature | Status | Location |
|---------|--------|----------|
| `DebugPodTemplate` CRD | ✅ Complete | `api/v1alpha1/debug_pod_template_types.go` |
| `DebugSessionTemplate` CRD | ✅ Complete | `api/v1alpha1/debug_session_template_types.go` |
| `DebugSession` CRD | ✅ Complete | `api/v1alpha1/debug_session_types.go` |
| Debug session controller | ✅ Complete | `pkg/breakglass/debug_session_reconciler.go` |
| Webhook pod whitelisting | ✅ Complete | `pkg/webhook/controller.go` (checkDebugSessionAccess) |
| REST API endpoints | ✅ Complete | `pkg/breakglass/debug_session_api.go` |
| Prometheus metrics | ✅ Complete | `pkg/metrics/metrics.go` |
| Cleanup routine | ✅ Complete | `pkg/breakglass/cleanup_task.go` |
| Unit tests | ✅ Complete | `*_test.go` files with bad case coverage |
| Documentation | ✅ Complete | `docs/debug-session.md`, `docs/api-reference.md` |
| Frontend UI | ✅ Complete | `frontend/src/views/DebugSession*.vue` |
| Mock API data | ✅ Complete | `frontend/mock-api/data.mjs` |

### Frontend Components

The following Vue components are available for debug session management:

| Component | Path | Description |
|-----------|------|-------------|
| `DebugSessionBrowser` | `views/DebugSessionBrowser.vue` | List and filter debug sessions |
| `DebugSessionCreate` | `views/DebugSessionCreate.vue` | Create new debug sessions from templates |
| `DebugSessionDetails` | `views/DebugSessionDetails.vue` | View session details, participants, pods |
| `DebugSessionCard` | `components/DebugSessionCard.vue` | Summary card for session list |

**Routes:**

- `/debug-sessions` - Browse all debug sessions
- `/debug-sessions/create` - Create a new debug session
- `/debug-sessions/:name` - View session details

**Services:**

- `DebugSessionService` (`services/debugSession.ts`) - API client for all debug session operations
- Model types in `model/debugSession.ts`

### 🔄 Future Enhancements

| Feature | Status | Notes |
|---------|--------|-------|
| Terminal sharing (tmux) | CRD fields exist | Implementation deferred - Phase 5 |
| Audit sidecar | CRD fields exist | Implementation deferred - Phase 5 |
| DenyPolicy integration | Planned | Block debug sessions based on policies |
| Tetragon/Falco integration | Documented only | Optional security monitoring |

### Testing Coverage

The following test categories are implemented:

- **Type tests**: All CRD types, field validation, edge cases
- **Reconciler tests**: State transitions, participant management, approvals, renewals
- **API tests**: All endpoints, request/response serialization, permission checks
- **Bad case tests**: Invalid inputs, unauthorized access, invalid state transitions
- **E2E tests**: Template creation, session lifecycle, multi-participant sessions
- **Frontend tests**: 478 tests passing (Vitest)

```