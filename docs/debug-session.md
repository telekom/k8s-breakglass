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

**Labels & annotations**: `spec.labels`/`spec.annotations` from the template (and binding overrides) are applied to created workloads, pod templates, and supporting resources (e.g., PDBs and ResourceQuotas). Session-level labels/annotations are also propagated.

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

Defines the pod specification for debug workloads. You can use either a structured `template` or a Go-templated `templateString`:

**Structured Template (recommended for static configurations):**

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
          image: ghcr.io/telekom/k8s-breakglass/utils/workload-debug@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
          securityContext:
            runAsNonRoot: true
            runAsUser: 65532
            runAsGroup: 65532
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: [ALL]
            seccompProfile:
              type: RuntimeDefault
          resources:
            requests:
              cpu: 100m
              memory: 128Mi
            limits:
              cpu: 500m
              memory: 256Mi
```

**templateString (for dynamic configurations with session context):**

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugPodTemplate
metadata:
  name: dynamic-debug-pod
spec:
  displayName: "Dynamic Debug Pod"
  description: "Pod with dynamic configuration based on session context"
  templateString: |
    containers:
      - name: debug-{{ .session.name | trunc 15 }}
        image: ghcr.io/telekom/k8s-breakglass/utils/workload-debug@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
        env:
          - name: SESSION_NAME
            value: {{ .session.name | quote }}
          - name: CLUSTER
            value: {{ .session.cluster | quote }}
          - name: REQUESTED_BY
            value: {{ .session.requestedBy | quote }}
        resources:
          limits:
            cpu: {{ .vars.cpuLimit | default "500m" }}
            memory: {{ .vars.memoryLimit | default "256Mi" }}
  ```

The `templateString` supports session context variables (`.session`, `.target`,
and the explicitly declared `.vars` values) using Sprig template functions.
Keep security-sensitive values such as images, commands, mounts, capabilities,
and host namespaces literal in the administrator-owned template. See [Template
Context Variables](#template-context-variables) for the full list.

> **Note:** `template` and `templateString` are mutually exclusive. The webhook will reject DebugPodTemplates with both fields set.

For additive operator-owned documentation supplied through a digest-pinned
OCI image volume, see the [OCI runbook bundle contract](./runbook-bundle-contract.md).

#### Multi-Document YAML in Pod Templates

When using `templateString`, the first document is the PodSpec (the `spec`
portion, not a full Pod object). Additional documents are complete Kubernetes
resources separated by `---`.

**Rules:**
- The **first document** MUST be the PodSpec (just the `spec` portion, not a full Pod definition)
- **Subsequent documents** must be complete Kubernetes resources with `apiVersion` and `kind`
- Additional resources are created BEFORE the debug workload starts
- Additional resources are tracked and cleaned up when the session reaches a
  cleanup state; resources marked `deleteAfter: false` are retained
- Empty documents (blank or whitespace-only) are silently skipped

Use this feature only for provider-reviewed, session-scoped resources such as
a PVC or NetworkPolicy. Do not interpolate an image, command, node name,
mount, capability, Secret value, or RBAC rule from user input. For a complete
authoring pattern, including per-session identity and isolation, see the
[DebugSession authoring guide](./debug-session-authoring.md). For storage
workflows use the [storage utility contract](../utils/images/storage-debug/README.md)
instead of a free-form fio or kubestr pod.

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
  
  # Optional: Scheduling constraints (mandatory, cannot be overridden by users)
  schedulingConstraints:
    nodeSelector:
      node-pool: "general-purpose"
    deniedNodeLabels:
      node-role.kubernetes.io/control-plane: "*"
    deniedNodes:
      - "control-plane-*"
  
  # Optional: Scheduling options (user can choose one)
  schedulingOptions:
    required: true
    options:
      - name: network-capable
        displayName: "Network-capable Nodes"
        description: "Deploy on nodes selected by the downstream platform"
        schedulingConstraints:
          nodeSelector:
            debug.network.example/approved: "true"
      - name: standard
        displayName: "Standard Nodes"
        default: true
        schedulingConstraints:
          nodeSelector: {}
  
  # Optional: Terminal sharing
  terminalSharing:
    enabled: true

  # Optional: Notifications and expiry behavior
  notification:
    enabled: true
    notifyOnRequest: true
    notifyOnApproval: true
    notifyOnExpiry: true
    notifyOnTermination: true
  expirationBehavior: terminate   # or notify-only
  gracePeriodBeforeExpiry: 15m

  # Optional: Resource controls
  resourceQuota:
    maxPods: 5
    maxCPU: "2"
    maxMemory: "2Gi"
    maxStorage: "5Gi"
    enforceResourceRequests: true
    enforceResourceLimits: true
  podDisruptionBudget:
    enabled: true
    minAvailable: 1
    method: tmux
  
  # Optional: Audit logging
  audit:
    logCommands: true
    sidecar:
      image: registry.example/audit-logger@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef

  # Optional: Granular pod operation controls
  allowedPodOperations:
    exec: true        # kubectl exec (also required for kubectl cp)
    attach: true      # kubectl attach
    logs: true        # kubectl logs
    portForward: true # kubectl port-forward
```

The controller updates `DebugSessionTemplate.status` with readiness conditions,
the observed generation, pod-template reference resolution, active session
usage, and clusters made available through active
`DebugSessionClusterBinding` resources.

## Allowed Pod Operations

The `allowedPodOperations` field controls which kubectl operations are permitted on debug session pods. This enables fine-grained access control for different use cases.

The web UI mirrors these permissions in the session details view. For example, when `exec` is disabled, running debug pods show the operation as unavailable and do not offer a copyable `kubectl exec` command.

### Configuration

| Field | Type | Default | Description |
|-------|------|---------|-------------|
| `exec` | bool | true | Allow running commands via `kubectl exec`. Also required for `kubectl cp`. |
| `attach` | bool | true | Allow attaching to container processes via `kubectl attach` |
| `logs` | bool | false | Allow viewing container logs via `kubectl logs` |
| `portForward` | bool | true | Allow port forwarding via `kubectl port-forward` |

### Use Cases

The `allowedPodOperations` field enables least-privilege access patterns for different debugging scenarios. Below are practical examples with security considerations.

#### 1. Logs-Only Access (Read-Only Debugging)

For auditors, support staff, or automated log collection where no interactive access is needed:

```yaml
# Use case: Application log review without shell access
# Security: No code execution, file access, or network access possible
allowedPodOperations:
  exec: false      # Blocks shell access AND kubectl cp
  attach: false    # Cannot attach to running processes
  logs: true       # Can only view stdout/stderr logs
  portForward: false
```

**Example scenarios:**
- L1 support reviewing application errors
- Auditors examining application behavior
- Log aggregation scripts needing direct pod log access
- QA engineers verifying application output

---

#### 2. Core Dump Collection from Host

Use the [diagnostic artifact collector](../utils/images/diagnostic-artifact-collector/README.md)
for its reviewed `crashdump-collection.v1` recipe. It fixes the collector
command, read-only host mount, node placement, output path, and upload
boundary; it is not a general-purpose shell or `kubectl cp` recipe. Binary
core files are sensitive and are not generically redacted.

---

#### 3. Storage Write Benchmark / Functionality Test

Use the [storage diagnostics image](../utils/images/storage-debug/README.md).
Its standard `mounted-volume` mode targets an already attached PVC with
bounded `fio`/`ioping`; its controller-owned advanced operations use a fixed
kubestr contract and a dedicated ServiceAccount. Do not expose arbitrary fio
files, commands, images, StorageClasses, or PVC sizes through a session
request.

---

#### 4. Network Debugging with Port Forwarding

For debugging network connectivity issues with local port access:

```yaml
# Use case: Access internal services via port-forward for testing
# Security: Network access only, no shell execution
allowedPodOperations:
  exec: false      # No shell access
  attach: false
  logs: false
  portForward: true  # Forward internal service ports locally
```

**Example scenarios:**
- Accessing internal databases for query testing
- Testing internal APIs from local development tools
- Connecting to monitoring endpoints (Prometheus, metrics)

**Usage:**
```bash
# Forward internal database port
kubectl port-forward debug-pod-xyz 5432:5432

# Forward internal API server
kubectl port-forward debug-pod-xyz 8080:8080
```

---

#### 5. Process Attachment for Live Debugging

For attaching debuggers (gdb, strace) to running processes:

```yaml
# Use case: Attach debugger to running process
# Security: Attach only, cannot execute new commands or copy files
allowedPodOperations:
  exec: false      # Cannot run arbitrary commands
  attach: true     # Can attach to main process
  logs: false
  portForward: false
```

**Note:** This is useful when the debug container runs a process that needs inspection (e.g., a crash loop that you want to catch with gdb), but you don't want to allow arbitrary command execution.

---

#### 6. Full Debug Access (Maximum Privileges)

For SRE/platform engineers who need complete debugging capabilities:

```yaml
# Use case: Full unrestricted debugging
# Security: Maximum privileges - use sparingly with proper approval
allowedPodOperations:
  exec: true       # Shell access + kubectl cp
  attach: true     # Process attachment
  logs: true       # Log viewing
  portForward: true  # Network access
```

**When to use:**
- Complex multi-faceted debugging requiring all tools
- Incident response where investigation scope is unknown
- Senior engineers with appropriate approval workflow

---

#### 7. Observability-Only Access

For viewing application state without any interactive access:

```yaml
# Use case: Read-only observability for monitoring teams
# Security: Logs and port-forward only - no execution capabilities
allowedPodOperations:
  exec: false
  attach: false
  logs: true         # View application logs
  portForward: true  # Access metrics/health endpoints
```

**Example scenarios:**
- Monitoring team accessing Prometheus metrics endpoint
- SRE reviewing application logs and health checks
- Dashboards requiring direct pod metric access

**Usage:**
```bash
# View logs
kubectl logs debug-pod-xyz -f

# Forward metrics port for Grafana/Prometheus
kubectl port-forward debug-pod-xyz 9090:9090
```

---

### Default Behavior Matrix

| Operation | Default When Field Omitted | Rationale |
|-----------|---------------------------|-----------|
| `exec` | `true` | Primary debugging mechanism |
| `attach` | `true` | Process attachment for debuggers |
| `logs` | `false` | Explicit opt-in for log access |
| `portForward` | `true` | Common for service access |

### Backward Compatibility

When `allowedPodOperations` is not specified (nil), the system defaults to:
- `exec: true`
- `attach: true`  
- `portForward: true`
- `logs: false`

This maintains backward compatibility with existing debug session templates.

### Security Notes

- The webhook enforces operation restrictions by checking the pod subresource (`exec`, `attach`, `log`, `portforward`) against the session's `AllowedPodOperations`.
- `kubectl cp` uses the exec subresource internally (it runs tar in the container). Therefore, `kubectl cp` requires `exec: true` to function. If exec is disabled, all `kubectl cp` operations will be blocked.
- The webhook operates at the subresource level and cannot distinguish between different commands executed via exec.

### Viewing Allowed Operations

**CLI (`bgctl`)**: Use the wide output format to see allowed operations:
```bash
# List sessions with operations column
bgctl debug session list -o wide

# Example output:
# NAME              TEMPLATE        CLUSTER    ...  OPERATIONS
# debug-abc123      standard-debug  prod-1     ...  exec,attach,portforward
# debug-xyz789      logs-only       staging    ...  logs
```

The `get` command shows the full session details including `status.allowedPodOperations`:
```bash
bgctl debug session get debug-abc123 -o yaml
```

The controller persists the resolved operation set in `status.allowedPodOperations`.
Webhook checks read this status field, so controller status updates preserve it
across requeues while the session remains active.

**Web UI**: The session details page displays an "Allowed Pod Operations" card showing which operations are enabled (✓) or disabled (✗) for the session.

### DebugSession

Created when a user requests a debug session:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSession
metadata:
  name: debug-session-abc123
  namespace: breakglass-system
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
      ready: true
  deployedResources:
    - apiVersion: apps/v1
      kind: DaemonSet
      name: debug-session-abc123-ds
      namespace: breakglass-debug
```

## Scheduling Constraints and Options

Debug sessions support advanced scheduling controls that allow administrators to:
- Define mandatory constraints that cannot be overridden by users
- Offer users a choice of predefined scheduling configurations
- Prevent pods from running on control-plane or other restricted nodes

### Scheduling Constraints

Scheduling constraints are **mandatory** and cannot be overridden by users. They're applied after template settings:

```yaml
schedulingConstraints:
  # Mandatory node labels (merged with template)
  nodeSelector:
    node-pool: "general-purpose"
  
  # Hard node affinity requirements (AND logic with existing)
  requiredNodeAffinity:
    nodeSelectorTerms:
      - matchExpressions:
          - key: node-role.kubernetes.io/control-plane
            operator: DoesNotExist
  
  # Soft node affinity preferences (added to existing)
  preferredNodeAffinity:
    - weight: 100
      preference:
        matchExpressions:
          - key: debug-workloads
            operator: In
            values: ["allowed"]
  
  # Pod anti-affinity to spread debug pods
  requiredPodAntiAffinity:
    - labelSelector:
        matchLabels:
          breakglass.t-caas.telekom.com/session-type: debug
      topologyKey: kubernetes.io/hostname
  
  # Additional tolerations (merged with template)
  tolerations:
    - key: "dedicated"
      value: "debug-workloads"
      effect: NoSchedule
  
  # Topology spread constraints
  topologySpreadConstraints:
    - maxSkew: 1
      topologyKey: topology.kubernetes.io/zone
      whenUnsatisfiable: ScheduleAnyway
  
  # Block specific nodes by name pattern (glob)
  deniedNodes:
    - "control-plane-*"
    - "etcd-*"
  
  # Block nodes with any of these labels
  deniedNodeLabels:
    node-role.kubernetes.io/control-plane: "*"
    node-role.kubernetes.io/master: "*"
```

Exact `deniedNodes` entries and `deniedNodeLabels` are rendered into hard node affinity requirements on created debug workloads. Glob-style `deniedNodes` entries are retained in the resolved session constraints for policy visibility, but Kubernetes node affinity cannot enforce glob patterns directly; prefer stable labels in `deniedNodeLabels` for hard node-pool exclusion.

### Scheduling Options

Scheduling options allow administrators to offer users a choice of predefined scheduling configurations. This reduces the need for multiple templates for different node pools:

Scheduling options affect where the debug pod is placed. They do not delay debug-session activation, and `POST /api/debugSessions` does not accept a `scheduledStartTime` field.

```yaml
schedulingOptions:
  # If true, user MUST select an option
  required: true
  
  options:
    - name: network-capable
      displayName: "Network-capable Nodes"
      description: "Deploy on nodes selected by the downstream platform"
      schedulingConstraints:
        nodeSelector:
          debug.network.example/approved: "true"
      # Restrict this option to specific groups
      allowedGroups:
        - netops-admins
    
    - name: standard
      displayName: "Standard Nodes"
      description: "Deploy on regular worker nodes"
      default: true  # Pre-selected in UI
      schedulingConstraints:
        nodeSelector: {}
    
    - name: any
      displayName: "Any Worker Node"
      description: "Deploy on any available worker node"
      schedulingConstraints: {}  # No additional constraints
```

`allowedGroups` and `allowedUsers` are enforced when a `DebugSession` request is created. The API checks the selected option, including a required option that is selected by default, against the authenticated user's username, email, and groups. Requests for restricted options return `403 Forbidden` when the requester does not match. Leave both fields empty only for options that are safe for every requester who can use the template.

The controller refreshes `status.allowedPods` dynamically as debug pods start, stop, or change readiness. That refresh is scoped to the pod-list field so it does not rewrite API-owned session lifecycle details such as participants, renewal count, or `expiresAt`.

**Merge Logic**: When a user selects an option, the constraints are merged in this order:
1. Base constraints from `DebugPodTemplate`
2. Overrides from `DebugSessionTemplate`
3. Base `schedulingConstraints` from template (mandatory for all options)
4. Selected option's `schedulingConstraints` (additive)
5. User's `nodeSelector` (if allowed by template)

Selected options and cluster bindings may add stricter constraints but cannot replace mandatory ones. If a binding or option sets a different value for an existing mandatory `nodeSelector` key, the request is rejected instead of silently weakening the base constraint. `deniedNodeLabels` are additive: a wildcard `*` value denies every value for that key and dominates narrower exact-value entries, while conflicting exact values for the same key are rejected. Required node affinity is combined with Kubernetes-correct AND semantics across selector terms.

## Namespace Constraints

Namespace constraints control where debug pods can be deployed. They allow administrators to:
- Define allowed and denied namespace patterns
- Set a default namespace for debug sessions
- Allow or prohibit user-specified namespaces
- Automatically create namespaces if they don't exist

### Configuration

```yaml
namespaceConstraints:
  # Default namespace when user doesn't specify one
  defaultNamespace: "breakglass-debug"
  
  # Allow users to request a specific namespace
  allowUserNamespace: true
  
  # Patterns for allowed namespaces (glob-style)
  allowedNamespaces:
    patterns:
      - "debug-*"
      - "troubleshoot-*"
    # Or use label selectors (Kubernetes label selector semantics)
    selectorTerms:
      # matchLabels for simple key=value matching
      - matchLabels:
          debug-enabled: "true"
      # matchExpressions for advanced matching
      - matchExpressions:
          - key: environment
            operator: In
            values: ["dev", "staging", "test"]
          - key: restricted
            operator: DoesNotExist
  
  # Patterns for denied namespaces (evaluated after allowed)
  deniedNamespaces:
    patterns:
      - "kube-*"
      - "default"
      - "production-*"
    selectorTerms:
      - matchLabels:
          protected: "true"
      - matchExpressions:
          - key: compliance
            operator: In
            values: ["pci-dss", "hipaa"]
  
  # Create namespace if it doesn't exist
  createIfNotExists: false
  
  # Labels to apply when creating namespaces
  namespaceLabels:
    managed-by: breakglass
    purpose: debug-session
```

### Label Selector Semantics

The `selectorTerms` field uses standard Kubernetes label selector semantics:

- **Multiple `selectorTerms`**: Combined with OR logic (namespace matches if ANY term matches)
- **Within a single term**: `matchLabels` and `matchExpressions` are combined with AND logic
- **Supported operators**: `In`, `NotIn`, `Exists`, `DoesNotExist`

Example: Allow debugging in namespaces that are EITHER:
- Labeled with `debug-enabled: true`, OR
- In non-production environments (dev/staging/test)

```yaml
selectorTerms:
  # Term 1: explicit opt-in
  - matchLabels:
      debug-enabled: "true"
  # Term 2: environment-based (OR with Term 1)
  - matchExpressions:
      - key: environment
        operator: In
        values: ["dev", "staging", "test"]
```

### Behavior

When a user creates a debug session:

1. **No namespace specified**: Uses `defaultNamespace` from constraints (falling back to `breakglass-debug`), still validated against the allow/deny filters
2. **Namespace specified + `allowUserNamespace: false`** or **`denyUserNamespace: true`**: Request rejected. `denyUserNamespace` always wins over `allowUserNamespace`
3. **Namespace specified + `allowUserNamespace: true`**:
   - Validated against the **effective allow-list**, which is the intersection of every configured `allowedNamespaces` filter. If no `allowedNamespaces` is configured at all, **only `defaultNamespace` is allowed** — an empty allow-list is not "allow any".
   - Validated against the union of every configured `deniedNamespaces` filter (deny takes precedence).
   - `selectorTerms` on either the allow or the deny side are evaluated against **live namespace labels** read from the target cluster. If those labels cannot be read (spoke API error, namespace missing, no client configured), the request is **rejected** with an error naming the namespace and the offending filter — a selector-based policy is never silently skipped.
   - If a `DebugSessionClusterBinding` is selected, the namespace must satisfy both the template constraints and the binding constraints
4. **Namespace doesn't exist**: 
   - `createIfNotExists: true`: Creates namespace with `namespaceLabels`
   - `createIfNotExists: false`: Session fails or uses fail-open mode

The web UI validates Kubernetes namespace syntax and glob-style allowed/denied patterns before submitting a debug session request. The API and controller remain the authoritative enforcement points for namespace constraints and cluster state.
Kubectl-debug namespace selectors for ephemeral-container injection and pod-copy creation are evaluated against live namespace labels from the target cluster; selector-based policies fail closed if those labels cannot be read.

### Example: Team-Isolated Debug Namespaces

```yaml
spec:
  namespaceConstraints:
    defaultNamespace: "team-sre-debug"
    allowUserNamespace: true
    allowedNamespaces:
      patterns:
        - "team-sre-*"
        - "shared-debug"
      selectorTerms:
        - matchLabels:
            team: sre
        - matchExpressions:
            - key: debug-level
              operator: In
              values: ["standard", "elevated"]
    deniedNamespaces:
      patterns:
        - "*-prod"
        - "*-production"
      selectorTerms:
        - matchLabels:
            production: "true"
    createIfNotExists: true
    namespaceLabels:
      team: sre
      purpose: debug
```

## Impersonation

Impersonation allows the breakglass controller to deploy debug resources using a constrained ServiceAccount instead of its own permissions. This enables least-privilege deployment:

### Using an Existing ServiceAccount

Reference a pre-existing ServiceAccount that the controller will impersonate:

```yaml
impersonation:
  serviceAccountRef:
    name: debug-deployer
    namespace: breakglass-system
```

**Requirements:**
- The referenced ServiceAccount must exist
- The breakglass controller needs explicit impersonation permissions for this SA. The production base does not grant broad user/group impersonation.
- RBAC for impersonation:
  ```yaml
  apiVersion: rbac.authorization.k8s.io/v1
  kind: ClusterRole
  metadata:
    name: breakglass-impersonator
  rules:
    - apiGroups: [""]
      resources: ["serviceaccounts"]
      verbs: ["impersonate"]
      resourceNames: ["debug-deployer"]
  ```

### When to Use Impersonation

| Scenario | Approach |
|----------|----------|
| Multi-tenant clusters | Pre-configured SA with tenant-scoped permissions |
| Audit requirements | Existing SA with dedicated identity |
| Least-privilege | SA with minimal permissions |
| Simple setup | No impersonation (uses controller's SA) |

## Auxiliary Resources

Auxiliary resources are additional Kubernetes objects deployed alongside debug pods. They provide supporting infrastructure like network isolation, RBAC, configuration, and monitoring.

### Configuration

Define auxiliary resources in your `DebugSessionTemplate`:

```yaml
spec:
  auxiliaryResources:
    - name: debug-network-policy
      category: network-policy
      description: "Restricts debug pod network access"
      template:
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        metadata:
          name: "debug-{{ .session.name }}-isolation"
          namespace: "{{ .target.namespace }}"
        spec:
          podSelector:
            matchLabels:
              breakglass.t-caas.telekom.com/session: "{{ .session.name }}"
          policyTypes:
            - Ingress
            - Egress
          egress:
            - to:
                - namespaceSelector:
                    matchLabels:
                      kubernetes.io/metadata.name: kube-dns
              ports:
                - protocol: UDP
                  port: 53
```

### Multi-Document YAML Templates

Use `templateString` instead of `template` for multi-document YAML. This allows deploying multiple Kubernetes resources from a single auxiliary resource definition:

```yaml
spec:
  auxiliaryResources:
    - name: debug-rbac-bundle
      category: rbac
      description: "Creates ServiceAccount, Role, and RoleBinding for debug pods"
      templateString: |
        apiVersion: v1
        kind: ServiceAccount
        metadata:
          name: debug-{{ .session.name }}-sa
          namespace: {{ .target.namespace }}
        ---
        apiVersion: rbac.authorization.k8s.io/v1
        kind: Role
        metadata:
          name: debug-{{ .session.name }}-role
          namespace: {{ .target.namespace }}
        rules:
          - apiGroups: [""]
            resources: ["pods", "pods/log"]
            verbs: ["get", "list"]
        ---
        apiVersion: rbac.authorization.k8s.io/v1
        kind: RoleBinding
        metadata:
          name: debug-{{ .session.name }}-binding
          namespace: {{ .target.namespace }}
        subjects:
          - kind: ServiceAccount
            name: debug-{{ .session.name }}-sa
            namespace: {{ .target.namespace }}
        roleRef:
          kind: Role
          name: debug-{{ .session.name }}-role
          apiGroup: rbac.authorization.k8s.io
```

All resources from multi-document YAML are:
- Tracked in the session status for observability
- Cleaned up automatically when the session ends unless `deleteAfter: false`
- Monitored for readiness using kstatus

Auxiliary resource lifecycle is reflected in
`status.auxiliaryResourceStatuses`. Additional objects produced by
multi-document pod templates are reflected in
`status.podTemplateResourceStatuses`, allowing cleanup and audit workflows to
continue from persisted status after controller requeues or restarts.

> **Note:** `template` (structured) and `templateString` (Go template) are mutually exclusive. Use `templateString` when you need multi-document YAML or dynamic templating.

### Resource Categories

Common categories for organizing auxiliary resources:

| Category | Description | Examples |
|----------|-------------|----------|
| `network-policy` | Network isolation | NetworkPolicy, CiliumNetworkPolicy |
| `rbac` | Access control | Role, RoleBinding, ServiceAccount |
| `configmap` | Configuration data | ConfigMap, Secret |
| `monitoring` | Observability | ServiceMonitor, PodMonitor |
| `custom` | Other resources | Any Kubernetes resource |

### Template Variables

Auxiliary resource templates support Go templating with [Sprig functions](https://masterminds.github.io/sprig/). Available variables:

| Variable | Description |
|----------|-------------|
| `.session.name` | Debug session name |
| `.session.namespace` | Session's namespace |
| `.session.cluster` | Target cluster name |
| `.session.requestedBy` | Requesting user |
| `.target.namespace` | Target namespace for debug pods |
| `.session.reason` | Session request reason |
| `.template.name` | Template name |

### Lifecycle

1. **Creation**: Auxiliary resources are created before debug pods start when `createBefore: true` (the default), or after the debug workload is applied when `createBefore: false`
2. **Cleanup**: Resources are deleted when the session ends when `deleteAfter: true` (the default), and retained when `deleteAfter: false`

### Failure Policies

Control behavior when auxiliary resource creation fails:

```yaml
auxiliaryResources:
  - name: optional-monitoring
    category: monitoring
    failurePolicy: ignore  # Continue if creation fails
    template: ...
```

| Policy | Behavior |
|--------|----------|
| `fail` | Abort session if resource creation fails (default) |
| `ignore` | Continue session regardless of failure |
| `warn` | Log warning and continue |

The controller also treats an omitted `failurePolicy` as `fail`. The deprecated `optional: true` field is honored as `ignore` for backwards compatibility.

### Cluster Binding Overrides

Cluster bindings can require specific auxiliary resource categories:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionClusterBinding
metadata:
  name: team-production
spec:
  templateRef:
    name: standard-debug
  clusters:
    - production-eu
  requiredAuxiliaryResourceCategories:
    - network-policy  # Always require network isolation
    - rbac            # Always require RBAC setup
```

### Pod Template Multi-Doc vs Auxiliary Resources

Both pod templates and auxiliary resources support multi-document YAML for creating additional Kubernetes resources. Here's when to use each:

| Feature | Pod Template Multi-Doc | Auxiliary Resources |
|---------|----------------------|---------------------|
| **Use Case** | Resources tightly coupled to the pod | Reusable, policy-enforced resources |
| **Failure Policy** | Session fails if creation fails | Configurable (fail/ignore/warn) |
| **Readiness Tracking** | Basic (created/deleted) | Full kstatus monitoring |
| **Categories** | Not categorized | Organized by category |
| **Binding Requirements** | N/A | Can enforce required categories |
| **Template Context** | `.session`, `.target`, `.vars` | `.session`, `.target`, `.vars` |

**Choose Pod Template Multi-Doc when:**
- Resources are specific to this pod template (e.g., PVC for storage testing)
- You want a self-contained template with all its dependencies
- The resources have a 1:1 relationship with the pod

**Choose Auxiliary Resources when:**
- Resources need failure policies (ignore failures for optional monitoring)
- Cluster bindings should enforce certain resource categories
- You need detailed readiness tracking via kstatus
- Resources are reusable across multiple templates

## Cluster Bindings

`DebugSessionClusterBinding` resources delegate access to debug session templates for specific clusters and teams. They enable:

- **Team-scoped access**: Restrict which teams can use a template on which clusters
- **Constraint overrides**: Customize durations, namespaces, and approval requirements per cluster
- **Impersonation**: Deploy debug pods using a constrained ServiceAccount

When a request omits `bindingRef`, the API can still default to an applicable
binding for the target cluster. If the selected binding has non-empty
`spec.allowed.users` or `spec.allowed.groups`, those requester rules replace
the template requester allowlist for that matched cluster. A caller who is
allowed by the template but not by the selected binding is rejected instead of
receiving that binding's constraints, labels, approvers, or impersonation
settings. Bindings that omit `spec.allowed`, or set it without users or groups,
still inherit the template requester allowlist.

### Basic Binding

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionClusterBinding
metadata:
  name: sre-production-access
  namespace: breakglass-system
spec:
  templateRef:
    name: network-debug
  clusters:
    - production-eu
    - production-us
  displayName: "SRE Production Debug"
  allowed:
    groups:
      - sre-team
      - platform-oncall
```

### Constraint Overrides

Override template constraints for specific clusters:

```yaml
spec:
  constraints:
    maxDuration: "2h"      # Stricter than template
    defaultDuration: "30m"
    maxRenewals: 1
  namespaceConstraints:
    allowedPatterns:
      - "breakglass-*"
    deniedPatterns:
      - "kube-*"
```

### Approval Overrides

Configure cluster-specific approval requirements:

```yaml
spec:
  approvers:
    groups:
      - security-leads     # Different approvers per cluster
  autoApprove: false       # Require manual approval
```

### Template Clusters API

The two-step session creation flow uses the template clusters API to show users available clusters with resolved constraints:

```http
GET /api/debugSessions/templates/:name/clusters
```

Only ready cluster configurations are offered as debug targets. A matching `ClusterConfig` must have `Ready=True`; clusters with `Ready=False`, `Ready=Unknown`, no ready condition, or a duplicate `metadata.name` in another namespace are hidden from this response and `POST /api/debugSessions` rejects new debug sessions that target them. `DebugSessionClusterBinding` objects with `spec.hidden: true` are also omitted from this UI discovery response, but callers that already know the binding name can still use it through an explicit `bindingRef` in `POST /api/debugSessions`.

Template and cluster discovery is requester-specific. The API returns a
template only when the authenticated requester can use the template directly or
through at least one active matching `DebugSessionClusterBinding`. Cluster
entries, binding options, scheduling options, and extra deploy variables that
the requester cannot use at session creation time are omitted from discovery
responses.

Response includes per-cluster details:

```json
{
  "templateName": "network-debug",
  "templateDisplayName": "Network Debug Access",
  "clusters": [
    {
      "name": "production-eu",
      "displayName": "Production EU",
      "bindingRef": {
        "name": "sre-production",
        "namespace": "breakglass"
      },
      "constraints": {
        "maxDuration": "2h",
        "defaultDuration": "30m"
      },
      "approval": {
        "required": true,
        "approverGroups": ["security-leads"]
      }
    }
  ]
}
```

## Kubectl Debug Configuration

### Ephemeral Containers

Allow injecting ephemeral containers into running pods:

```yaml
kubectlDebug:
  ephemeralContainers:
    enabled: true
    allowedNamespaces:
      patterns:
        - "app-*"
        - "services-*"
    deniedNamespaces:
      patterns:
        - "kube-system"
        - "breakglass"
    allowedImages:
      - "ghcr.io/telekom/k8s-breakglass/utils/network-debug@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    requireImageDigest: true
    maxCapabilities: []
    allowPrivileged: false
    requireNonRoot: true
```

`allowedImages` entries are exact image references or explicit glob patterns.
Prefer one reviewed digest per template and set `requireImageDigest: true`.
When `allowPrivileged` is `false`, requests with
`securityContext.privileged: true` are rejected. The template's allowlist is
not a reason to expose image or command selection to an untrusted caller.

#### Namespace Filtering with Labels

The `allowedNamespaces` and `deniedNamespaces` fields support label selectors for dynamic namespace matching:

```yaml
kubectlDebug:
  ephemeralContainers:
    enabled: true
    # Allow namespaces matching patterns OR labels
    allowedNamespaces:
      patterns:
        - "app-*"
      selectorTerms:
        - matchLabels:
            debug-enabled: "true"
    # Deny namespaces matching patterns OR labels  
    deniedNamespaces:
      patterns:
        - "kube-*"
      selectorTerms:
        - matchLabels:
            restricted: "true"
        - matchExpressions:
            - key: tier
              operator: In
              values: ["critical", "production"]
```

This allows:
- Pattern-based matching (e.g., `app-*` matches `app-frontend`, `app-backend`)
- Label-based matching using Kubernetes label selectors
- Combined patterns and labels (OR logic between them)

### Node Debugging

Allow debugging nodes directly:

```yaml
kubectlDebug:
  nodeDebug:
    enabled: true
    allowedImages:
      - "ghcr.io/telekom/k8s-breakglass/utils/network-debug@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
    hostNamespaces:
      hostNetwork: true
      hostPID: true
      hostIPC: false
    nodeSelector:
      node-role.kubernetes.io/worker: ""
```

Node-debug pods are created in the debug session's resolved
`spec.targetNamespace` first, then the template `targetNamespace`, and finally
the default `breakglass-debug` namespace.

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

Requested durations must be positive and cannot exceed the effective
`maxDuration`. When a request selects a `DebugSessionClusterBinding` through
`bindingRef`, or the API/reconciler defaults to a requester-authorized
applicable binding for the target cluster, that binding's duration constraints
override the template constraints for that session. Renewals extend the current
expiration time, but the renewed expiration cannot move past
`status.startsAt + maxDuration`.
Only the requester or an active `owner`/`participant` status entry can renew a
session; `viewer` entries and participants with `leftAt` set cannot renew.
The active-session expiry, approval-timeout, expiring-soon message, cleanup
timeout, and cleanup expiry writers use optimistic locking, so stale reconciler
or cleanup passes cannot overwrite a newer renewal or participant update.

## Terminal Sharing

Enable collaborative debugging with terminal sharing:

```yaml
terminalSharing:
  enabled: true
  provider: tmux  # or "screen"
  maxParticipants: 5
  readOnlyParticipants: false
```

When enabled, participants can attach to shared terminals:
- Owner starts the debug session
- Invited users join the session as viewers and use the `attachCommand` from status
- All participants see the same terminal output

**Implementation details:**
- When terminal sharing is enabled, the controller wraps the container command with `tmux new-session` or `screen` 
- The attach command is populated in `status.terminalSharing.attachCommand`
- Invited viewers can attach to the shared terminal. The join API does not accept a request body and does not grant the privileged `participant` role; only existing owner or participant status entries can use debug pod operations.
- The debug image must include the selected terminal sharing binary (`tmux` or `screen`)

**Tmux image for E2E:**
- The repository provides a tmux-enabled image at [e2e/images/tmux-debug/Dockerfile](../e2e/images/tmux-debug/Dockerfile)
- E2E setup scripts build it as `breakglass-tmux-debug:e2e` and load it into Kind before terminal-sharing tests run
- Test pod templates set `imagePullPolicy: IfNotPresent`, and pod-copy E2E requests use the fixed-tag `breakglass-tmux-debug:e2e` image so Kubernetes uses a preloaded Kind image when it is already present instead of pulling from a registry
- Override the image name via `TMUX_DEBUG_IMAGE` if needed

## Approval Workflow

### What counts as a configured approver set

An approver set is *configured* only when it names at least one user or group.
All of the following mean "no approvers configured":

```yaml
# omitted entirely
# ---
approvers: {}
# ---
approvers:
  users: []
  groups: []
```

When no approvers are configured, sessions using that template or binding are
**auto-approved** — they never enter `PendingApproval`, so no approval is needed.
Consistently with that, an unconfigured approver set makes **nobody** an approver:
it does not mean "any authenticated user may approve". Approval and read
authorization apply the same rule.

If you want four-eyes control, you must name approvers explicitly. An empty
approver set grants no approval rights and gates nothing.

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

Approval and rejection handlers block requester self-approval by comparing both the authenticated username and email against `spec.requestedBy` and `spec.requestedByEmail`. A requester remains blocked even when they also belong to an approver group.

When a session is created through a `DebugSessionClusterBinding`, approval and rejection use the approvers from the recorded `spec.bindingRef`. Other bindings that match the same template or cluster do not grant approval for that session.

## Participant Roles

Debug sessions support multiple participant roles:

| Role | Capabilities |
|------|--------------|
| `owner` | Full control, can terminate session, invite others |
| `participant` | Can use debug pods, view terminal |
| `viewer` | Read-only access, can observe terminal sharing |

Joining an existing session requires an entry in `spec.invitedParticipants`, an active unexpired session, and terminal sharing enabled by the resolved template/status. Leaving or terminating through the API also requires the session to still be active and unexpired. Self-service join requests always create `viewer` entries; users cannot request the `participant` role for themselves.
Kubectl-debug mutation endpoints require the requester, an active `owner`, or an active `participant`; active `viewer` entries remain read-only and receive `403 Forbidden` for pod mutation requests.

Leaving a session sets `status.participants[].leftAt`. Participants with
`leftAt` set are no longer treated as active participants for kubectl-debug
lookup or authorization webhook pod operations.

## Audit Logging

Enable command logging for compliance:

```yaml
audit:
  logCommands: true
  excludePatterns:
    - "history"
    - "clear"
  sidecar:
    image: registry.example/audit-logger@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
    resources:
      requests:
        cpu: 50m
        memory: 64Mi
```

The DebugSession reconciler emits lifecycle audit events through configured
`AuditConfig` sinks for approval timeouts, session failures, pod failures,
container restarts, and auxiliary resource deploy/cleanup operations. Failure
notifications to the requester use the configured `MailProvider` and honor
`--disable-email`.

## API Endpoints

Debug sessions can be managed via the REST API:

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/debugSessions` | List debug sessions visible to the caller |
| `GET` | `/api/debugSessions/{name}` | Get a specific visible session |
| `POST` | `/api/debugSessions` | Create a new session |
| `POST` | `/api/debugSessions/{name}/join` | Join an existing session |
| `POST` | `/api/debugSessions/{name}/leave` | Leave an existing session |
| `POST` | `/api/debugSessions/{name}/renew` | Renew session duration |
| `POST` | `/api/debugSessions/{name}/terminate` | Terminate session |
| `POST` | `/api/debugSessions/{name}/approve` | Approve session |
| `POST` | `/api/debugSessions/{name}/reject` | Reject session |
| `GET` | `/api/debugSessions/templates` | List available templates |
| `GET` | `/api/debugSessions/podTemplates` | List pod templates |
| `POST` | `/api/debugSessions/{name}/injectEphemeralContainer` | Inject ephemeral container into a pod |
| `POST` | `/api/debugSessions/{name}/createPodCopy` | Create a debug copy of a pod |
| `POST` | `/api/debugSessions/{name}/createNodeDebugPod` | Create a debug pod on a node |

Lifecycle actions `join`, `leave`, and `terminate` reject non-empty request bodies.

List and detail responses require an authenticated caller. A caller can read a
debug session when they are the requester, an active participant, an invited
participant, a configured approver, or a recorded approver/rejector for that
session.

Mutating DebugSession endpoints that accept JSON bodies use strict decoding:
unknown fields, malformed JSON, and trailing JSON values return `400 Bad
Request`. The join endpoint may omit its body and defaults to the `viewer` role;
non-empty join bodies must still be strict JSON.

List and detail responses include `canApprove` and `canReject` booleans for the
current caller. The web UI uses these fields to show approve/reject controls
only to authorized approvers for sessions in `PendingApproval`; unauthorized
callers may still read visible sessions but do not see approval actions.

Status-changing actions use optimistic locking. If another request changes the
same `DebugSession` between read and write, the API returns `409 Conflict`; the
client should refresh the session and retry when appropriate.

### Kubectl Debug API Endpoints

These endpoints are available for sessions in `kubectl-debug` or `hybrid` mode.
The session must still be active and unexpired at request time; operations are
rejected after `status.expiresAt` even if cleanup has not yet marked the session
`Expired`. Policy denials such as disallowed namespaces or node selector
mismatches return `403 Forbidden`; unsupported or malformed operation requests
return `400 Bad Request`.
They require the requester, an active `owner`, or an active `participant` role
on the session. `viewer` participants can observe shared terminals but cannot
inject ephemeral containers, create pod copies, or create node debug pods.

Kubectl-debug operations merge their operation-specific status fields into the
current `DebugSession` status before returning. Concurrent renewals, participant
changes, and lifecycle updates are preserved while the operation records copied
pods, injected containers, allowed pods, or cleanup state.

#### Inject Ephemeral Container

**POST** `/api/debugSessions/{name}/injectEphemeralContainer`

Inject a debug container into a running pod without restarting it.

The wire request contains the target namespace/pod and container name plus the
operation's image and command fields. The upstream API surface does not select
safe values for a deployment. Generate those fields only from an
administrator-owned, digest-pinned profile and enforce that profile with
admission; this page intentionally provides no free-form request example.

**Response:**
```json
{
  "message": "ephemeral container injected successfully",
  "pod": "my-app-pod-xyz",
  "namespace": "default",
  "container": "debug"
}
```

#### Create Pod Copy

**POST** `/api/debugSessions/{name}/createPodCopy`

Create a copy of an existing pod for debugging without affecting the original.

The wire request identifies the source namespace/pod and may carry a debug
image. The image, if used, must come from an administrator-owned,
digest-pinned profile. Do not expose that field as caller-selected input; this
page intentionally provides no free-form request example.

**Response:**
```json
{
  "message": "pod copy created successfully",
  "copyName": "my-app-pod-xyz-debug-abc123",
  "copyNamespace": "default",
  "originalPod": "my-app-pod-xyz",
  "originalNamespace": "default"
}
```

#### Create Node Debug Pod

**POST** `/api/debugSessions/{name}/createNodeDebugPod`

Create a privileged debug pod on a specific node for node-level debugging.

The wire request carries a node name. Resolve it from a controller-owned,
allowlisted scheduling policy and verify the target at admission; a requester
must not be able to select an arbitrary node. This page intentionally provides
no free-form request example. The current implementation creates a privileged
pod with host namespaces and a read-write `/host` host-path; expose this
endpoint only through a separately reviewed, short-lived node-maintenance
profile and admission policy.

**Response:**
```json
{
  "message": "node debug pod created successfully",
  "podName": "node-debug-worker-node-1-abc123",
  "namespace": "breakglass-debug",
  "node": "worker-node-1"
}
```

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
          image: ghcr.io/telekom/k8s-breakglass/utils/workload-debug@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
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

Use the [network-debug utility contract](../utils/network-debug/README.md)
and the [DebugSession authoring guide](./debug-session-authoring.md). Keep
ordinary pod-network diagnostics separate from the advanced host-network/
host-PID `pwru` profile; the latter requires a distinct approval and a
provider-enforced security context. Do not copy a privileged or all-node
template into a general-purpose session.

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
        patterns:
          - "app-*"
          - "services-*"
      deniedNamespaces:
        patterns:
          - "kube-system"
          - "breakglass"
      allowedImages:
        - "ghcr.io/telekom/k8s-breakglass/utils/network-debug@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
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
          image: ghcr.io/telekom/k8s-breakglass/utils/workload-debug@sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
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
        patterns:
          - "app-*"
      deniedNamespaces:
        patterns:
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
4. **Investigate cleanup retries**: Failed debug-resource deletes keep their status tracking entries so the controller can retry cleanup on the next reconciliation

## Troubleshooting

### Session stuck in Pending

- Check if `DebugSessionTemplate` exists and is configured correctly
- Verify `DebugPodTemplate` is referenced correctly
- Check controller logs for errors

### Session stuck in PendingApproval

- Verify approver groups/users are configured
- Check if user is in autoApproveFor groups
- Contact an approver to approve/reject
- Sessions automatically fail after `DEBUG_SESSION_APPROVAL_TIMEOUT` (default: 24h) — approve/reject API calls enforce the deadline immediately, and the reconciler also checks this on every requeue cycle

### Debug session templates or compatible clusters fail to load in the UI

- Use the retry action on the create page to reload the template list or compatible-cluster list after transient API errors
- Verify the API server can list `DebugSessionTemplate`, `DebugSessionClusterBinding`, and `ClusterConfig` resources
- Check controller/API logs for the request correlation ID shown in the toast notification
- Treat this differently from `No Debug Session Templates Available`, which means the API request succeeded but no templates were returned
- Treat `No clusters are available for this template` differently from a cluster-load error; the former means the compatible-cluster request succeeded with an empty list

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

## Interaction with Deny Policies

Active debug sessions take precedence over [deny policies](deny-policy.md) for pod-level operations. When the authorization webhook processes a `SubjectAccessReview` for `exec`, `attach`, `portforward`, or `log` on a specific pod, it checks for matching debug sessions **before** evaluating deny policies.

This means:

- An active debug session participant can exec into their allowed pods even if a `DenyPolicy` would normally block exec operations.
- The bypass applies **only** to pods listed in `status.allowedPods` and operations resolved in `status.allowedPodOperations` (derived from the template/binding configuration).
- Participants with `status.participants[].leftAt` set no longer receive this bypass.
- All other operations (e.g., `get`, `delete`, `create` on non-pod resources) still go through normal deny policy evaluation.

This is intentional — debug sessions represent pre-approved, time-limited troubleshooting access. The security boundary is enforced at session creation time through `DebugSessionTemplate` constraints:

- **Namespace restrictions** — `allowedNamespaces` / `deniedNamespaces` control where debug pods can be created
- **Image allow-lists** — `allowedImages` restricts which debug container images can be used by exact reference or explicit glob pattern
- **Privileged ephemeral containers** — `allowPrivileged: false` blocks ephemeral container requests with `securityContext.privileged: true`
- **Approval requirements** — `approvalConfig` can require explicit approver sign-off
- **Time limits** — `maxDuration` caps session lifetime
- **Operation restrictions** — `status.allowedPodOperations` (resolved from template/binding) limits which subresources are accessible

See [Deny Policy — Policy Evaluation](deny-policy.md#policy-evaluation) for the full evaluation order.

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
| Debug session controller | ✅ Complete | `pkg/breakglass/debug/debug_session_reconciler.go` |
| Webhook pod whitelisting | ✅ Complete | `pkg/webhook/controller.go` (checkDebugSessionAccess) |
| REST API endpoints | ✅ Complete | `pkg/breakglass/debug/debug_session_api.go` |
| Kubectl-debug API endpoints | ✅ Complete | `pkg/breakglass/debug/debug_session_kubectl.go` |
| Terminal sharing configuration | ✅ Complete | `pkg/breakglass/debug/debug_session_reconciler.go` |
| Auto-approve by group | ✅ Complete | `pkg/breakglass/debug/debug_session_reconciler.go` |
| Prometheus metrics | ✅ Complete | `pkg/metrics/metrics.go` |
| Cleanup routine | ✅ Complete | `pkg/breakglass/cleanup_task.go` |
| Unit tests | ✅ Complete | `*_test.go` files with bad case coverage |
| E2E tests | ✅ Complete | `e2e/debug_session_e2e_test.go` |
| Documentation | ✅ Complete | `docs/debug-session.md`, `docs/api-reference.md` |
| Frontend UI | ✅ Complete | `frontend/src/views/DebugSession*.vue` |
| Frontend kubectl-debug UI | ✅ Complete | `frontend/src/views/DebugSessionDetails.vue` |
| Mock API data | ✅ Complete | `frontend/mock-api/data.mjs` |

### Kubectl-Debug Features

The following kubectl-debug style operations are fully implemented:

| Operation | Description | API Endpoint |
|-----------|-------------|--------------|
| Ephemeral Container Injection | Inject debug containers into running pods | `POST /injectEphemeralContainer` |
| Pod Copy | Create debug copies of pods | `POST /createPodCopy` |
| Node Debug Pod | Create privileged pods on nodes | `POST /createNodeDebugPod` |

**Security Controls:**
- Operations are only available for sessions in `kubectl-debug` or `hybrid` mode
- Each operation type can be individually enabled/disabled in the template
- Namespace allow/deny lists control where operations can target
- Image allow lists restrict which debug images can be used
- Security context restrictions (privileged, capabilities, runAsNonRoot)

### Frontend Components

The following Vue components are available for debug session management:

| Component | Path | Description |
|-----------|------|-------------|
| `DebugSessionBrowser` | `views/DebugSessionBrowser.vue` | List and filter debug sessions |
| `DebugSessionCreate` | `views/DebugSessionCreate.vue` | Create new debug sessions from templates |
| `DebugSessionDetails` | `views/DebugSessionDetails.vue` | View session details, participants, pods, kubectl-debug operations |
| `DebugSessionCard` | `components/DebugSessionCard.vue` | Summary card for session list |

The debug session create wizard moves keyboard focus to the cluster and
configuration step after the template step advances, so keyboard and screen
reader users are placed in the newly rendered workflow context.

The Debug Session browser and detail routes are covered by mobile Playwright screenshots. Their responsive layouts must not introduce document-level horizontal scrolling; long pod names, participant identifiers, and kubectl command snippets wrap or scroll inside their local controls instead.

`DebugSessionDetails` reloads based on the `:name` route parameter, so navigating
between detail URLs in the same browser view always shows the session named in
the current URL.

**Routes:**

- `/debug-sessions` - Browse all debug sessions
- `/debug-sessions/create` - Create a new debug session
- `/debug-sessions/:name` - View session details

**Services:**

- `DebugSessionService` (`services/debugSession.ts`) - API client for all debug session operations including kubectl-debug
- Model types in `model/debugSession.ts`

### 🔄 Future Enhancements

| Feature | Status | Notes |
|---------|--------|-------|
| Terminal sharing (tmux) | ✅ Implemented | Requires tmux-enabled debug image |
| Audit sidecar | CRD fields exist | Implementation deferred - Phase 5 |
| DenyPolicy interaction | ✅ Implemented | Active debug sessions bypass deny policies for pod operations (by design); see [Interaction with Deny Policies](#interaction-with-deny-policies) |
| Tetragon/Falco integration | Documented only | Optional security monitoring |

### Testing Coverage

The following test categories are implemented:

- **Type tests**: All CRD types, field validation, edge cases
- **Reconciler tests**: State transitions, participant management, approvals, renewals
- **API tests**: All endpoints, request/response serialization, permission checks
- **Kubectl-debug tests**: Ephemeral containers, pod copy, node debug operations
- **Bad case tests**: Invalid inputs, unauthorized access, invalid state transitions
- **E2E tests**: Template creation, session lifecycle, multi-participant sessions, kubectl-debug operations
- **Frontend tests**: 478 tests passing (Vitest)
