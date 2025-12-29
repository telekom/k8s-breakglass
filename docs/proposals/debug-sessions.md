# Debug Sessions Feature

## Overview

This proposal introduces a new "Debug Session" concept - a cluster-scoped temporary debugging environment that spawns pre-approved diagnostic tooling (DaemonSets/Deployments) and restricts `pods/exec` access to ONLY those debug pods. This enables controlled debugging workflows (network tracing, tcpdump, strace) without granting broad cluster access.

## Motivation

Current breakglass sessions grant access to existing pods based on RBAC groups. However, debugging often requires:
1. **Specialized tools** not present in application pods (tcpdump, wireshark, netshoot, strace)
2. **Host-level access** for network tracing (but restricted to a controlled debug container)
3. **Collaboration** - multiple team members joining the same debug session
4. **Clean teardown** - debug resources should be automatically removed after use

This feature provides a "sandbox" approach: spawn controlled debug pods, allow exec only to those, auto-cleanup when done.

## Design

### CRD Hierarchy

To enable reusability and reduce maintenance overhead, we introduce a three-tier CRD structure:

```
DebugPodTemplate (reusable pod specs)
    ↓ referenced by
DebugSessionTemplate (session configuration + overrides)
    ↓ instantiates
DebugSession (active session instance)
```

### New CRD: `DebugPodTemplate`

Defines reusable pod specifications that can be shared across multiple DebugSessionTemplates:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugPodTemplate
metadata:
  name: netshoot-base
spec:
  displayName: "Netshoot Debug Container"
  description: "Base template for network debugging with netshoot"
  
  # Pod template (not a full workload controller)
  # This is rendered into DaemonSet/Deployment by DebugSessionTemplate
  template:
    metadata:
      labels:
        breakglass.telekom.com/debug-type: "network"
    spec:
      # Security: pods should be read-only with ephemeral storage only
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      
      containers:
      - name: debug
        image: nicolaka/netshoot@sha256:abc123...  # Use digest for security
        command: ["sleep", "infinity"]
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          capabilities:
            drop: ["ALL"]
            add: ["NET_ADMIN", "NET_RAW"]
        volumeMounts:
        - name: tmp
          mountPath: /tmp
        - name: cache
          mountPath: /var/cache
        resources:
          limits:
            cpu: "500m"
            memory: "256Mi"
          requests:
            cpu: "100m"
            memory: "64Mi"
      
      volumes:
      - name: tmp
        emptyDir:
          sizeLimit: "100Mi"
      - name: cache
        emptyDir:
          sizeLimit: "50Mi"
      
      # No service account token - isolated from cluster
      automountServiceAccountToken: false
      
      # Tolerations for scheduling flexibility
      tolerations: []
      
      # Base affinity (can be extended by DebugSessionTemplate)
      affinity: {}

---
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugPodTemplate
metadata:
  name: strace-base
spec:
  displayName: "Strace Debug Container"
  description: "Base template for syscall tracing"
  
  template:
    spec:
      securityContext:
        runAsNonRoot: false  # strace requires root
      containers:
      - name: debug
        image: alpine:3.19@sha256:def456...
        command: ["sleep", "infinity"]
        securityContext:
          readOnlyRootFilesystem: true
          capabilities:
            drop: ["ALL"]
            add: ["SYS_PTRACE"]
        volumeMounts:
        - name: tmp
          mountPath: /tmp
      volumes:
      - name: tmp
        emptyDir:
          sizeLimit: "100Mi"
      automountServiceAccountToken: false
```

### New CRD: `DebugSessionTemplate`

Defines session configuration and references a DebugPodTemplate:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionTemplate
metadata:
  name: network-trace
spec:
  displayName: "Network Tracing Session"
  description: "Deploy netshoot pods for network diagnostics"
  
  # Reference to reusable pod template
  podTemplateRef:
    name: netshoot-base
  
  # Workload type to create from the pod template
  workloadType: DaemonSet  # or Deployment
  
  # For Deployment workloads
  replicas: 1
  
  # Pod template overrides (merged with base template)
  podOverrides:
    spec:
      # Enable hostNetwork for this specific use case
      hostNetwork: true
      
      # Add host PID for advanced tracing
      hostPID: false
      
      containers:
      - name: debug
        # Override capabilities for this template
        securityContext:
          capabilities:
            add: ["NET_ADMIN", "NET_RAW", "SYS_PTRACE"]
  
  # Affinity overrides - useful for excluding control planes
  affinityOverrides:
    nodeAffinity:
      requiredDuringSchedulingIgnoredDuringExecution:
        nodeSelectorTerms:
        - matchExpressions:
          # Exclude control plane nodes
          - key: node-role.kubernetes.io/control-plane
            operator: DoesNotExist
          - key: node-role.kubernetes.io/master
            operator: DoesNotExist
    podAntiAffinity:
      preferredDuringSchedulingIgnoredDuringExecution:
      - weight: 100
        podAffinityTerm:
          labelSelector:
            matchLabels:
              breakglass.telekom.com/debug-session: "{{.SessionID}}"
          topologyKey: kubernetes.io/hostname
  
  # Additional tolerations for this template
  additionalTolerations:
  - key: "dedicated"
    operator: "Equal"
    value: "debug"
    effect: "NoSchedule"
  
  # Who can request this debug template
  allowed:
    groups: ["sre-team", "network-admins"]
    clusters: ["prod-*", "staging-*"]
  
  # Approvers (optional - if omitted, auto-approved for allowed users)
  approvers:
    groups: ["debug-approvers"]
    # Auto-approve for specific groups (no manual approval needed)
    autoApproveFor:
      groups: ["senior-sre"]
  
  # Session constraints
  constraints:
    maxDuration: "4h"
    defaultDuration: "1h"
    renewalLimit: 3
    maxConcurrentSessions: 2  # Per cluster
  
  # Target namespace (MUST be pre-created by admin)
  targetNamespace: "breakglass-debug"
  
  # Fail mode if namespace doesn't exist or deployment fails
  failMode: "closed"
  
  # Terminal sharing configuration
  terminalSharing:
    enabled: true
    provider: "tmux"  # tmux or screen
    maxParticipants: 5
  
  # Audit configuration
  audit:
    enabled: true
    destinations:
      - type: breakglass
      - type: kubernetes
      - type: webhook
        url: "https://siem.example.com/ingest"
    enableTerminalRecording: true
    recordingRetention: "90d"  # Configurable per template
    enableShellHistory: true
```

### Per-Escalation Pod Security Overrides

Allow `BreakglassEscalation` to relax pod security rules for specific groups:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: sre-production-access
spec:
  groupName: "sre-production"
  duration: "4h"
  
  # ... existing fields ...
  
  # NEW: Pod security overrides for this escalation
  podSecurityOverrides:
    # Allow exec to privileged pods for this escalation
    allowPrivilegedExec: true
    
    # Override risk score threshold (e.g., allow higher risk)
    riskScoreOverride:
      maxAllowedScore: 150  # Override default threshold
    
    # Exempt specific risk factors from blocking
    exemptFactors:
      - privilegedContainer
      - hostNetwork
    
    # Only apply overrides to specific namespaces
    namespaceScope:
      - "kube-system"
      - "monitoring"
    
    # Require additional approval for override usage
    requireApproval: true
    approvers:
      groups: ["security-team"]
```

### New CRD: `DebugSession`

Tracks active debug sessions (analogous to `BreakglassSession`):

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSession
metadata:
  name: debug-abc123
  namespace: breakglass-system
spec:
  cluster: "prod-cluster-1"
  templateRef: "network-trace"
  requestedBy: "user@example.com"
  requestedDuration: "2h"
  reason: "Investigating network latency in payment-service"
  
  # Optional: restrict to specific nodes (merged with template affinity)
  nodeSelector:
    kubernetes.io/hostname: "node-1"
  
  # Optional: additional participants invited at creation
  invitedParticipants:
    - "colleague@example.com"

status:
  state: Active  # Pending, PendingApproval, Active, Expired, Terminated, Failed
  
  # Approval tracking
  approval:
    required: true
    approvedBy: "approver@example.com"
    approvedAt: "2024-01-15T09:58:00Z"
  
  # Session participants (can join/leave)
  participants:
    - user: "user@example.com"
      role: owner
      joinedAt: "2024-01-15T10:00:00Z"
    - user: "colleague@example.com"
      role: participant
      joinedAt: "2024-01-15T10:05:00Z"
  
  # Terminal sharing info (if enabled)
  terminalSharing:
    enabled: true
    sessionName: "debug-abc123-tmux"
    attachCommand: "tmux attach -t debug-abc123-tmux"
  
  # References to deployed resources
  deployedResources:
    - apiVersion: apps/v1
      kind: DaemonSet
      name: debug-abc123-netshoot
      namespace: breakglass-debug
  
  # Pod exec whitelist (dynamically populated from deployed workloads)
  allowedPods:
    - namespace: breakglass-debug
      name: debug-abc123-netshoot-xxxxx
    - namespace: breakglass-debug
      name: debug-abc123-netshoot-yyyyy
  
  startsAt: "2024-01-15T10:00:00Z"
  expiresAt: "2024-01-15T12:00:00Z"
  renewalCount: 0
  
  # Conditions for detailed status
  conditions:
    - type: Ready
      status: "True"
      lastTransitionTime: "2024-01-15T10:00:30Z"
      reason: "DeploymentReady"
      message: "Debug pods are ready"
    - type: PodsScheduled
      status: "True"
      lastTransitionTime: "2024-01-15T10:00:15Z"
```

### Webhook Integration

Modify `pkg/webhook/controller.go` to check for active debug sessions:

```go
// In handleAuthorize, after regular session checks:
if sar.Spec.ResourceAttributes != nil {
    ra := sar.Spec.ResourceAttributes
    if ra.Resource == "pods" && (ra.Subresource == "exec" || ra.Subresource == "attach") {
        // Check if user has an active debug session for this cluster
        debugSessions, err := wc.getActiveDebugSessions(ctx, username, clusterName)
        if err != nil {
            reqLog.Warnw("Failed to check debug sessions", "error", err)
        }
        
        for _, ds := range debugSessions {
            if ds.Status.State == "Active" && isPodInDebugSession(ra.Namespace, ra.Name, ds.Status.AllowedPods) {
                reqLog.Infow("Allowing exec via debug session", 
                    "debugSession", ds.Name, 
                    "pod", ra.Name,
                    "template", ds.Spec.TemplateRef)
                allowed = true
                allowSource = "debug-session"
                allowDetail = fmt.Sprintf("session=%s template=%s", ds.Name, ds.Spec.TemplateRef)
                break
            }
        }
        
        // If trying to exec into non-debug pod while having debug session, deny with helpful message
        if !allowed && len(debugSessions) > 0 {
            reason := fmt.Sprintf("Debug session active but pod %s/%s is not part of the debug deployment. Use pods in namespace %s with label breakglass.telekom.com/debug-session=%s",
                ra.Namespace, ra.Name, "breakglass-debug", debugSessions[0].Name)
            // ... return deny
        }
    }
}
```

### Session Lifecycle Controller

New controller in `pkg/breakglass/debug_session_controller.go`:

```go
type DebugSessionController struct {
    log              *zap.SugaredLogger
    client           ctrlclient.Client
    ccProvider       *cluster.ClientProvider
    templateCache    map[string]*v1alpha1.DebugSessionTemplate
}

// Reconcile handles DebugSession state transitions
func (c *DebugSessionController) Reconcile(ctx context.Context, req ctrl.Request) (ctrl.Result, error) {
    ds := &v1alpha1.DebugSession{}
    if err := c.client.Get(ctx, req.NamespacedName, ds); err != nil {
        return ctrl.Result{}, client.IgnoreNotFound(err)
    }
    
    switch ds.Status.State {
    case "Pending":
        // Check approval, transition to Active
        return c.handlePending(ctx, ds)
    case "Active":
        // Check expiry, update allowed pods list
        return c.handleActive(ctx, ds)
    case "Expired", "Terminated":
        // Cleanup deployed resources
        return c.handleCleanup(ctx, ds)
    }
    return ctrl.Result{}, nil
}

// deployDebugResources creates the DaemonSet/Deployment on target cluster
func (c *DebugSessionController) deployDebugResources(ctx context.Context, ds *v1alpha1.DebugSession) error {
    template, err := c.getTemplate(ctx, ds.Spec.TemplateRef)
    if err != nil {
        return err
    }
    
    // Get target cluster client
    restCfg, err := c.ccProvider.GetRESTConfig(ctx, ds.Spec.Cluster)
    if err != nil {
        return err
    }
    targetClient, err := ctrlclient.New(restCfg, ctrlclient.Options{})
    if err != nil {
        return err
    }
    
    // Render template with session ID
    rendered := c.renderTemplate(template.Spec.Template, map[string]string{
        "SessionID": ds.Name,
        "User":      ds.Spec.RequestedBy,
        "Cluster":   ds.Spec.Cluster,
    })
    
    // Create namespace if needed
    ns := &corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: template.Spec.TargetNamespace}}
    _ = targetClient.Create(ctx, ns) // Ignore if exists
    
    // Deploy the workload
    if err := targetClient.Create(ctx, rendered); err != nil {
        return err
    }
    
    // Update status with deployed resource reference
    ds.Status.DeployedResources = append(ds.Status.DeployedResources, ...)
    return c.client.Status().Update(ctx, ds)
}

// updateAllowedPods watches for pod changes and updates the whitelist
func (c *DebugSessionController) updateAllowedPods(ctx context.Context, ds *v1alpha1.DebugSession) error {
    // List pods with label breakglass.telekom.com/debug-session=<session-id>
    // Update ds.Status.AllowedPods
}

// cleanupResources removes all deployed debug resources
func (c *DebugSessionController) cleanupResources(ctx context.Context, ds *v1alpha1.DebugSession) error {
    restCfg, err := c.ccProvider.GetRESTConfig(ctx, ds.Spec.Cluster)
    if err != nil {
        return err
    }
    targetClient, err := ctrlclient.New(restCfg, ctrlclient.Options{})
    
    for _, ref := range ds.Status.DeployedResources {
        obj := &unstructured.Unstructured{}
        obj.SetAPIVersion(ref.APIVersion)
        obj.SetKind(ref.Kind)
        obj.SetName(ref.Name)
        obj.SetNamespace(ref.Namespace)
        if err := targetClient.Delete(ctx, obj); err != nil && !apierrors.IsNotFound(err) {
            c.log.Warnw("Failed to delete debug resource", "resource", ref, "error", err)
        }
    }
    return nil
}
```

### REST API Endpoints

Add to `pkg/api/` or extend session controller:

```go
// POST /api/debugSessions
// Create new debug session request
type CreateDebugSessionRequest struct {
    Cluster         string `json:"cluster"`
    TemplateRef     string `json:"templateRef"`
    Duration        string `json:"duration,omitempty"`
    Reason          string `json:"reason,omitempty"`
    NodeSelector    map[string]string `json:"nodeSelector,omitempty"`
}

// POST /api/debugSessions/:name/join
// Join existing debug session (for collaboration)
type JoinDebugSessionRequest struct{}

// POST /api/debugSessions/:name/renew
// Extend session duration (within limits)
type RenewDebugSessionRequest struct {
    ExtendBy string `json:"extendBy"` // e.g., "1h"
}

// POST /api/debugSessions/:name/terminate
// Early termination by owner or approver
type TerminateDebugSessionRequest struct {
    Reason string `json:"reason,omitempty"`
}
```

### Frontend Integration

New Vue components in `frontend/src/`:

```
components/
├── DebugSessionList.vue       # List active/past debug sessions
├── DebugSessionRequest.vue    # Request form with template selection
├── DebugSessionDetail.vue     # View session details, participants, pods
└── DebugTemplateSelector.vue  # Browse available debug templates
```

### Cleanup Routine Integration

Extend `pkg/breakglass/cleanup_task.go`:

```go
func (cr CleanupRoutine) clean() {
    // ... existing session cleanup ...
    
    // Debug session cleanup
    cr.cleanupExpiredDebugSessions(context.Background())
}

func (cr CleanupRoutine) cleanupExpiredDebugSessions(ctx context.Context) {
    dsl := v1alpha1.DebugSessionList{}
    if err := cr.Manager.List(ctx, &dsl); err != nil {
        cr.Log.Error("error listing debug sessions", zap.Error(err))
        return
    }
    
    now := time.Now()
    for _, ds := range dsl.Items {
        if ds.Status.State == v1alpha1.DebugSessionStateActive && 
           !ds.Status.ExpiresAt.IsZero() && 
           now.After(ds.Status.ExpiresAt.Time) {
            // Transition to Expired, trigger cleanup
            ds.Status.State = v1alpha1.DebugSessionStateExpired
            if err := cr.Manager.Status().Update(ctx, &ds); err != nil {
                cr.Log.Errorw("Failed to expire debug session", "session", ds.Name, "error", err)
            }
        }
    }
}
```

### Metrics

```go
var (
    DebugSessionsCreated = prometheus.NewCounterVec(
        prometheus.CounterOpts{Name: "breakglass_debug_sessions_created_total"},
        []string{"cluster", "template"},
    )
    DebugSessionsActive = prometheus.NewGaugeVec(
        prometheus.GaugeOpts{Name: "breakglass_debug_sessions_active"},
        []string{"cluster", "template"},
    )
    DebugSessionDuration = prometheus.NewHistogramVec(
        prometheus.HistogramOpts{
            Name:    "breakglass_debug_session_duration_seconds",
            Buckets: []float64{300, 900, 1800, 3600, 7200, 14400},
        },
        []string{"cluster", "template"},
    )
    DebugPodExecAllowed = prometheus.NewCounterVec(
        prometheus.CounterOpts{Name: "breakglass_debug_pod_exec_allowed_total"},
        []string{"cluster", "template", "user"},
    )
)
```

## Security Considerations

1. **Template validation**: DebugSessionTemplates should be admin-controlled CRDs; regular users cannot create their own
2. **Image pinning**: Template images should use digests, not mutable tags
3. **Resource quotas**: Apply resource quotas to debug namespace to prevent abuse
4. **Network policies**: Debug namespace should have NetworkPolicies restricting egress
5. **RBAC isolation**: Debug pods should NOT have service account tokens mounted
6. **Audit trail**: All debug session actions logged with user attribution

## Implementation Phases

### Phase 1: Core CRDs and Controller
- `api/v1alpha1/debug_session_types.go`
- `api/v1alpha1/debug_session_template_types.go`
- `pkg/breakglass/debug_session_controller.go`
- `make generate && make manifests`

### Phase 2: Webhook Integration
- Modify `pkg/webhook/controller.go` for debug session pod whitelisting
- Add `isPodInDebugSession()` helper

### Phase 3: REST API and Frontend
- API endpoints in `pkg/api/debug_session_handler.go`
- Vue components for session management
- Update `docs/api-reference.md`

### Phase 4: Cleanup and Metrics
- Integrate with cleanup routine
- Add Prometheus metrics
- Create Grafana dashboard panels

### Phase 5: Predefined Templates
- Create standard templates: network-trace, strace, kubectl-debug
- Document in `docs/debug-sessions.md`

## Example Use Cases

### 1. Network Tracing Template
```yaml
name: network-trace
template:
  kind: DaemonSet
  spec:
    template:
      spec:
        hostNetwork: true
        containers:
        - name: tcpdump
          image: nicolaka/netshoot@sha256:...
          command: ["sleep", "infinity"]
          securityContext:
            capabilities:
              add: ["NET_ADMIN", "NET_RAW"]
```

### 2. Application Debugging Template
```yaml
name: app-debug
template:
  kind: Deployment
  spec:
    replicas: 1
    template:
      spec:
        containers:
        - name: debug
          image: busybox:stable
          command: ["sleep", "infinity"]
          # Mount app's PVC for log access
          volumeMounts:
          - name: app-logs
            mountPath: /logs
            readOnly: true
```

## Design Decisions

1. **Fail mode**: Configurable per template via `spec.failMode` ("open" or "closed").
2. **Debug namespace**: Pre-created by admin; template specifies `targetNamespace` which must already exist. Controller validates namespace exists before deploying.
3. **Approval workflow**: Configurable per template - set `approvers` for required approval, omit for auto-approval.
4. **Audit logging**: Comprehensive audit trail required (see Audit section below).

## Audit Logging Requirements

Debug sessions require extensive audit logging for compliance and forensics:

### Session-Level Audit Events

```go
// Emitted to breakglass audit log and optionally Kubernetes audit
type DebugSessionAuditEvent struct {
    Timestamp     time.Time         `json:"timestamp"`
    EventType     string            `json:"eventType"`     // created, approved, joined, renewed, terminated, expired
    SessionID     string            `json:"sessionId"`
    Cluster       string            `json:"cluster"`
    Template      string            `json:"template"`
    Actor         string            `json:"actor"`         // user performing action
    Participants  []string          `json:"participants"`  // all users in session
    Reason        string            `json:"reason,omitempty"`
    Metadata      map[string]string `json:"metadata,omitempty"`
}
```

### Exec-Level Audit Events

Every exec/attach to debug pods is logged:

```go
type DebugExecAuditEvent struct {
    Timestamp     time.Time `json:"timestamp"`
    SessionID     string    `json:"sessionId"`
    User          string    `json:"user"`
    Cluster       string    `json:"cluster"`
    PodName       string    `json:"podName"`
    PodNamespace  string    `json:"podNamespace"`
    Container     string    `json:"container"`
    Command       []string  `json:"command,omitempty"`  // if available from SAR
    SourceIP      string    `json:"sourceIP,omitempty"`
}
```

### In-Pod Activity Logging

For comprehensive audit of commands executed within debug pods:

```yaml
# DebugSessionTemplate with audit sidecar
spec:
  template:
    spec:
      containers:
      - name: debug-main
        image: nicolaka/netshoot@sha256:...
        command: ["/bin/bash"]
        # stdin routed through audit wrapper
      
      - name: audit-logger
        image: breakglass-audit-sidecar:latest
        env:
        - name: SESSION_ID
          value: "{{.SessionID}}"
        - name: AUDIT_ENDPOINT
          value: "https://breakglass.example.com/api/audit/ingest"
        volumeMounts:
        - name: shell-history
          mountPath: /audit/history
      
      volumes:
      - name: shell-history
        emptyDir: {}
```

**Alternative approaches for in-pod audit**:

1. **Shell wrapper**: Custom entrypoint that logs all commands to sidecar
2. **eBPF-based**: Deploy eBPF probes to capture execve syscalls (requires privileged)
3. **Audit daemon**: Tetragon or Falco sidecar for syscall-level logging
4. **Session recording**: Use `script` command or asciinema for terminal replay

**Recommended for MVP**: Shell history logging via sidecar + breakglass exec audit events. Full syscall auditing (eBPF/Tetragon) as Phase 2.

### Audit Storage and Export

```yaml
# In DebugSessionTemplate
spec:
  audit:
    # Where to send audit events
    destinations:
      - type: breakglass          # Built-in breakglass audit log
      - type: kubernetes          # Kubernetes audit log via events
      - type: webhook             # External webhook endpoint
        url: "https://siem.example.com/ingest"
        headers:
          Authorization: "Bearer {{.AuditToken}}"
    
    # Retention for session recordings
    recordingRetention: "90d"
    
    # Enable terminal session recording (asciinema format)
    enableTerminalRecording: true
```

## Design Decisions (Resolved)

1. **Cross-namespace access**: ❌ **No** - Debug pods should NOT access app namespaces. They are isolated to the debug namespace with no ConfigMap/Secret mounts from other namespaces.

2. **Persistent storage**: ❌ **No** - Pods should be read-only with ephemeral volumes only (emptyDir). This ensures:
   - No data persistence between sessions (security)
   - Clean state on each renewal
   - Reduced attack surface

3. **Terminal sharing**: ✅ **Yes** - Integrated via tmux/screen for real-time collaboration. Configurable per template via `terminalSharing.enabled` and `terminalSharing.provider`.

4. **Audit retention**: ✅ **Configurable** - Each `DebugSessionTemplate` can specify `audit.recordingRetention` (e.g., "90d", "1y"). Default: 90 days.

5. **Syscall auditing**: 📖 **Documentation only** - Tetragon/Falco integration is documented but left to cluster admins. We provide:
   - Example configurations in docs
   - Guidance on sidecar injection
   - Recommended policies for debug namespaces

6. **Per-escalation overrides**: ✅ **Yes** - `BreakglassEscalation` can specify `podSecurityOverrides` to relax pod security rules for specific groups (e.g., SRE escalation allows exec to privileged pods).

7. **Reusable pod templates**: ✅ **Yes** - Introduced `DebugPodTemplate` CRD that can be referenced by multiple `DebugSessionTemplate` resources. Reduces duplication and maintenance overhead.

8. **Affinity/Anti-affinity**: ✅ **Yes** - `DebugSessionTemplate` supports:
   - `affinityOverrides` to add node/pod affinity rules
   - `additionalTolerations` for scheduling flexibility
   - Example: exclude control plane nodes via nodeAffinity

## Syscall Auditing with Tetragon/Falco

For cluster admins who need syscall-level auditing, we recommend integrating with Tetragon or Falco. This section provides guidance.

### Tetragon Configuration

Deploy Tetragon with a policy targeting the debug namespace:

```yaml
apiVersion: cilium.io/v1alpha1
kind: TracingPolicy
metadata:
  name: debug-session-audit
spec:
  kprobes:
  - call: "sys_execve"
    syscall: true
    selectors:
    - matchNamespaces:
      - namespace: breakglass-debug
        operator: In
    - matchLabels:
      - key: breakglass.telekom.com/debug-session
        operator: Exists
    args:
    - index: 0
      type: "string"
```

### Falco Rules

```yaml
- rule: Debug Session Command Execution
  desc: Log all commands executed in debug session pods
  condition: >
    spawned_process and
    container and
    k8s.ns.name = "breakglass-debug" and
    k8s.pod.label.breakglass.telekom.com/debug-session exists
  output: >
    Debug session command (user=%user.name command=%proc.cmdline
    pod=%k8s.pod.name session=%k8s.pod.label.breakglass.telekom.com/debug-session)
  priority: NOTICE
  tags: [debug-session, audit]
```

### Integration with Audit Sidecar

For templates requiring in-pod audit, include an audit sidecar:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugPodTemplate
metadata:
  name: audited-debug
spec:
  template:
    spec:
      containers:
      - name: debug
        image: nicolaka/netshoot@sha256:...
        command: ["/audit/shell-wrapper.sh"]  # Wrapper that logs commands
        volumeMounts:
        - name: audit-fifo
          mountPath: /audit
      
      - name: audit-logger
        image: ghcr.io/telekom/breakglass-audit-sidecar:v1
        env:
        - name: SESSION_ID
          valueFrom:
            fieldRef:
              fieldPath: metadata.labels['breakglass.telekom.com/debug-session']
        - name: AUDIT_ENDPOINT
          value: "https://breakglass.example.com/api/audit/ingest"
        volumeMounts:
        - name: audit-fifo
          mountPath: /audit
      
      volumes:
      - name: audit-fifo
        emptyDir: {}
```

## Kubectl Debug Integration

### Overview

In addition to pre-deployed debug pods (DaemonSet/Deployment), this proposal supports **kubectl debug** workflows for ephemeral container debugging. This allows users to attach debug containers directly to existing workloads or nodes without modifying the original deployment.

### Use Cases

1. **Ephemeral container debugging**: Inject a debug container into a running pod to inspect it without modifying the pod spec
2. **Node debugging**: Create debug pods that share a node's namespaces (network, PID, IPC)
3. **Pod copy debugging**: Create a copy of a failing pod with debug tooling added

### Kubectl Debug Subresources

Kubectl debug operations translate to these Kubernetes API calls:

| kubectl command | API Resource | Subresource |
|-----------------|--------------|-------------|
| `kubectl debug pod/<name> -it --image=...` | pods | ephemeralcontainers |
| `kubectl debug node/<name> -it --image=...` | nodes | proxy (creates pod) |
| `kubectl debug pod/<name> --copy-to=...` | pods | - (creates new pod) |

### DebugSessionTemplate Extensions for Kubectl Debug

Extend the `DebugSessionTemplate` CRD to support kubectl debug workflows:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionTemplate
metadata:
  name: kubectl-debug-ephemeral
spec:
  displayName: "Kubectl Debug (Ephemeral Containers)"
  description: "Allow injecting ephemeral debug containers into pods"
  
  # New: kubectl debug mode (instead of deploying workloads)
  mode: kubectl-debug
  
  # Configure allowed kubectl debug operations
  kubectlDebug:
    # Allow ephemeral container injection
    ephemeralContainers:
      enabled: true
      # Restrict which namespaces users can debug pods in
      allowedNamespaces:
        - "app-*"
        - "staging-*"
      # Block debugging in sensitive namespaces
      deniedNamespaces:
        - "kube-system"
        - "breakglass-system"
      # Restrict ephemeral container images
      allowedImages:
        - "nicolaka/netshoot@sha256:*"
        - "busybox:stable"
        - "alpine:3.*"
        - "ghcr.io/telekom/debug-tools:*"
      # Require image digests (no mutable tags)
      requireImageDigest: false
      # Maximum capabilities allowed for ephemeral containers
      maxCapabilities: ["NET_ADMIN", "NET_RAW", "SYS_PTRACE"]
      # Disallow privileged ephemeral containers
      allowPrivileged: false
      # Require ephemeral container runs as non-root
      requireNonRoot: true
    
    # Allow node debugging (creates privileged pod on node)
    nodeDebug:
      enabled: false  # Disabled by default (high privilege)
      # If enabled:
      allowedImages:
        - "ghcr.io/telekom/node-debug:v1"
      hostNamespaces:
        hostNetwork: true
        hostPID: true
        hostIPC: false
      # Restrict to specific nodes
      nodeSelector:
        node-role.kubernetes.io/worker: ""
    
    # Allow pod copy (creates modified copy of pod)
    podCopy:
      enabled: true
      # Namespace for copied pods
      targetNamespace: "debug-copies"
      # Labels to add to copied pods
      labels:
        breakglass.telekom.com/debug-copy: "true"
      # Timeout for copied pods (auto-delete)
      ttl: "2h"
  
  # Who can request this debug template
  allowed:
    groups: ["developers", "sre-team"]
    clusters: ["dev-*", "staging-*"]
  
  # Approvers (required for ephemeral containers in prod)
  approvers:
    groups: ["platform-team"]
    autoApproveFor:
      clusters: ["dev-*"]  # Auto-approve in dev clusters
  
  # Session constraints
  constraints:
    maxDuration: "2h"
    defaultDuration: "30m"
```

### Webhook Integration for Ephemeral Containers

The authorization webhook evaluates ephemeral container operations:

```go
// In handleAuthorize, for ephemeral container operations:
if ra.Resource == "pods" && ra.Subresource == "ephemeralcontainers" {
    // Check if user has a debug session with kubectl-debug permissions
    debugSessions, err := wc.getActiveDebugSessions(ctx, username, clusterName)
    if err != nil {
        reqLog.Warnw("Failed to check debug sessions", "error", err)
    }
    
    for _, ds := range debugSessions {
        template := ds.Status.ResolvedTemplate
        if template == nil || template.Spec.Mode != "kubectl-debug" {
            continue
        }
        
        kd := template.Spec.KubectlDebug
        if kd == nil || kd.EphemeralContainers == nil || !kd.EphemeralContainers.Enabled {
            continue
        }
        
        // Check namespace allowed
        if !isNamespaceAllowed(ra.Namespace, kd.EphemeralContainers.AllowedNamespaces, 
                                kd.EphemeralContainers.DeniedNamespaces) {
            continue
        }
        
        // Additional validation happens in admission webhook
        reqLog.Infow("Allowing ephemeral container via debug session",
            "debugSession", ds.Name,
            "pod", ra.Name,
            "namespace", ra.Namespace)
        allowed = true
        allowSource = "debug-session"
        allowDetail = fmt.Sprintf("session=%s template=%s mode=kubectl-debug", 
                                  ds.Name, template.Name)
        break
    }
}
```

### Admission Webhook for Image/Capability Validation

A separate validating admission webhook enforces image and security constraints:

```go
// ValidatingWebhookConfiguration for ephemeral containers
// Triggers on: pods/ephemeralcontainers PATCH requests

func (wh *DebugAdmissionWebhook) ValidateEphemeralContainer(ctx context.Context, 
    req admission.Request) admission.Response {
    
    pod := &corev1.Pod{}
    if err := wh.decoder.Decode(req, pod); err != nil {
        return admission.Errored(http.StatusBadRequest, err)
    }
    
    // Find the new ephemeral container
    newContainer := findNewEphemeralContainer(req.OldObject, pod)
    if newContainer == nil {
        return admission.Allowed("no new ephemeral container")
    }
    
    // Get user's active debug session
    ds, err := wh.getDebugSessionForUser(ctx, req.UserInfo.Username, req.Namespace)
    if err != nil || ds == nil {
        return admission.Denied("no active debug session for ephemeral containers")
    }
    
    template := ds.Status.ResolvedTemplate
    ec := template.Spec.KubectlDebug.EphemeralContainers
    
    // Validate image
    if !imageAllowed(newContainer.Image, ec.AllowedImages) {
        return admission.Denied(fmt.Sprintf("image %s not in allowed list", newContainer.Image))
    }
    
    // Validate image digest if required
    if ec.RequireImageDigest && !hasImageDigest(newContainer.Image) {
        return admission.Denied("ephemeral container images must use @sha256: digest")
    }
    
    // Validate capabilities
    if newContainer.SecurityContext != nil && 
       newContainer.SecurityContext.Capabilities != nil {
        for _, cap := range newContainer.SecurityContext.Capabilities.Add {
            if !contains(ec.MaxCapabilities, string(cap)) {
                return admission.Denied(fmt.Sprintf("capability %s not allowed", cap))
            }
        }
    }
    
    // Validate non-root if required
    if ec.RequireNonRoot {
        sc := newContainer.SecurityContext
        if sc == nil || sc.RunAsNonRoot == nil || !*sc.RunAsNonRoot {
            return admission.Denied("ephemeral container must run as non-root")
        }
    }
    
    return admission.Allowed("ephemeral container validated")
}
```

### DenyPolicy Integration

Extend `PodSecurityRules` to handle ephemeral container requests:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DenyPolicy
metadata:
  name: ephemeral-container-restrictions
spec:
  podSecurityRules:
    appliesTo:
      subresources: ["exec", "attach", "portforward", "ephemeralcontainers"]
    
    # Evaluate the TARGET pod's security posture
    # (same logic as exec - if pod is risky, deny ephemeral container injection)
    riskFactors:
      hostNetwork: 20
      hostPID: 25
      privilegedContainer: 50
    thresholds:
      - maxScore: 50
        action: warn
      - maxScore: 100
        action: deny
        reason: "Cannot inject ephemeral container into high-risk pod"
    
    # Block ephemeral containers in specific namespaces
    exemptions:
      namespaces: []  # No exemptions
```

### DebugSession Status for Kubectl Debug Mode

For kubectl-debug mode sessions, the status tracks allowed operations instead of deployed pods:

```yaml
status:
  state: Active
  
  # For kubectl-debug mode
  kubectlDebugStatus:
    ephemeralContainersInjected:
      - podName: payment-service-abc123
        namespace: payments
        containerName: debugger-1
        image: nicolaka/netshoot@sha256:...
        injectedAt: "2024-01-15T10:05:00Z"
        injectedBy: "user@example.com"
    
    copiedPods:
      - originalPod: frontend-xyz789
        originalNamespace: web
        copyName: debug-copy-frontend-xyz789
        copyNamespace: debug-copies
        createdAt: "2024-01-15T10:10:00Z"
        expiresAt: "2024-01-15T12:10:00Z"
  
  startsAt: "2024-01-15T10:00:00Z"
  expiresAt: "2024-01-15T12:00:00Z"
```

### Example: Combined Debug Template

A template that allows both pre-deployed debug pods AND kubectl debug:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionTemplate
metadata:
  name: comprehensive-debug
spec:
  displayName: "Comprehensive Debug Access"
  description: "Pre-deployed network tools + ephemeral container injection"
  
  # Mode can be: "workload" (deploy pods), "kubectl-debug", or "hybrid"
  mode: hybrid
  
  # Pre-deployed debug pods (workload mode)
  podTemplateRef:
    name: netshoot-base
  workloadType: DaemonSet
  targetNamespace: breakglass-debug
  
  # Kubectl debug options (kubectl-debug mode)
  kubectlDebug:
    ephemeralContainers:
      enabled: true
      allowedNamespaces: ["*"]
      deniedNamespaces: ["kube-system", "breakglass-system"]
      allowedImages:
        - "nicolaka/netshoot@sha256:*"
        - "busybox:stable"
      maxCapabilities: ["NET_ADMIN", "NET_RAW"]
    podCopy:
      enabled: true
      targetNamespace: debug-copies
      ttl: "1h"
  
  # Access control
  allowed:
    groups: ["sre-team"]
    clusters: ["*"]
  approvers:
    groups: ["security-team"]
    autoApproveFor:
      groups: ["senior-sre"]
  
  constraints:
    maxDuration: "4h"
    defaultDuration: "1h"
```

### Security Considerations for Kubectl Debug

1. **Image allowlisting**: Only permit trusted debug images to prevent supply chain attacks
2. **Namespace restrictions**: Block ephemeral containers in system namespaces
3. **Capability limits**: Restrict Linux capabilities available to ephemeral containers
4. **Audit logging**: Log all ephemeral container injections with user attribution
5. **TTL for copied pods**: Auto-delete pod copies to prevent resource sprawl
6. **No persistent state**: Ephemeral containers cannot add volumes

## Implementation Status

### Implemented (Pod Security Classification)

The following features from the pod security proposal are **implemented and tested**:

| Feature | Status | Location |
|---------|--------|----------|
| `PodSecurityRules` in DenyPolicy | ✅ Implemented | `api/v1alpha1/deny_policy_types.go` |
| Risk factor scoring | ✅ Implemented | `pkg/policy/pod_security.go` |
| Block factors (immediate deny) | ✅ Implemented | `pkg/policy/pod_security.go` |
| Threshold-based actions | ✅ Implemented | `pkg/policy/pod_security.go` |
| Namespace/label exemptions | ✅ Implemented | `pkg/policy/pod_security.go` |
| Fail mode (open/closed) | ✅ Implemented | `pkg/webhook/controller.go` |
| Pod fetch injection for tests | ✅ Implemented | `pkg/webhook/controller.go` |
| Unit tests (94.9% coverage) | ✅ Implemented | `pkg/policy/pod_security_test.go` |
| E2E tests for SAR flows | ✅ Implemented | `pkg/api/api_end_to_end_test.go` |
| Documentation | ✅ Implemented | `docs/deny-policy.md` |

### Implemented (Escalation Overrides)

| Feature | Status | Location |
|---------|--------|----------|
| `PodSecurityOverrides` type | ✅ Implemented | `api/v1alpha1/breakglass_escalation_types.go` |
| Override in Action struct | ⏳ Partial | Type exists, webhook wiring pending |

### Not Yet Implemented (Debug Sessions)

| Feature | Status | Priority |
|---------|--------|----------|
| `DebugPodTemplate` CRD | ❌ Not started | Phase 1 |
| `DebugSessionTemplate` CRD | ❌ Not started | Phase 1 |
| `DebugSession` CRD | ❌ Not started | Phase 1 |
| Debug session controller | ❌ Not started | Phase 1 |
| Webhook pod whitelisting | ❌ Not started | Phase 2 |
| REST API endpoints | ❌ Not started | Phase 3 |
| Frontend components | ❌ Not started | Phase 3 |
| Kubectl debug support | ❌ Not started | Phase 4 |
| Terminal sharing (tmux) | ❌ Not started | Phase 5 |
| Audit sidecar | ❌ Not started | Phase 5 |

