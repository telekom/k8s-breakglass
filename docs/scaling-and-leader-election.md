# Scaling and Leader Election in Breakglass

## Overview

This document explains how breakglass controller scales horizontally with multiple replicas using Kubernetes-native leader election to prevent duplicate work in background loops.

**Status**: ✅ Leader election is now **fully implemented** (as of v1.x)

## Background Components

The breakglass controller runs several background loops in goroutines that require proper coordination:

### 1. **CleanupRoutine** (Session Lifecycle Management) ✅ LEADER ELECTION ENABLED

- **Purpose**: Marks expired sessions for deletion, activates scheduled sessions, expires pending sessions
- **Location**: `pkg/breakglass/cleanup_task.go:CleanupRoutine()`
- **Interval**: 5 minutes (hardcoded `CleanupInterval`)
- **Startup**: Launched as goroutine if `--enable-cleanup=true`
- **Shared State**: Directly modifies BreakglassSession resources (via SessionManager)
- **Concurrency Handling**: ✅ **SAFE** - Only runs on leader replica (waits for `LeaderElected` signal)
- **Status**: Leader election properly implemented

### 2. **EscalationStatusUpdater** (Keycloak Group Sync) ✅ LEADER ELECTION ENABLED

- **Purpose**: Periodically resolves approver groups from Keycloak and updates BreakglassEscalation.Status.ApproverGroupMembers
- **Location**: `pkg/breakglass/escalation_status_updater.go:Start()`
- **Interval**: 10 minutes (configurable via `--escalation-status-update-interval`)
- **Startup**: Always launched
- **Shared State**: Updates BreakglassEscalation.Status with resolved group members
- **Concurrency Handling**: ✅ **SAFE** - Only runs on leader replica (waits for `LeaderElected` signal)
- **Uses Keycloak Cache**: Internal `kcCache` with `sync.RWMutex` (thread-safe)
- **Status**: Leader election properly implemented

### 3. **ClusterConfigChecker** (Validation Loop) ✅ LEADER ELECTION ENABLED

- **Purpose**: Validates ClusterConfig resources, verifies kubeconfig secrets exist and are readable
- **Location**: `pkg/breakglass/cluster_config_checker.go:Start()`
- **Interval**: 10 minutes (configurable via `--cluster-config-check-interval`)
- **Startup**: Always launched
- **Shared State**: Updates ClusterConfig.Status with validation results, emits Kubernetes events
- **Concurrency Handling**: ✅ **SAFE** - Only runs on leader replica (waits for `LeaderElected` signal)
- **Status**: Leader election properly implemented

### 4. **IdentityProvider Reconciler** (Config Watcher) ✅ ALWAYS RUNNING

- **Purpose**: Watches for changes to IdentityProvider CR and reloads configuration
- **Location**: `pkg/config/identity_provider_reconciler.go:SetupWithManager()`
- **Pattern**: Kubernetes controller-runtime reconciler (event-driven, not polling)
- **Concurrency Handling**: ✅ **SAFE** - Runs on all replicas
  - controller-runtime handles work queue deduplication
  - Event-driven (doesn't poll)
  - No shared state modified

### 5. **Validating Webhooks** ✅ ALWAYS RUNNING

- **Purpose**: Validates breakglass CRDs on create/update
- **Paths**: Fixed in v1.x to match controller-runtime generated paths:
  - `/validate-breakglass-t-caas-telekom-com-v1alpha1-breakglasssession`
  - `/validate-breakglass-t-caas-telekom-com-v1alpha1-breakglassescalation`
  - `/validate-breakglass-t-caas-telekom-com-v1alpha1-clusterconfig`
  - `/validate-breakglass-t-caas-telekom-com-v1alpha1-identityprovider`
- **Concurrency Handling**: ✅ **SAFE** - Stateless request handlers, run on all replicas
- **Status**: Fixed to use correct webhook paths

## Leader Election Implementation

### How It Works

The breakglass controller uses **Kubernetes Lease-based leader election** via `k8s.io/client-go/tools/leaderelection`:

```text
Multiple Replicas
    ↓
Compete for Lease (coordination.k8s.io/leases)
    ↓
ONE replica acquires lease → OnStartedLeading callback
    ↓
Signal background loops via leaderElectedCh
    ↓
Background loops (CleanupRoutine, EscalationStatusUpdater, 
ClusterConfigChecker) BEGIN execution
    ↓
Leader continuously renews lease
    ↓
If leader dies → Non-leader acquires lease
    ↓
New leader takes over (all loops resume)
```

### Configuration

#### 1. Enable/Disable Leader Election

```bash
# Enable leader election (default - recommended for multi-replica)
breakglass-controller --enable-leader-election=true

# Disable leader election (single-instance deployments)
breakglass-controller --enable-leader-election=false
```

**Environment Variable:**
```bash
ENABLE_LEADER_ELECTION=true breakglass-controller
```

#### 2. Configure Lease Namespace

```bash
# Lease in controller namespace (default)
breakglass-controller --leader-elect-namespace=breakglass-system

# Lease in custom namespace
breakglass-controller --leader-elect-namespace=my-namespace
```

**Environment Variable:**
```bash
LEADER_ELECT_NAMESPACE=breakglass-system breakglass-controller
```

#### 3. Configure Lease ID

```bash
# Custom lease name (default: breakglass.telekom.io)
breakglass-controller --leader-elect-id=my-lease-id
```

**Environment Variable:**
```bash
LEADER_ELECT_ID=my-lease-id breakglass-controller
```

### Lease Timings

The LeaderElector uses these tunable parameters (currently hardcoded, can be made configurable):

- **LeaseDuration**: 15 seconds (how long the lease is held)
- **RenewDeadline**: 10 seconds (deadline for renewing before losing leadership)
- **RetryPeriod**: 2 seconds (wait between election attempts)

These defaults provide a good balance between responsiveness and stability. The leader must renew every 10 seconds or it loses leadership; other replicas check every 2 seconds.

## Concurrency Analysis

### Components with Leader Election

| Component | Safeguard | Impact |
|-----------|-----------|--------|
| CleanupRoutine | Only runs on leader | ✅ No duplicate session deletions |
| EscalationStatusUpdater | Only runs on leader | ✅ No redundant Keycloak queries |
| ClusterConfigChecker | Only runs on leader | ✅ No duplicate validation events |

### Safe Components (No Leader Election Needed)

✅ **IdentityProvider Reconciler** - Event-driven, work queue handles deduplication
✅ **Session/Escalation REST API** - Stateless, scales horizontally
✅ **Frontend/UI** - Stateless, served by HTTP server
✅ **SAR Webhook** - Stateless request handler
✅ **Validating Webhooks** - Stateless validation logic  --enable-api=true \
  --enable-cleanup=true \
  --enable-webhooks=true
```

✅ Safe for single instance, doesn't scale

### Pattern 2: Multiple Replicas - API Only (Currently Safe)

```bash
# Replica 1
breakglass-controller \
  --enable-frontend=true \
  --enable-api=true \
  --enable-cleanup=false \
  --enable-webhooks=false

# Replica 2, 3, ...
breakglass-controller \
  --enable-frontend=true \
  --enable-api=true \
  --enable-cleanup=false \
  --enable-webhooks=false
```

✅ Stateless endpoints scale horizontally

### Pattern 3: Multiple Replicas - All Components (UNSAFE - NEEDS FIX)

```bash
breakglass-controller \
  --enable-frontend=true \
  --enable-api=true \
  --enable-cleanup=true \
  --enable-webhooks=true
```

❌ Race conditions in cleanup + update loops

### Pattern 4: Multiple Replicas - With Leader Election (✅ IMPLEMENTED)

```bash
breakglass-controller \
  --enable-frontend=true \
  --enable-api=true \
  --enable-cleanup=true \
  --enable-webhooks=true \
  --enable-leader-election=true
```

✅ Safe with leader election enabled:

- **Leader runs**: CleanupRoutine, EscalationStatusUpdater, ClusterConfigChecker
- **All replicas run**: API, Frontend, SAR Webhook, IdentityProvider Reconciler
- **Automatic failover**: When leader crashes, new leader elected within 15 seconds
- **No duplicate work**: Lease-based coordination prevents concurrent execution

## Implemented Solution: Leader Election for All Background Loops

### Implementation Approach

The leader election is now fully implemented using Kubernetes-native Lease objects:

1. **Kubernetes-native Lease coordination**
   - Uses `k8s.io/client-go/tools/leaderelection.LeaderElector`
   - Stores lease in `breakglass-system` namespace
   - Lease name: `breakglass.telekom.io`

2. **Three background loops use leadership signals**
   - **CleanupRoutine**: Only active on leader, deletes expired sessions
   - **EscalationStatusUpdater**: Only active on leader, syncs group membership with Keycloak
   - **ClusterConfigChecker**: Only active on leader, validates cluster configurations
   - Each loop blocks until leadership is acquired

3. **Key benefits of this implementation**
   - ✅ Single source of truth for leadership (shared Kubernetes Lease)
   - ✅ Leverages existing controller-runtime infrastructure
   - ✅ Graceful failover (new leader elected within 15 seconds)
   - ✅ No external dependencies (uses only Kubernetes API)
   - ✅ Simple to debug and reason about
   - ✅ No race conditions in background operations

### Architecture Changes

```text
┌──────────────────────────────────────────────────┐
│  breakglass controller (multiple replicas)        │
├──────────────────────────────────────────────────┤
│                                                  │
│  Kubernetes Lease-Based Leader Election         │
│  ├─ LeaderElector: k8s.io/client-go/tools      │
│  ├─ Lease: breakglass.telekom.io               │
│  ├─ Namespace: breakglass-system               │
│  └─ Leader Signal (channel)                    │
│                                                  │
│  Listeners (only run on leader):                 │
│  ├─ CleanupRoutine (session cleanup)            │
│  ├─ EscalationStatusUpdater (group sync)        │
│  └─ ClusterConfigChecker (validation)           │
│                                                  │
│  Always Running (all replicas):                  │
│  ├─ HTTP API/Frontend (port 8080)               │
│  ├─ SAR Webhook (port 8080)                     │
│  ├─ Validating Webhooks (port 9443)             │
│  └─ IdentityProvider Reconciler                 │
│                                                  │
│  Configuration:                                  │
│  ├─ --enable-leader-election (default: true)   │
│  └─ ENABLE_LEADER_ELECTION=true/false           │
│                                                  │
└──────────────────────────────────────────────────┘
```

### Implementation Details

#### 1. LeaderElector Lifecycle

The LeaderElector is initialized in `cmd/main.go` with these phases:

```
1. Create ResourceLock (Kubernetes Lease object)
   └─> If lease doesn't exist, Kubernetes creates it automatically

2. Create LeaderElector with callbacks
   ├─ OnStartedLeading: Close leaderElectedCh (signal leadership)
   ├─ OnStoppedLeading: Log warning (leadership lost)
   └─ OnNewLeader: Log info (replica became leader)

3. Run LeaderElector
   ├─ Acquire lease (blocks if another replica is leader)
   ├─ Renew lease every 10 seconds while leader
   ├─ Release lease on shutdown
   └─ Retry every 2 seconds if not leader
```

#### 2. LeaderElector Configuration

```go
elector, err := leaderelection.NewLeaderElector(leaderelection.LeaderElectionConfig{
    Lock: resourceLock,
    
    // Lease durations
    LeaseDuration: 15 * time.Second,  // Lease valid for 15s after last renewal
    RenewDeadline: 10 * time.Second,  // Must renew within 10s or lose leadership
    RetryPeriod:   2 * time.Second,   // Check every 2s if can become leader
    
    // Callbacks
    Callbacks: leaderelection.LeaderCallbacks{
        OnStartedLeading: func(ctx context.Context) {
            log.Infow("breakglass controller is now the leader")
            close(leaderElectedCh)  // Signal all listeners
        },
        OnStoppedLeading: func() {
            log.Warnw("breakglass controller lost leader status")
        },
        OnNewLeader: func(identity string) {
            if identity == os.Getenv("HOSTNAME") {
                log.Infow("breakglass controller became the leader", "leader", identity)
            }
        },
    },
    Name:      "breakglass-controller",
})
```

#### 3. Background Loops Wait for Leadership

Each background loop blocks until `leaderElectedCh` is closed:

```go
// In CleanupRoutine
<-leaderElectedCh  // Block until leadership acquired

// In EscalationStatusUpdater  
<-leaderElectedCh  // Block until leadership acquired

// In ClusterConfigChecker
<-leaderElectedCh  // Block until leadership acquired
```

Once the channel is closed, the loop proceeds normally. The same loop continues running (doesn't restart), just now performing actual work instead of idling.

#### 4. Disabling Leader Election

When `--enable-leader-election=false`:

```go
if enableLeaderElection {
    go elector.Run(ctx)
} else {
    close(leaderElectedCh)  // Immediately signal all replicas are "leaders"
}
```

All replicas immediately get the leadership signal, so all background loops run concurrently. Use this mode for single-instance deployments or testing.

#### 5. RBAC Requirements for Leader Election

The controller needs permissions to manage leases:

```yaml
rules:
- apiGroups: ["coordination.k8s.io"]
  resources: ["leases"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
- apiGroups: [""]
  resources: ["events"]
  verbs: ["create", "patch"]
```

These permissions allow the controller to:
- **Get/List/Watch leases**: Check current leader
- **Create/Update/Patch leases**: Acquire/renew leadership
- **Delete leases**: Release leadership on shutdown
- **Create/Patch events**: Record leadership transitions

See `config/rbac/role.yaml` for full RBAC configuration.

## Testing Strategy

### Verification Checklist

Before deploying to production with multiple replicas:

- [ ] Single instance deployment works with `--enable-leader-election=true`
- [ ] Single instance deployment works with `--enable-leader-election=false`
- [ ] Multi-replica deployment elects a leader (check logs for "is now the leader")
- [ ] Cleanup operations run on leader only (check logs for "Running breakglass session cleanup task")
- [ ] Group status updates run on leader only (check logs for "Checking group membership")
- [ ] Config validation runs on leader only (check logs for "Checking cluster config")
- [ ] API endpoints work on all replicas (test REST API on each pod)
- [ ] Leader election works across pod restarts (delete leader pod, verify new leader elected)
- [ ] Webhook validation works on all replicas (test via kubectl)

### Manual Testing Commands

```bash
# Check lease status
kubectl get lease -n breakglass-system breakglass.telekom.io -w

# Watch leader transitions
kubectl logs -n breakglass-system -l app=breakglass-controller -f | grep -i leader

# Check which replica is leader
kubectl logs -n breakglass-system -l app=breakglass-controller -f | grep "is now the leader"

# Verify cleanup runs on leader
kubectl logs -n breakglass-system -l app=breakglass-controller -f | grep "Running breakglass session cleanup"

# Delete leader pod to test failover
kubectl delete pod -n breakglass-system breakglass-controller-0
# Watch for new leader election within ~15 seconds
```

### Unit Test Examples

```go
func TestCleanupRoutineWaitsForLeadership(t *testing.T) {
    leaderElectedCh := make(chan struct{})
    routine := &CleanupRoutine{LeaderElected: leaderElectedCh}
    
    // Start routine (should block)
    done := make(chan bool)
    go func() {
        routine.CleanupRoutine()
        done <- true
    }()
    
    // Verify routine hasn't started cleanup yet
    select {
    case <-done:
        t.Fatal("CleanupRoutine started without leadership signal")
    case <-time.After(100 * time.Millisecond):
        // Good - routine is blocked
    }
    
    // Signal leadership
    close(leaderElectedCh)
    
    // Verify routine now proceeds
    select {
    case <-done:
        // Good - routine proceeded after signal
    case <-time.After(1 * time.Second):
        t.Fatal("CleanupRoutine did not proceed after leadership signal")
    }
}
```

## Migration Path

### For New Deployments

1. Deploy single replica with `--enable-leader-election=true` (default)
2. Leader election works automatically - no additional configuration needed
3. When ready to scale, add more replicas and increase resource requests
4. All replicas will participate in leader election automatically

### For Existing Single-Replica Deployments

**No action required!**

- Existing deployments continue to work
- `--enable-leader-election` defaults to `true`
- Single replica automatically becomes leader
- When scaled to multiple replicas, leader election engages automatically

### For Existing Multi-Replica Deployments (Race Condition Risk)

If you're currently running multiple replicas:

1. **Verify current behavior**: Check if background loops are running on all replicas
   ```bash
   kubectl logs -n breakglass-system -l app=breakglass-controller | grep "Running breakglass session cleanup"
   ```

2. **Option A: Enable Leader Election (Recommended)**
   - Update deployment to set `--enable-leader-election=true` (default)
   - Redeploy: `kubectl rollout restart deployment/breakglass-controller`
   - Monitor logs for leader election
   - Cleanup operations now run on leader only

3. **Option B: Keep Old Behavior (Short-term)**
   - Set `--enable-leader-election=false` to disable leader election
   - All replicas run background loops (original behavior)
   - Not recommended for long-term due to duplicate work and potential races

### Troubleshooting Migration

**Symptom**: Background loops not running after enabling leader election

```bash
# Check if lease was created
kubectl get lease -n breakglass-system breakglass.telekom.io

# Check controller logs for leadership
kubectl logs -n breakglass-system -l app=breakglass-controller | grep -i leader

# Verify RBAC allows lease operations
kubectl auth can-i get leases --as=system:serviceaccount:breakglass-system:breakglass-controller -n breakglass-system
```

**Symptom**: Multiple replicas showing "is now the leader"

This should not happen - only one replica can hold the lease at a time. If you see this:
- Check clock skew between nodes: `kubectl get nodes -o wide`
- Verify lease duration settings in logs
- Check for network connectivity issues between pods

## Troubleshooting & FAQ

### Why aren't cleanup operations running?

**Checklist**:
1. Verify leader election is enabled: `--enable-leader-election=true` (check logs)
2. Verify controller is leader: `kubectl logs -n breakglass-system -l app=breakglass-controller | grep "is now the leader"`
3. Verify RBAC has lease permissions: `kubectl auth can-i get leases --as=system:serviceaccount:breakglass-system:breakglass-controller`
4. Check lease exists: `kubectl get lease -n breakglass-system breakglass.telekom.io`

### Can I disable leader election?

Yes, for single-instance deployments or testing:

```bash
# Via flag
breakglass-controller --enable-leader-election=false

# Via environment variable
export ENABLE_LEADER_ELECTION=false
breakglass-controller
```

**Note**: Only safe for single instance. Multiple replicas with leader election disabled causes duplicate work and race conditions.

### How long does failover take?

With default settings:
- Lease duration: 15 seconds
- Max time to detect leader loss: 15 seconds
- New leader acquires lease within 2-10 seconds

**Total**: Up to ~25-30 seconds from leader crash to new leader taking over. Tune `LeaseDuration` and `RenewDeadline` in `cmd/main.go` to adjust.

### Do webhooks need leader election?

No. Webhooks are stateless request handlers that run on all replicas:
- ValidatingWebhooks validate requests synchronously
- SAR Webhook checks permissions synchronously
- No background state required

Leader election only affects background loops that perform cleanup and monitoring.

### Do API endpoints need leader election?

No. The API is stateless and scales horizontally:
- Multiple replicas can handle requests in parallel
- State changes go through normal Kubernetes reconciliation
- Leader election only affects background loops (cleanup, updates)

### Why use Kubernetes Leases for leader election?

1. **Native to Kubernetes**: Uses standard Lease API
2. **No external dependencies**: No etcd, Redis, or database needed
3. **Automatic cleanup**: Leases are garbage collected
4. **Observable**: Check leader with `kubectl get lease`
5. **Standardized**: Same mechanism used by other Kubernetes operators
6. **Resilient**: Works across pod restarts, node failures, etc.

### What if the lease gets stuck?

If the lease is held by a crashed pod:

```bash
# Delete the lease to force new election
kubectl delete lease -n breakglass-system breakglass.telekom.io

# New leader will be elected within 2-10 seconds
kubectl logs -n breakglass-system -l app=breakglass-controller -f | grep "is now the leader"
```

The lease has a 15-second expiration, so it will be automatically reclaimed if the leader crashes ungracefully.

### How do I monitor leader election?

```bash
# Watch lease changes
kubectl get lease -n breakglass-system breakglass.telekom.io -w

# Check controller logs
kubectl logs -n breakglass-system -l app=breakglass-controller -f

# See only leadership events
kubectl logs -n breakglass-system -l app=breakglass-controller -f | grep -E "(leader|leadership)"
```

### Webhook paths changed - do I need to update ValidatingWebhookConfiguration?

If you're using Helm or Kustomize, the manifests are already updated:
- `config/webhook/manifests.yaml`: Contains correct webhook paths
- Webhook paths include full group name: `breakglass-t-caas-telekom-com`

Examples:
- `/validate-breakglass-t-caas-telekom-com-v1alpha1-identityprovider`
- `/validate-breakglass-t-caas-telekom-com-v1alpha1-breakglasssession`
- `/validate-breakglass-t-caas-telekom-com-v1alpha1-breakglassescalation`
- `/validate-breakglass-t-caas-telekom-com-v1alpha1-clusterconfig`

If manually managing ValidatingWebhookConfiguration, ensure paths match what the controller generates.

### What webhook paths should I use?

The controller automatically registers webhooks at these paths:

| Resource | Path | Group |
|----------|------|-------|
| IdentityProvider | `/validate-breakglass-t-caas-telekom-com-v1alpha1-identityprovider` | `breakglass.t-caas.telekom.com` |
| BreakglassSession | `/validate-breakglass-t-caas-telekom-com-v1alpha1-breakglasssession` | `breakglass.t-caas.telekom.com` |
| BreakglassEscalation | `/validate-breakglass-t-caas-telekom-com-v1alpha1-breakglassescalation` | `breakglass.t-caas.telekom.com` |
| ClusterConfig | `/validate-breakglass-t-caas-telekom-com-v1alpha1-clusterconfig` | `breakglass.t-caas.telekom.com` |

The path format is: `/validate-[group-with-hyphens]-[version]-[kind-lowercase]`

### Where are validating webhooks configured?

Webhook configuration comes from kubebuilder markers in the type definitions:

```go
//+kubebuilder:webhook:path=/validate-breakglass-t-caas-telekom-com-v1alpha1-identityprovider,...
```

Located in:
- `api/v1alpha1/identity_provider_types.go`
- `api/v1alpha1/breakglass_session_types.go`
- `api/v1alpha1/breakglass_escalation_types.go`
- `api/v1alpha1/cluster_config_types.go`

Manifests generated in:
- `config/webhook/manifests.yaml`

## Deployment Examples

### Single Instance (Development/Small Clusters)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: breakglass-controller
  namespace: breakglass-system
spec:
  replicas: 1  # Single instance
  selector:
    matchLabels:
      app: breakglass-controller
  template:
    metadata:
      labels:
        app: breakglass-controller
    spec:
      containers:
      - name: controller
        image: breakglass:latest
        args:
          - --enable-leader-election=true  # Optional, no effect with replicas: 1
          - --enable-cleanup=true
          - --enable-webhooks=true
          - --enable-frontend=true
        resources:
          requests:
            memory: "128Mi"
            cpu: "100m"
          limits:
            memory: "256Mi"
            cpu: "500m"
```

### Multi-Replica (Production)

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: breakglass-controller
  namespace: breakglass-system
spec:
  replicas: 3  # Multiple replicas
  selector:
    matchLabels:
      app: breakglass-controller
  template:
    metadata:
      labels:
        app: breakglass-controller
    spec:
      affinity:
        podAntiAffinity:
          preferredDuringSchedulingIgnoredDuringExecution:
          - weight: 100
            podAffinityTerm:
              labelSelector:
                matchExpressions:
                - key: app
                  operator: In
                  values:
                  - breakglass-controller
              topologyKey: kubernetes.io/hostname
      
      containers:
      - name: controller
        image: breakglass:latest
        args:
          - --enable-leader-election=true  # IMPORTANT: Enables leader election
          - --enable-cleanup=true
          - --enable-webhooks=true
          - --enable-frontend=true
        env:
        - name: LEADER_ELECT_NAMESPACE  # Optional
          value: "breakglass-system"
        - name: LEADER_ELECT_ID  # Optional
          value: "breakglass.telekom.io"
        
        resources:
          requests:
            memory: "256Mi"
            cpu: "200m"
          limits:
            memory: "512Mi"
            cpu: "1000m"
        
        livenessProbe:
          httpGet:
            path: /healthz
            port: 8080
          initialDelaySeconds: 30
          periodSeconds: 10
        
        readinessProbe:
          httpGet:
            path: /readyz
            port: 8080
          initialDelaySeconds: 10
          periodSeconds: 5
      
      serviceAccountName: breakglass-controller
```

### Helm Values (from charts/escalation-config)

```yaml
# Enable horizontal scaling with leader election
replicaCount: 3

controller:
  args:
    - --enable-leader-election=true
    - --enable-cleanup=true
    - --enable-webhooks=true
    - --enable-frontend=true

resources:
  requests:
    memory: "256Mi"
    cpu: "200m"
  limits:
    memory: "512Mi"
    cpu: "1000m"

affinity:
  podAntiAffinity:
    preferredDuringSchedulingIgnoredDuringExecution:
    - weight: 100
      podAffinityTerm:
        labelSelector:
          matchExpressions:
          - key: app
            operator: In
            values:
            - breakglass-controller
        topologyKey: kubernetes.io/hostname
```

## Related Documentation

- [Building](./building.md) - Build controller from source
- [Installation](./installation.md) - Install breakglass in Kubernetes
- [Webhook Setup](./webhook-setup.md) - Configure validating webhooks
- [Troubleshooting](./troubleshooting.md) - Common issues and solutions
- [API Reference](./api-reference.md) - API objects and CRDs
- [Cluster Config](./cluster-config.md) - Cluster configuration

## Summary

**Leader Election Status**: ✅ **FULLY IMPLEMENTED**

With the implemented leader election:

| Feature | Status | Details |
|---------|--------|---------|
| Lease-based coordination | ✅ Implemented | Uses Kubernetes Lease API |
| CleanupRoutine leadership | ✅ Implemented | Only leader deletes expired sessions |
| EscalationStatusUpdater leadership | ✅ Implemented | Only leader syncs group membership |
| ClusterConfigChecker leadership | ✅ Implemented | Only leader validates configurations |
| Configuration flag | ✅ Implemented | `--enable-leader-election` (default: true) |
| Environment variable support | ✅ Implemented | `ENABLE_LEADER_ELECTION=true/false` |
| RBAC permissions | ✅ Implemented | Lease and event permissions configured |
| Automatic failover | ✅ Implemented | New leader elected within 15-30 seconds |
| Webhook paths fixed | ✅ Implemented | All paths updated with full group name |

**Recommended Scaling Patterns**:

1. **Single instance**: 1 replica, leader election disabled or enabled (no difference)
2. **High availability**: 3+ replicas, leader election enabled, pod anti-affinity recommended
3. **Large clusters**: 5+ replicas across multiple nodes, dedicated node pool optional

**Next Steps**:

1. Deploy with `--enable-leader-election=true` (default behavior)
2. Monitor lease creation: `kubectl get lease -n breakglass-system`
3. Watch leader transitions: `kubectl logs -n breakglass-system -l app=breakglass-controller -f | grep leader`
4. Scale replicas as needed - leader election handles coordination automatically
