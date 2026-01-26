# Proposal: Enhanced DebugSessionTemplate-Cluster Binding and Resource Deployment

**Status**: Draft  
**Date**: 2026-01-21 (Updated: 2026-01-27)  
**Issue**: Enhanced cluster-template binding, scheduling constraints, and auxiliary resource deployment

## Problem Statement

The current DebugSessionTemplate design has several limitations:

1. **Weak Cluster-Template Binding**: The `allowed.clusters` field provides a simple glob-based list, but doesn't allow:
   - Different permission groups per cluster
   - Cluster-specific scheduling constraints
   - Cluster-specific resource requirements
   - Multiple node pool targeting (e.g., SRIOV vs non-SRIOV)

2. **No Scheduling Constraints**: There's no way to:
   - Prevent debug pods from spawning on control-plane nodes
   - Enforce affinity/anti-affinity rules per cluster or tenant
   - Restrict node pools that can run debug pods

3. **No Auxiliary Resources**: Debug sessions may need:
   - NetworkPolicies for secure communication
   - PodDisruptionBudgets for stability
   - ServiceAccounts with specific permissions
   - ConfigMaps/Secrets for tooling configuration

4. **Limited Namespace Control**: No way to:
   - Restrict which namespaces users can deploy debug pods to
   - Enforce namespace constraints per cluster or binding

5. **No Impersonation Support**: No way to:
   - Deploy debug pods as a specific ServiceAccount
   - Enforce least-privilege principles for debug workloads

## Goals

1. Enable per-cluster binding with distinct permission groups and constraints
2. Provide mandatory scheduling constraints that cannot be overridden by users
3. Support deployment of auxiliary Kubernetes resources alongside debug pods
4. Maintain backward compatibility with existing templates
5. **DebugSessionTemplate remains fully functional standalone for platform admins**
6. Support multiple bindings per template/cluster for different node pool scenarios
7. Mirror all constraints to API/UI for user visibility
8. Support label selectors everywhere (clusters, templates, nodes, namespaces)
9. Support user-configurable target namespaces with constraints
10. Support impersonation for ServiceAccount-based deployment

## Non-Goals

- Changing the fundamental DebugSession workflow
- Implementing cluster auto-discovery
- Real-time cluster capability detection

---

## Current State (Reality Check)

Before implementing this proposal, it's important to understand what already exists in the codebase:

### Existing Resources

| Resource | Scope | Location | Notes |
|----------|-------|----------|-------|
| `DebugSessionTemplate` | **Cluster-scoped** | `api/v1alpha1/debug_session_template_types.go` | Global debug session configuration |
| `DebugPodTemplate` | **Cluster-scoped** | `api/v1alpha1/debug_pod_template_types.go` | Reusable pod specs |
| `DebugSession` | **Namespaced** | `api/v1alpha1/debug_session_types.go` | Individual session instances |
| `ClusterConfig` | Cluster-scoped | `api/v1alpha1/cluster_config_types.go` | Target cluster connections |

### Existing Types That Will Be Extended

- **`DebugSessionAllowed`**: Has `clusters`, `groups`, `users` fields (glob pattern support)
- **`DebugSessionApprovers`**: Has `groups`, `users`, `autoApproveFor` fields
- **`DebugSessionConstraints`**: Has `maxDuration`, `defaultDuration`, `maxRenewals`, `maxConcurrentSessions`
- **`NamespaceFilter`**: Existing type with `patterns` and `selectorTerms` - can be reused for cluster filtering

### Existing Scheduling Features

The current implementation already supports:
- `DebugPodTemplate.Spec.Template.Spec.Affinity` - Base affinity rules
- `DebugPodTemplate.Spec.Template.Spec.Tolerations` - Base tolerations
- `DebugPodTemplate.Spec.Template.Spec.NodeSelector` - Base node selection
- `DebugSessionTemplate.Spec.AffinityOverrides` - Template-level affinity overrides
- `DebugSessionTemplate.Spec.AdditionalTolerations` - Additive tolerations
- `DebugSession.Spec.NodeSelector` - User-specified node selection at request time

### What Needs to Be Added

1. **New CRD**: `DebugSessionClusterBinding` (namespaced binding for delegated access)
2. **New CRD (Optional)**: `AuxiliaryResourceTemplate` (reusable auxiliary resource definitions)
3. **New Type**: `SchedulingConstraints` for mandatory constraints
4. **New Type**: `NamespaceConstraints` for target namespace control
5. **New Type**: `ImpersonationConfig` for ServiceAccount impersonation
6. **Enhanced Fields in `DebugSessionTemplate`**: All Binding features must also exist in the template for platform admin standalone usage
7. **Reconciler Changes**: Template resolution logic in `debug_session_reconciler.go`
8. **API Changes**: Two-step API (`/templates` and `/templates/{name}/clusters`)

### Key Design Principle: Feature Parity

**Every feature available in `DebugSessionClusterBinding` MUST also be available in `DebugSessionTemplate`.**

This ensures:
- Platform admins can use templates standalone without bindings
- Bindings are purely additive/restrictive layers on top of templates
- No functionality is locked behind bindings

### ClusterConfig Metadata for Label Selection

`ClusterConfig` already has these fields that can be used for `clusterSelector`:
- `spec.environment` (e.g., "dev", "staging", "prod")
- `spec.location` (region)
- `spec.site`
- `spec.tenant`
- Standard Kubernetes metadata labels

---

## Proposed Solution

### Naming: ClusterBinding

We use **`DebugSessionClusterBinding`** following Kubernetes patterns:
- **Binding**: Direct link between template and cluster (like RoleBinding links ClusterRole to namespace)
- Follows established Kubernetes naming conventions (ClusterRoleBinding, RoleBinding)

### Resource Architecture

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                        CLUSTER-SCOPED (Platform Admin)                      │
├─────────────────────────────────────────────────────────────────────────────┤
│  DebugPodTemplate          DebugSessionTemplate       AuxiliaryResourceTemplate  │
│  (Pod specs)               (Session config)           (Optional: reusable aux)   │
│       │                           │                           │                 │
│       └───────────────────────────┴───────────────────────────┘                 │
│                                   │                                             │
│                    Can be used STANDALONE by platform admins                    │
└─────────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
┌─────────────────────────────────────────────────────────────────────────────┐
│                        NAMESPACED (Delegated Access)                        │
├─────────────────────────────────────────────────────────────────────────────┤
│                       DebugSessionClusterBinding                             │
│                    (Restrictive overlay for teams)                          │
│                                                                             │
│   - References template by name (cluster-scoped)                            │
│   - Adds cluster-specific constraints (additive/restrictive)                │
│   - Multiple bindings per template+cluster allowed                          │
│   - Grants access to specific users/groups per cluster                      │
└─────────────────────────────────────────────────────────────────────────────┘
```

### DebugSessionClusterBinding Resource

Introduce a new **namespaced** CRD `DebugSessionClusterBinding` that provides delegated access to templates with cluster-specific configuration.

**Why namespaced?**

- **RBAC delegation**: Teams can manage their own bindings in their namespace
- **Multi-tenancy**: Different teams can have different bindings for the same template
- **Audit**: Namespace provides ownership context in audit logs
- **Separation of concerns**: Platform admins manage cluster-scoped DebugSessionTemplates, while team admins manage namespaced bindings

> **Note**: DebugSessionTemplate is **cluster-scoped** (like ClusterRole), while DebugSessionClusterBinding is **namespaced** (like RoleBinding). This mirrors the Kubernetes RBAC pattern where ClusterRoles can be bound in namespaces via RoleBindings for delegation.

### Multiple Bindings for Different Node Pools

A single template can have **multiple bindings** for the same cluster to target different node pools:

```yaml
# Binding for SRIOV nodes
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionClusterBinding
metadata:
  name: netops-debug-prod
  namespace: breakglass-system
spec:
  templateRef:
    name: netops-debug-template
  displayName: "Network Debug"
  clusters:
    - "prod-cluster-a"
  
  # Offer users a choice of scheduling options
  schedulingOptions:
    # If true, user MUST select one option. If false, options are optional.
    required: true
    
    # Available options for the user to choose from
    options:
      - name: sriov
        displayName: "SRIOV Nodes"
        description: "Deploy on nodes with SR-IOV network interfaces"
        schedulingConstraints:
          nodeSelector:
            network.kubernetes.io/sriov: "true"
      
      - name: standard
        displayName: "Standard Nodes"
        description: "Deploy on regular worker nodes without SR-IOV"
        schedulingConstraints:
          nodeSelector:
            network.kubernetes.io/sriov: "false"
      
      - name: any
        displayName: "Any Worker Node"
        description: "Deploy on any available worker node"
        default: true  # Pre-selected option
        schedulingConstraints: {}  # No additional constraints
  
  # Base constraints applied to ALL options (cannot be overridden)
  schedulingConstraints:
    requiredNodeAffinity:
      nodeSelectorTerms:
        - matchExpressions:
            - key: node-role.kubernetes.io/control-plane
              operator: DoesNotExist
  
  allowed:
    groups: ["netops-team", "netops-sriov-team"]
```

This approach:
- **Reduces resources**: One binding instead of 2-3 separate bindings
- **User choice**: User sees options in UI/CLI and selects one
- **Base + options**: Base `schedulingConstraints` apply to all, option-specific constraints are merged
- **Flexibility**: Some options can be restricted to specific groups (optional)

### Full Binding Example

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionClusterBinding
metadata:
  name: netops-debug-prod-cluster-a
  namespace: breakglass-system
spec:
  # Display name shown in UI (differentiates multiple bindings for same template)
  displayName: "Network Debug - Production (Worker Nodes)"
  
  # Template reference (cluster-scoped, just the name)
  templateRef:
    name: netops-debug-template
  # OR use label selector to match multiple templates
  # templateSelector:
  #   matchLabels:
  #     category: network-debug
  
  # Cluster selection (multiple methods, OR logic between them)
  clusters:
    - "prod-cluster-a"
    - "prod-cluster-b"
  clusterSelector:
    matchLabels:
      environment: production
      region: eu-west
  
  # Allowed users/groups (REPLACES template's allowed for matched clusters)
  # This grants access to these users/groups on the specified clusters
  allowed:
    groups:
      - "netops-team"
      - "sre-oncall"
    users:
      - "admin@example.com"
  
  # Approvers (overrides template's approvers for matched clusters)
  approvers:
    groups:
      - "security-team"
    autoApproveFor:
      groups:
        - "sre-oncall"
  
  # Mandatory scheduling constraints (CANNOT be overridden by users)
  schedulingConstraints:
    requiredNodeAffinity:
      nodeSelectorTerms:
        - matchExpressions:
            - key: node-role.kubernetes.io/control-plane
              operator: DoesNotExist
            - key: node.kubernetes.io/instance-type
              operator: In
              values: ["worker", "compute"]
    preferredNodeAffinity:
      - weight: 100
        preference:
          matchExpressions:
            - key: debug-workloads
              operator: In
              values: ["allowed"]
    nodeSelector:
      node-pool: "general-purpose"
    tolerations:
      - key: "dedicated"
        value: "debug-workloads"
        effect: NoSchedule
    deniedNodes:
      - "control-plane-*"
    deniedNodeLabels:
      node-role.kubernetes.io/control-plane: "*"
  
  # Session constraints (stricter than template)
  constraints:
    maxDuration: "2h"
    maxConcurrentSessions: 1
    maxRenewals: 1

  # Namespace constraints
  namespaceConstraints:
    # Allow user to choose from these namespaces
    allowedNamespaces:
      patterns:
        - "debug-*"
        - "breakglass-*"
      selectorTerms:
        - matchLabels:
            purpose: debugging
    # But never these
    deniedNamespaces:
      patterns:
        - "kube-system"
        - "kube-public"
    # Default if user doesn't specify
    defaultNamespace: "breakglass-debug"
    # User can request custom namespace (within allowed list)
    allowUserNamespace: true
  
  # Impersonation for least-privilege deployment
  impersonation:
    # Deploy resources as this ServiceAccount
    serviceAccountRef:
      name: debug-deployer
      namespace: breakglass-system
    # Or create per-session ServiceAccount
    # createPerSession: true
  
  # Required auxiliary resource categories (must be enabled)
  requiredAuxiliaryResourceCategories:
    - "network-isolation"  # NetworkPolicies required on this cluster
  
  # Auxiliary resource overrides (enable/disable categories)
  auxiliaryResourceOverrides:
    network-isolation: true
    rbac: false
  
  # Disabled temporarily disables this binding
  disabled: false
```

---

## Multi-Template Bindings with TemplateSelector

A single binding can match **multiple templates** using label selectors. This is useful for:

- Applying the same cluster constraints to a category of templates
- Managing permissions for related templates together
- Bulk configuration of auxiliary resources

### TemplateSelector Example

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionClusterBinding
metadata:
  name: network-tools-production
  namespace: breakglass-system
spec:
  # Match ALL templates with these labels
  templateSelector:
    matchLabels:
      category: network-debug
    matchExpressions:
      - key: tier
        operator: In
        values: ["standard", "advanced"]
  
  # This binding applies to all matched templates on these clusters
  clusterSelector:
    matchLabels:
      environment: production
  
  # Constraints apply to ALL matched templates
  schedulingConstraints:
    deniedNodeLabels:
      node-role.kubernetes.io/control-plane: "*"
  
  allowed:
    groups:
      - "netops-team"
```

### Naming Behavior with TemplateSelector

When a binding uses `templateSelector` instead of `templateRef`, the naming and display behavior follows these rules:

| Scenario | Display Name in UI | API Response |
|----------|-------------------|--------------|
| `templateRef` + `displayName` set | Binding's `displayName` | Single template with binding's name |
| `templateRef` + no `displayName` | Template's `displayName` | Single template with template's name |
| `templateSelector` + `displayName` set | `"{binding.displayName} - {template.displayName}"` | Multiple templates, each prefixed |
| `templateSelector` + no `displayName` | Template's `displayName` (unmodified) | Multiple templates with their own names |

### Multi-Template Binding Example with Naming

```yaml
# Templates that will be matched
---
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionTemplate
metadata:
  name: network-basic
  labels:
    category: network-debug
    tier: standard
spec:
  displayName: "Basic Network Debug"
  # ...
---
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionTemplate
metadata:
  name: network-advanced
  labels:
    category: network-debug
    tier: advanced
spec:
  displayName: "Advanced Network Debug"
  # ...
---
# Binding that matches both templates
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionClusterBinding
metadata:
  name: network-tools-prod
  namespace: breakglass-system
spec:
  # Optional: prefix for all matched templates
  displayNamePrefix: "Production"
  
  templateSelector:
    matchLabels:
      category: network-debug
  
  clusters:
    - "prod-cluster-a"
  
  allowed:
    groups:
      - "netops-team"
```

**Resulting API Response:**

```json
{
  "templates": [
    {
      "name": "network-basic",
      "displayName": "Production - Basic Network Debug",
      "binding": "network-tools-prod",
      "clusters": [{"name": "prod-cluster-a", ...}]
    },
    {
      "name": "network-advanced", 
      "displayName": "Production - Advanced Network Debug",
      "binding": "network-tools-prod",
      "clusters": [{"name": "prod-cluster-a", ...}]
    }
  ]
}
```

### TemplateSelector vs TemplateRef

| Feature | `templateRef` | `templateSelector` |
|---------|--------------|-------------------|
| Matches | Single template by name | Multiple templates by labels |
| `displayName` behavior | Overrides template name | Prefixes template names |
| Use case | Specific template binding | Category-wide binding |
| Validation | Immediate (template must exist) | Deferred (matches at runtime) |

### Validation Rules

1. `templateRef` and `templateSelector` are **mutually exclusive**
2. If `templateSelector` matches zero templates, binding is in `Warning` condition
3. If `templateSelector` would match templates the user doesn't have base access to, those templates are filtered out
4. `displayNamePrefix` is only valid with `templateSelector`, ignored with `templateRef`

---

## Enhanced DebugSessionTemplate (Feature Parity)

**Critical Requirement**: Every feature available in `DebugSessionClusterBinding` MUST also exist in `DebugSessionTemplate` so platform admins can use templates standalone.

### Complete DebugSessionTemplate Example

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionTemplate
metadata:
  name: network-debug-platform
  labels:
    category: network-debug
    tier: platform
spec:
  displayName: "Network Debug (Platform Admin)"
  description: "Full network debugging capabilities for platform admins"
  
  # Mode and workload configuration (existing)
  mode: workload
  workloadType: DaemonSet
  podTemplateRef:
    name: network-debug-pod
  
  # === PERMISSIONS (existing, enhanced) ===
  allowed:
    # Cluster selection - supports both patterns and labels
    clusters:
      - "*"  # All clusters
    clusterSelector:
      matchLabels:
        environment: production
    # User/group access
    groups:
      - "platform-admins"
      - "sre-oncall"
    users:
      - "admin@example.com"
  
  # === APPROVERS (existing) ===
  approvers:
    groups:
      - "security-team"
    autoApproveFor:
      groups:
        - "platform-admins"
      clusters:
        - "dev-*"
  
  # === SCHEDULING CONSTRAINTS (NEW - mirrors binding) ===
  schedulingConstraints:
    requiredNodeAffinity:
      nodeSelectorTerms:
        - matchExpressions:
            - key: node-role.kubernetes.io/control-plane
              operator: DoesNotExist
    preferredNodeAffinity:
      - weight: 100
        preference:
          matchExpressions:
            - key: debug-workloads
              operator: In
              values: ["allowed"]
    requiredPodAntiAffinity:
      - labelSelector:
          matchLabels:
            breakglass.t-caas.telekom.com/session-type: debug
        topologyKey: kubernetes.io/hostname
    nodeSelector:
      node-pool: "general-purpose"
    tolerations:
      - key: "dedicated"
        value: "debug-workloads"
        effect: NoSchedule
    deniedNodes:
      - "control-plane-*"
    deniedNodeLabels:
      node-role.kubernetes.io/control-plane: "*"
    topologySpreadConstraints:
      - maxSkew: 1
        topologyKey: topology.kubernetes.io/zone
        whenUnsatisfiable: ScheduleAnyway
        labelSelector:
          matchLabels:
            breakglass.t-caas.telekom.com/session-type: debug
  
  # === SESSION CONSTRAINTS (existing) ===
  constraints:
    maxDuration: "4h"
    defaultDuration: "1h"
    maxRenewals: 3
    maxConcurrentSessions: 5
  
  # === NAMESPACE CONSTRAINTS (NEW - mirrors binding) ===
  namespaceConstraints:
    allowedNamespaces:
      patterns:
        - "debug-*"
        - "breakglass-*"
      selectorTerms:
        - matchLabels:
            purpose: debugging
    deniedNamespaces:
      patterns:
        - "kube-system"
        - "kube-public"
    defaultNamespace: "breakglass-debug"
    allowUserNamespace: true
  
  # === IMPERSONATION (NEW - mirrors binding) ===
  impersonation:
    serviceAccountRef:
      name: debug-deployer
      namespace: breakglass-system
    # createPerSession: true  # Alternative: create SA per session
  
  # === AUXILIARY RESOURCES (NEW) ===
  auxiliaryResourceDefaults:
    network-isolation: true
    rbac: false
    monitoring: true
  
  # Required categories (cannot be disabled by bindings)
  requiredAuxiliaryResourceCategories:
    - "network-isolation"
  
  # === EXISTING FIELDS ===
  targetNamespace: "breakglass-debug"
  failMode: "closed"
  
  audit:
    enabled: true
    enableTerminalRecording: true
```

### Feature Parity Table

| Feature | DebugSessionTemplate | DebugSessionClusterBinding | Notes |
|---------|---------------------|---------------------------|-------|
| `schedulingConstraints` | ✅ | ✅ | Binding adds mandatory constraints |
| `schedulingOptions` | ✅ | ✅ | Offer user choice of scheduling configs |
| `namespaceConstraints` | ✅ | ✅ | Binding can restrict further |
| `impersonation` | ✅ | ✅ | Binding can override |
| `auxiliaryResourceDefaults` | ✅ | ❌ | Defined in template only |
| `auxiliaryResourceOverrides` | ❌ | ✅ | Binding enables/disables categories |
| `requiredAuxiliaryResourceCategories` | ✅ | ✅ | Both can require categories |
| `allowed.clusterSelector` | ✅ | ✅ | Label-based cluster selection |
| `templateRef` | ❌ | ✅ | Binding references single template |
| `templateSelector` | ❌ | ✅ | Binding can match multiple templates |
| `displayName` | ✅ | ✅ | Binding overrides template name in UI |
| `displayNamePrefix` | ❌ | ✅ | Prefix for multi-template bindings |

**Advantages:**

- Clear separation of concerns (template = what, binding = where/who)
- Multiple bindings can reference the same template
- Easy to manage per-cluster permissions
- Declarative and auditable
- Allows cluster admins to control bindings independently of template authors
- **Namespaced**: Enables RBAC delegation and multi-tenancy
- **DebugSessionTemplate stays global**: Keeps `allowed.clusters` and `allowed.groups` for platform-wide enablement
- **Auxiliary resources**: Defined in DebugPodTemplate, defaults in DebugSessionTemplate, simple enable/disable overrides in bindings

**Disadvantages:**

- Introduces a new CRD
- More resources to manage
- Requires changes to template resolution logic

### Key Design Decision: Template vs Binding

- **DebugSessionTemplate** remains the primary configuration for platform-wide access. It still has `allowed.clusters` and `allowed.groups` for global enablement.
- **DebugSessionClusterBinding** is an **additional** layer for cluster-specific overrides (stricter constraints, different approvers, etc.)
- When no binding exists for a cluster, the template's settings are used directly

### Access Control Model

The relationship between template and binding permissions follows specific rules:

| Aspect | Behavior | Rationale |
|--------|----------|-----------|
| **Constraints** | Binding is **additive** (more restrictive) | Safety: binding adds limits, cannot remove them |
| **Scheduling** | Binding is **additive** (more restrictive) | Safety: can deny nodes, cannot grant access to denied ones |
| **Namespaces** | Binding is **additive** (more restrictive) | Safety: can narrow allowed list, not expand |
| **Allowed Users/Groups** | Binding is **replacement** (not intersection) | Delegation: binding defines who can use this template on specific clusters |
| **Approvers** | Binding is **replacement** | Delegation: different clusters may have different approval chains |

**Key Insight**: For `allowed.groups` and `allowed.users`, the binding **replaces** the template's settings for matched clusters. This enables delegation:

```text
Template (platform-wide):
  allowed.groups: ["platform-admins"]        # Admins can use anywhere
  allowed.clusters: ["*"]                    # On all clusters

Binding (team-specific):
  allowed.groups: ["netops-team"]           # NetOps team
  clusters: ["prod-cluster-a"]              # Only on this cluster

Result:
  - platform-admins can use template on ALL clusters (via template)
  - netops-team can use template on prod-cluster-a ONLY (via binding)
  - Binding grants access, not restricts it
```

**Security Invariant**: A binding can only grant access to clusters that the user creating the binding has access to (enforced by namespace RBAC).

---

## Scheduling Constraints Design

### New Types for SchedulingConstraints

```go
// SchedulingConstraints defines mandatory scheduling rules for debug pods.
// These constraints are applied AFTER template/user settings and CANNOT be overridden.
type SchedulingConstraints struct {
    // RequiredNodeAffinity specifies hard node affinity requirements.
    // Merged with template's affinity using AND logic.
    // +optional
    RequiredNodeAffinity *corev1.NodeSelector `json:"requiredNodeAffinity,omitempty"`
    
    // PreferredNodeAffinity specifies soft node affinity preferences.
    // Added to template's preferred affinities.
    // +optional
    PreferredNodeAffinity []corev1.PreferredSchedulingTerm `json:"preferredNodeAffinity,omitempty"`
    
    // RequiredPodAntiAffinity specifies hard pod anti-affinity rules.
    // Ensures debug pods don't co-locate inappropriately.
    // +optional
    RequiredPodAntiAffinity []corev1.PodAffinityTerm `json:"requiredPodAntiAffinity,omitempty"`
    
    // PreferredPodAntiAffinity specifies soft pod anti-affinity preferences.
    // +optional
    PreferredPodAntiAffinity []corev1.WeightedPodAffinityTerm `json:"preferredPodAntiAffinity,omitempty"`
    
    // NodeSelector adds mandatory node labels for scheduling.
    // Merged with template's nodeSelector (binding takes precedence on conflicts).
    // +optional
    NodeSelector map[string]string `json:"nodeSelector,omitempty"`
    
    // Tolerations adds tolerations for debug pods.
    // Merged with template's tolerations.
    // +optional
    Tolerations []corev1.Toleration `json:"tolerations,omitempty"`
    
    // TopologySpreadConstraints controls how debug pods are spread.
    // +optional
    TopologySpreadConstraints []corev1.TopologySpreadConstraint `json:"topologySpreadConstraints,omitempty"`
    
    // DeniedNodes is a list of node name patterns that MUST NOT run debug pods.
    // Evaluated as glob patterns.
    // +optional
    DeniedNodes []string `json:"deniedNodes,omitempty"`
    
    // DeniedNodeLabels blocks nodes with any of these labels.
    // Key-value pairs where value can be "*" for any value.
    // +optional
    DeniedNodeLabels map[string]string `json:"deniedNodeLabels,omitempty"`
}
```

### SchedulingOptions Type

When a binding needs to offer users a choice between different scheduling configurations (e.g., SRIOV vs standard nodes), use `SchedulingOptions`:

```go
// SchedulingOptions allows users to choose from predefined scheduling configurations.
// This reduces the need for multiple bindings for the same template+cluster.
type SchedulingOptions struct {
    // Required specifies whether the user MUST select an option.
    // If false and no option is selected, base schedulingConstraints are used alone.
    // +optional
    // +kubebuilder:default=false
    Required bool `json:"required,omitempty"`
    
    // Options is the list of available scheduling configurations.
    // +required
    // +kubebuilder:validation:MinItems=1
    Options []SchedulingOption `json:"options"`
}

// SchedulingOption represents a single scheduling configuration choice.
type SchedulingOption struct {
    // Name is a unique identifier for this option (used in API requests).
    // +required
    // +kubebuilder:validation:MinLength=1
    // +kubebuilder:validation:MaxLength=63
    // +kubebuilder:validation:Pattern=`^[a-z0-9]([-a-z0-9]*[a-z0-9])?$`
    Name string `json:"name"`
    
    // DisplayName is the human-readable name shown in UI.
    // +required
    DisplayName string `json:"displayName"`
    
    // Description explains what this option does.
    // +optional
    Description string `json:"description,omitempty"`
    
    // Default marks this option as the pre-selected choice.
    // Only one option can be marked as default.
    // +optional
    Default bool `json:"default,omitempty"`
    
    // SchedulingConstraints are merged with the binding's base constraints.
    // These are ADDITIVE - they cannot remove base constraints.
    // +optional
    SchedulingConstraints *SchedulingConstraints `json:"schedulingConstraints,omitempty"`
    
    // AllowedGroups restricts this option to specific groups.
    // If empty, all users with access to the binding can use this option.
    // +optional
    AllowedGroups []string `json:"allowedGroups,omitempty"`
    
    // AllowedUsers restricts this option to specific users.
    // +optional
    AllowedUsers []string `json:"allowedUsers,omitempty"`
}
```

### Scheduling Options Merge Logic

When a user selects a scheduling option:

```text
1. Start with base constraints from DebugPodTemplate
2. Apply DebugSessionTemplate overrides
3. Apply binding's base schedulingConstraints (MANDATORY for all options)
4. Merge selected option's schedulingConstraints (ADDITIVE):
   - nodeSelector: merged (option values override on conflict)
   - requiredNodeAffinity: AND with base (more restrictive)
   - tolerations: appended
   - deniedNodeLabels: merged (more denials)
5. Apply user's nodeSelector (if allowUserNodeSelector=true)
```

### Example: Advanced Scheduling Options

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionClusterBinding
metadata:
  name: storage-debug-prod
spec:
  templateRef:
    name: storage-debug
  clusters: ["prod-*"]
  
  # Base constraints - apply to ALL options
  schedulingConstraints:
    requiredNodeAffinity:
      nodeSelectorTerms:
        - matchExpressions:
            - key: node-role.kubernetes.io/control-plane
              operator: DoesNotExist
    deniedNodeLabels:
      node.kubernetes.io/unschedulable: "*"
  
  schedulingOptions:
    required: true
    options:
      - name: nvme
        displayName: "NVMe Storage Nodes"
        description: "High-performance NVMe SSD nodes for storage debugging"
        schedulingConstraints:
          nodeSelector:
            storage.kubernetes.io/type: "nvme"
          tolerations:
            - key: "storage-dedicated"
              operator: "Equal"
              value: "nvme"
              effect: "NoSchedule"
        # Only storage-admins can use NVMe nodes
        allowedGroups: ["storage-admins"]
      
      - name: hdd
        displayName: "HDD Storage Nodes"
        description: "Standard HDD nodes for general storage debugging"
        default: true
        schedulingConstraints:
          nodeSelector:
            storage.kubernetes.io/type: "hdd"
      
      - name: any-storage
        displayName: "Any Storage Node"
        description: "Any node with storage role"
        schedulingConstraints:
          requiredNodeAffinity:
            nodeSelectorTerms:
              - matchExpressions:
                  - key: node-role.kubernetes.io/storage
                    operator: Exists
  
  allowed:
    groups: ["storage-team", "storage-admins"]
```

### Constraint Merging Logic

When creating a debug pod, constraints are merged in this order (later takes precedence):

1. **DebugPodTemplate** base settings
2. **DebugSessionTemplate** overrides
3. **DebugSessionClusterBinding** (or template's clusterOverrides) - **MANDATORY**
4. **DebugSession** user request (nodeSelector only, if allowed)

For mandatory constraints from ClusterBinding:

- `requiredNodeAffinity`: Always added (AND with existing)
- `deniedNodeLabels`: Converted to NOT IN expressions, always added
- `deniedNodes`: Implemented via webhook that rejects non-compliant pods

---

## Namespace Constraints Design

### NamespaceConstraints Type

```go
// NamespaceConstraints defines where debug pods can be deployed.
// This allows user choice within administrator-defined boundaries.
type NamespaceConstraints struct {
    // AllowedNamespaces specifies namespaces where debug pods can be deployed.
    // Uses NamespaceFilter for pattern and label-based selection.
    // If empty, only defaultNamespace is allowed.
    // +optional
    AllowedNamespaces *NamespaceFilter `json:"allowedNamespaces,omitempty"`
    
    // DeniedNamespaces specifies namespaces that are never allowed.
    // Evaluated AFTER allowedNamespaces (deny takes precedence).
    // +optional
    DeniedNamespaces *NamespaceFilter `json:"deniedNamespaces,omitempty"`
    
    // DefaultNamespace is used when user doesn't specify a namespace.
    // Must be within allowedNamespaces if specified.
    // +optional
    // +kubebuilder:default="breakglass-debug"
    DefaultNamespace string `json:"defaultNamespace,omitempty"`
    
    // AllowUserNamespace allows users to request a specific namespace.
    // If false, only defaultNamespace is used.
    // +optional
    // +kubebuilder:default=false
    AllowUserNamespace bool `json:"allowUserNamespace,omitempty"`
    
    // CreateIfNotExists creates the target namespace if it doesn't exist.
    // Requires appropriate RBAC permissions.
    // +optional
    // +kubebuilder:default=false
    CreateIfNotExists bool `json:"createIfNotExists,omitempty"`
    
    // NamespaceLabels are labels applied to created namespaces.
    // Only used when createIfNotExists=true.
    // +optional
    NamespaceLabels map[string]string `json:"namespaceLabels,omitempty"`
}
```

### User Request Flow

```text
1. User requests debug session, optionally specifying targetNamespace

2. If targetNamespace specified:
   a. Check allowUserNamespace=true (else reject)
   b. Check against allowedNamespaces (must match)
   c. Check against deniedNamespaces (must NOT match)
   d. Use user's requested namespace

3. If targetNamespace NOT specified:
   a. Use defaultNamespace from binding (or template if no binding)

4. If namespace doesn't exist:
   a. If createIfNotExists=true, create it with namespaceLabels
   b. Else fail according to failMode (closed=fail, open=skip pods)
```

---

## Impersonation Design

### ImpersonationConfig Type

```go
// ImpersonationConfig controls which identity is used to deploy debug resources.
// This enables least-privilege deployment where the controller impersonates
// a constrained ServiceAccount rather than using its own permissions.
type ImpersonationConfig struct {
    // ServiceAccountRef references an existing ServiceAccount to impersonate.
    // The breakglass controller must have impersonation permissions for this SA.
    // +optional
    ServiceAccountRef *ServiceAccountReference `json:"serviceAccountRef,omitempty"`
    
    // CreatePerSession creates a unique ServiceAccount for each debug session.
    // The SA is automatically cleaned up when the session ends.
    // Mutually exclusive with serviceAccountRef.
    // +optional
    CreatePerSession bool `json:"createPerSession,omitempty"`
    
    // PerSessionTemplate defines the template for per-session ServiceAccounts.
    // Only used when createPerSession=true.
    // +optional
    PerSessionTemplate *ServiceAccountTemplate `json:"perSessionTemplate,omitempty"`
    
    // ClusterRoleRef references a ClusterRole to bind to per-session SAs.
    // Only used when createPerSession=true.
    // +optional
    ClusterRoleRef string `json:"clusterRoleRef,omitempty"`
}

// ServiceAccountReference references a ServiceAccount in a specific namespace.
type ServiceAccountReference struct {
    // Name is the ServiceAccount name.
    // +required
    Name string `json:"name"`
    
    // Namespace is the ServiceAccount namespace.
    // +required
    Namespace string `json:"namespace"`
}

// ServiceAccountTemplate defines how per-session ServiceAccounts are created.
type ServiceAccountTemplate struct {
    // NamePrefix is prepended to the session name for the SA name.
    // +optional
    // +kubebuilder:default="debug-sa-"
    NamePrefix string `json:"namePrefix,omitempty"`
    
    // Labels to apply to created ServiceAccounts.
    // +optional
    Labels map[string]string `json:"labels,omitempty"`
    
    // Annotations to apply to created ServiceAccounts.
    // +optional
    Annotations map[string]string `json:"annotations,omitempty"`
}
```

### Security Considerations for Impersonation

1. **Controller RBAC**: Controller needs `impersonate` verb for ServiceAccounts
2. **Per-Session SA**: Automatically cleaned up, prevents credential leakage
3. **Audit Trail**: All actions are attributed to the impersonated SA
4. **Least Privilege**: Debug pods only get SA permissions, not controller permissions

### Impersonation Validation (Pre + Runtime)

The controller validates impersonation configuration at **two points**:

#### Pre-Validation (Binding Creation/Update)

When a `DebugSessionClusterBinding` with impersonation is created or updated, the webhook validates:

```go
func (r *DebugSessionClusterBindingValidator) validateImpersonation(
    ctx context.Context, 
    binding *DebugSessionClusterBinding,
) field.ErrorList {
    var allErrs field.ErrorList
    imp := binding.Spec.Impersonation
    if imp == nil {
        return allErrs
    }
    
    // Mutual exclusivity check
    if imp.ServiceAccountRef != nil && imp.CreatePerSession {
        allErrs = append(allErrs, field.Invalid(
            field.NewPath("spec", "impersonation"),
            imp, "serviceAccountRef and createPerSession are mutually exclusive"))
    }
    
    // Pre-validate referenced ServiceAccount
    if imp.ServiceAccountRef != nil {
        sa := &corev1.ServiceAccount{}
        err := r.Client.Get(ctx, types.NamespacedName{
            Name:      imp.ServiceAccountRef.Name,
            Namespace: imp.ServiceAccountRef.Namespace,
        }, sa)
        if err != nil {
            if apierrors.IsNotFound(err) {
                allErrs = append(allErrs, field.NotFound(
                    field.NewPath("spec", "impersonation", "serviceAccountRef"),
                    fmt.Sprintf("%s/%s", imp.ServiceAccountRef.Namespace, imp.ServiceAccountRef.Name)))
            } else {
                allErrs = append(allErrs, field.InternalError(
                    field.NewPath("spec", "impersonation", "serviceAccountRef"), err))
            }
        }
        
        // Validate controller can impersonate this SA
        if err := r.validateImpersonationPermission(ctx, sa); err != nil {
            allErrs = append(allErrs, field.Forbidden(
                field.NewPath("spec", "impersonation", "serviceAccountRef"),
                fmt.Sprintf("controller cannot impersonate SA: %v", err)))
        }
    }
    
    return allErrs
}

// validateImpersonationPermission checks if controller can impersonate the SA
func (r *DebugSessionClusterBindingValidator) validateImpersonationPermission(
    ctx context.Context,
    sa *corev1.ServiceAccount,
) error {
    // Use SelfSubjectAccessReview to check impersonation permission
    sar := &authv1.SelfSubjectAccessReview{
        Spec: authv1.SelfSubjectAccessReviewSpec{
            ResourceAttributes: &authv1.ResourceAttributes{
                Verb:      "impersonate",
                Group:     "",
                Version:   "v1",
                Resource:  "serviceaccounts",
                Name:      sa.Name,
                Namespace: sa.Namespace,
            },
        },
    }
    
    err := r.Client.Create(ctx, sar)
    if err != nil {
        return fmt.Errorf("failed to check impersonation permission: %w", err)
    }
    
    if !sar.Status.Allowed {
        return fmt.Errorf("impersonation not allowed: %s", sar.Status.Reason)
    }
    return nil
}
```

#### Runtime Validation (Session Creation)

Before deploying a debug pod, re-validate impersonation:

```go
func (c *DebugSessionController) validateImpersonationRuntime(
    ctx context.Context,
    session *DebugSession,
    binding *DebugSessionClusterBinding,
) error {
    log := log.FromContext(ctx)
    imp := binding.Spec.Impersonation
    
    if imp == nil || imp.ServiceAccountRef == nil {
        return nil // No impersonation or per-session SA (created fresh)
    }
    
    // Check SA still exists
    sa := &corev1.ServiceAccount{}
    err := c.clusterClient.Get(ctx, types.NamespacedName{
        Name:      imp.ServiceAccountRef.Name,
        Namespace: imp.ServiceAccountRef.Namespace,
    }, sa)
    if err != nil {
        log.Error(err, "impersonation SA not found", 
            "sa", imp.ServiceAccountRef.Name,
            "namespace", imp.ServiceAccountRef.Namespace)
        c.recorder.Eventf(session, corev1.EventTypeWarning, "ImpersonationFailed",
            "ServiceAccount %s/%s not found", 
            imp.ServiceAccountRef.Namespace, imp.ServiceAccountRef.Name)
        return fmt.Errorf("impersonation SA not found: %w", err)
    }
    
    // Re-validate controller can still impersonate
    if err := c.validateImpersonationPermission(ctx, sa); err != nil {
        log.Error(err, "controller cannot impersonate SA",
            "sa", sa.Name, "namespace", sa.Namespace)
        c.recorder.Eventf(session, corev1.EventTypeWarning, "ImpersonationFailed",
            "Controller cannot impersonate SA %s/%s: %v",
            sa.Namespace, sa.Name, err)
        return fmt.Errorf("impersonation permission revoked: %w", err)
    }
    
    // Audit log successful validation
    log.Info("impersonation validated",
        "session", session.Name,
        "sa", sa.Name,
        "namespace", sa.Namespace)
    
    return nil
}
```

#### Audit Logging

Both validation points are audited:

| Event | Audit Log Entry |
|-------|-----------------|
| Pre-validation success | `binding.impersonation.validated` with SA reference |
| Pre-validation failure | `binding.impersonation.validation_failed` with error |
| Runtime validation success | `session.impersonation.validated` with session + SA |
| Runtime validation failure | `session.impersonation.validation_failed` with error |
| Impersonated deployment | `session.pod.deployed` with `impersonatedAs` field |

---

## Auxiliary Resources Design

### AuxiliaryResource Type

```go
// AuxiliaryResource defines an additional Kubernetes resource to deploy with the debug session.
type AuxiliaryResource struct {
    // Name is a unique identifier for this auxiliary resource.
    // Used in status tracking and cleanup.
    // +kubebuilder:validation:MinLength=1
    // +kubebuilder:validation:MaxLength=63
    Name string `json:"name"`
    
    // Description explains what this resource does.
    // +optional
    Description string `json:"description,omitempty"`
    
    // Category is the resource category for enable/disable logic.
    // e.g., "network-isolation", "rbac", "configuration", "monitoring"
    // +optional
    Category string `json:"category,omitempty"`
    
    // Template is the embedded resource template.
    // Supports Go templating with session context variables.
    // +required
    Template runtime.RawExtension `json:"template"`
    
    // CreateBefore specifies if this resource should be created before debug pods.
    // Useful for NetworkPolicies that must exist before pods start.
    // +optional
    // +kubebuilder:default=true
    CreateBefore bool `json:"createBefore,omitempty"`
    
    // DeleteAfter specifies if this resource should be deleted after session ends.
    // +optional
    // +kubebuilder:default=true
    DeleteAfter bool `json:"deleteAfter,omitempty"`
    
    // FailurePolicy determines behavior if resource creation fails.
    // "fail" aborts the session, "ignore" continues anyway, "warn" logs warning and continues.
    // +optional
    // +kubebuilder:default="fail"
    // +kubebuilder:validation:Enum=fail;ignore;warn
    FailurePolicy string `json:"failurePolicy,omitempty"`
}
```

### Template Variables

Auxiliary resource templates are Go template strings using [Sprout](https://docs.atom.codes/sprout) as the helper library. Templates are rendered with a well-defined context.

#### Template Context

```go
// AuxiliaryResourceContext is passed to auxiliary resource templates
type AuxiliaryResourceContext struct {
    // Session information
    Session struct {
        Name        string            // DebugSession name
        Namespace   string            // DebugSession namespace (breakglass-system)
        Cluster     string            // Target cluster name
        RequestedBy string            // User email
        ApprovedBy  string            // Approver email (if applicable)
        Reason      string            // User-provided reason
        ExpiresAt   time.Time         // Session expiration time
    }
    
    // Target deployment information
    Target struct {
        Namespace   string            // Where debug pods are deployed
        ClusterName string            // ClusterConfig name
    }
    
    // Standard metadata to apply
    Labels      map[string]string     // Breakglass standard labels
    Annotations map[string]string     // Breakglass standard annotations
    
    // Template information
    Template struct {
        Name        string            // DebugSessionTemplate name
        DisplayName string            // Human-readable name
    }
    
    // Binding information (if applicable)
    Binding struct {
        Name      string              // DebugSessionClusterBinding name
        Namespace string              // Binding namespace
    }
}
```

#### Available Sprout Functions

All [Sprout functions](https://docs.atom.codes/sprout) are available. Commonly used:

| Function | Description | Example |
|----------|-------------|---------|
| `toYaml` | Convert to YAML string | `{{ .Labels \| toYaml }}` |
| `toJson` | Convert to JSON string | `{{ .Session \| toJson }}` |
| `nindent` | Add newline and indent | `{{ .Labels \| toYaml \| nindent 8 }}` |
| `default` | Default value if empty | `{{ .Binding.Name \| default "none" }}` |
| `required` | Fail if empty | `{{ required "namespace required" .Target.Namespace }}` |
| `lower` | Lowercase string | `{{ .Session.RequestedBy \| lower }}` |
| `replace` | String replacement | `{{ .Session.Name \| replace "-" "_" }}` |
| `trunc` | Truncate string | `{{ .Session.Name \| trunc 63 }}` |
| `sha256sum` | SHA256 hash | `{{ .Session.Name \| sha256sum \| trunc 8 }}` |

#### Variable Reference

| Variable | Type | Description | Example Value |
|----------|------|-------------|---------------|
| `{{ .Session.Name }}` | string | DebugSession name | `debug-session-abc123` |
| `{{ .Session.Namespace }}` | string | DebugSession namespace | `breakglass-system` |
| `{{ .Session.Cluster }}` | string | Target cluster name | `prod-cluster-a` |
| `{{ .Session.RequestedBy }}` | string | Requesting user | `user@example.com` |
| `{{ .Session.ApprovedBy }}` | string | Approver (if any) | `admin@example.com` |
| `{{ .Session.Reason }}` | string | Request reason | `Investigating issue` |
| `{{ .Target.Namespace }}` | string | Debug pod namespace | `debug-sessions-prod` |
| `{{ .Labels }}` | map | Standard labels | `map[string]string` |
| `{{ .Annotations }}` | map | Standard annotations | `map[string]string` |

### Example: NetworkPolicy Auxiliary Resource

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionTemplate
metadata:
  name: isolated-debug
spec:
  # ... standard fields ...
  
  auxiliaryResources:
    - name: egress-network-policy
      category: "network-isolation"
      createBefore: true
      deleteAfter: true
      failurePolicy: fail
      template:
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        metadata:
          name: "debug-egress-{{ .Session.Name }}"
          namespace: "{{ .Target.Namespace }}"
          labels: {{ .Labels | toYaml | nindent 12 }}
        spec:
          podSelector:
            matchLabels:
              breakglass.t-caas.telekom.com/session: "{{ .Session.Name }}"
          policyTypes:
            - Egress
          egress:
            - to:
                - ipBlock:
                    cidr: 10.0.0.0/8
              ports:
                - protocol: TCP
                  port: 443
    
    - name: debug-service-account
      category: "rbac"
      createBefore: true
      deleteAfter: true
      template:
        apiVersion: v1
        kind: ServiceAccount
        metadata:
          name: "debug-sa-{{ .Session.Name }}"
          namespace: "{{ .Target.Namespace }}"
          labels: {{ .Labels | toYaml | nindent 12 }}
          annotations:
            breakglass.t-caas.telekom.com/requested-by: "{{ .Session.RequestedBy }}"
            breakglass.t-caas.telekom.com/reason: "{{ .Session.Reason | trunc 100 }}"
```

### Example: ConfigMap with Multi-line Data

For complex configurations, use Go template blocks with proper indentation:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionTemplate
metadata:
  name: debug-with-config
spec:
  auxiliaryResources:
    - name: debug-config
      category: "configuration"
      createBefore: true
      deleteAfter: true
      template:
        apiVersion: v1
        kind: ConfigMap
        metadata:
          name: "debug-config-{{ .Session.Name }}"
          namespace: "{{ .Target.Namespace }}"
          labels: {{ .Labels | toYaml | nindent 12 }}
        data:
          # Simple key-value
          cluster: "{{ .Target.ClusterName }}"
          session-id: "{{ .Session.Name }}"
          requested-by: "{{ .Session.RequestedBy }}"
          
          # Multi-line script using | for literal blocks
          debug-script.sh: |
            #!/bin/bash
            # Auto-generated debug script for session {{ .Session.Name }}
            # Requested by: {{ .Session.RequestedBy }}
            # Reason: {{ .Session.Reason }}
            # Expires: {{ .Session.ExpiresAt.Format "2006-01-02T15:04:05Z07:00" }}
            
            echo "Debug session info:"
            echo "  Cluster: {{ .Target.ClusterName }}"
            echo "  Namespace: {{ .Target.Namespace }}"
            echo "  Template: {{ .Template.Name }}"
            
            # Add your debug commands here
            kubectl get pods -n {{ .Target.Namespace }}
          
          # JSON configuration
          config.json: |
            {
              "session": {
                "name": "{{ .Session.Name }}",
                "cluster": "{{ .Target.ClusterName }}",
                "namespace": "{{ .Target.Namespace }}",
                "requestedBy": "{{ .Session.RequestedBy | lower }}",
                "reason": {{ .Session.Reason | toJson }}
              },
              "labels": {{ .Labels | toJson }},
              "binding": {
                "name": "{{ .Binding.Name | default "none" }}",
                "namespace": "{{ .Binding.Namespace | default "none" }}"
              }
            }
          
          # YAML configuration (note: toYaml outputs with leading newline)
          metadata.yaml: |
            # Debug session metadata
            session:
              name: {{ .Session.Name }}
              cluster: {{ .Target.ClusterName }}
            labels:
{{ .Labels | toYaml | indent 14 }}
```

### Edge Cases and Defensive Templating

Handle missing or empty values defensively:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionTemplate
metadata:
  name: defensive-templating-example
spec:
  auxiliaryResources:
    - name: robust-config
      category: "configuration"
      template:
        apiVersion: v1
        kind: ConfigMap
        metadata:
          name: "debug-config-{{ .Session.Name }}"
          namespace: "{{ .Target.Namespace }}"
        data:
          # Handle potentially empty approver (not all sessions need approval)
          approved-by: "{{ .Session.ApprovedBy | default "auto-approved" }}"
          
          # Handle potentially empty binding (template may be used without binding)
          binding-info: "{{ .Binding.Name | default "no-binding" }}/{{ .Binding.Namespace | default "n-a" }}"
          
          # Truncate long strings to avoid Kubernetes limits (max annotation: 256KB)
          reason-short: "{{ .Session.Reason | trunc 200 }}"
          
          # Sanitize email for use in resource names (RFC 1123)
          user-label: "{{ .Session.RequestedBy | lower | replace "@" "-at-" | replace "." "-" | trunc 63 }}"
          
          # Required field - fail fast if missing
          cluster-name: "{{ required "cluster name is required" .Target.ClusterName }}"
          
          # Conditional content using if/else
          approval-status: |
            {{- if .Session.ApprovedBy }}
            Approved by: {{ .Session.ApprovedBy }}
            {{- else }}
            Auto-approved (no manual approval required)
            {{- end }}
          
          # Handle empty maps gracefully
          custom-labels: |
            {{- if .Labels }}
{{ .Labels | toYaml | indent 12 }}
            {{- else }}
            # No custom labels defined
            {{- end }}
          
          # Generate unique suffix for resources
          unique-suffix: "{{ .Session.Name | sha256sum | trunc 8 }}"
          
          # Date formatting (ExpiresAt is time.Time)
          expires-human: "{{ .Session.ExpiresAt.Format "Mon, 02 Jan 2006 15:04:05 MST" }}"
          expires-iso: "{{ .Session.ExpiresAt.Format "2006-01-02T15:04:05Z07:00" }}"
```

#### Common Edge Cases

| Scenario | Problem | Solution |
|----------|---------|----------|
| Empty `ApprovedBy` | Auto-approved sessions have no approver | `{{ .Session.ApprovedBy \| default "auto-approved" }}` |
| No binding used | Template used directly without binding | `{{ .Binding.Name \| default "none" }}` |
| Long reason text | Could exceed ConfigMap limits | `{{ .Session.Reason \| trunc 1000 }}` |
| Email in label | `@` and `.` invalid in labels | `{{ .Session.RequestedBy \| lower \| replace "@" "-at-" \| replace "." "-" }}` |
| Unicode in reason | May cause YAML issues | `{{ .Session.Reason \| toJson }}` (escapes properly) |
| Missing required field | Would create invalid resource | `{{ required "msg" .Field }}` (fails fast) |
| Resource name too long | K8s limit is 253 chars | `{{ .Session.Name \| trunc 63 }}` |

### Template Rendering Errors

When template rendering fails, the controller handles it based on the `failurePolicy`:

#### Failure Policies

| Policy | Behavior |
|--------|----------|
| `fail` (default) | Session creation fails, error returned to user |
| `ignore` | Skip this auxiliary resource, continue with session |
| `warn` | Log warning, add condition to session status, continue |

#### Error Handling Flow

```text
1. Pre-render Validation (at session creation time):
   - Parse all Go templates (syntax check)
   - Check required variables exist
   - Validate output would be valid YAML
   
2. If validation fails:
   a. failurePolicy=fail → Reject session, return error:
      "Failed to render auxiliary resource 'egress-policy': 
       template: egress-policy:3: function 'unknownFunc' not defined"
   
   b. failurePolicy=ignore → Log warning, skip resource, continue:
      Session proceeds but without this auxiliary resource
   
   c. failurePolicy=warn → Continue but add status condition:
      conditions:
        - type: AuxiliaryResourceWarning
          status: "True"
          reason: TemplateRenderFailed
          message: "Resource 'egress-policy' skipped: template error"

3. Runtime Errors (during resource creation):
   - If rendered YAML is invalid → Same as above based on failurePolicy
   - If K8s API rejects resource → Same as above based on failurePolicy
   - If resource already exists → Update if owned, error if not owned
```

#### Error Examples

```yaml
# Example: Missing required field
template:
  apiVersion: v1
  kind: ConfigMap
  metadata:
    name: "config-{{ .NonExistent.Field }}"  # ERROR: NonExistent is nil
    
# Error message:
# "Failed to render auxiliary resource 'config': 
#  template: config:4: nil pointer evaluating interface {}.Field"
```

```yaml
# Example: Invalid YAML output
template:
  apiVersion: v1
  kind: ConfigMap
  metadata:
    name: "config-{{ .Session.Name }}"
  data:
    # This produces invalid YAML if reason contains special chars
    raw-reason: {{ .Session.Reason }}  # Missing quotes!
    
# Error message:
# "Failed to parse rendered template for 'config': 
#  yaml: line 6: could not find expected ':'"

# Fix:
    raw-reason: "{{ .Session.Reason }}"  # Quoted
    # Or use toJson for safety:
    raw-reason: {{ .Session.Reason | toJson }}
```

#### Session Status with Template Errors

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSession
metadata:
  name: debug-session-abc123
status:
  state: Running  # Session still running if failurePolicy=warn
  conditions:
    - type: Ready
      status: "True"
      reason: PodRunning
    - type: AuxiliaryResourceWarning
      status: "True"
      reason: TemplateRenderFailed
      message: |
        Auxiliary resource 'custom-config' failed to render:
        template: custom-config:8: function "unknownHelper" not defined
        
        Resource was skipped (failurePolicy=warn).
    - type: AuxiliaryResourcesDeployed
      status: "False"
      reason: PartialDeployment
      message: "Deployed 2/3 auxiliary resources (1 skipped due to errors)"
  auxiliaryResources:
    - name: egress-policy
      status: Created
      resourceRef:
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        name: debug-egress-abc123
        namespace: debug-sessions
    - name: debug-sa
      status: Created
      resourceRef:
        apiVersion: v1
        kind: ServiceAccount
        name: debug-sa-abc123
        namespace: debug-sessions
    - name: custom-config
      status: Failed
      error: "template render error: function 'unknownHelper' not defined"
```

#### Debugging Template Errors

Use the CLI to validate templates before deployment:

```bash
# Validate a template with sample context
bgctl debug template validate \
  --template netops-debug \
  --cluster prod-cluster-a \
  --dry-run

# Output shows rendered resources or errors:
Validating auxiliary resources for template 'netops-debug'...

✓ egress-policy: Valid NetworkPolicy
✓ debug-sa: Valid ServiceAccount
✗ custom-config: Template error at line 8:
  function "unknownHelper" not defined
  
  Context dump:
  {
    "Session": {"Name": "dry-run-test", ...},
    "Target": {"Namespace": "debug-sessions", ...},
    ...
  }
```

### Allowed Resource Types

For security, only certain resource types should be allowed as auxiliary resources:

```go
// DefaultAllowedAuxiliaryResourceKinds lists resource types allowed by default.
var DefaultAllowedAuxiliaryResourceKinds = []schema.GroupKind{
    {Group: "", Kind: "ServiceAccount"},
    {Group: "", Kind: "ConfigMap"},
    {Group: "", Kind: "Secret"},
    {Group: "networking.k8s.io", Kind: "NetworkPolicy"},
    {Group: "policy", Kind: "PodDisruptionBudget"},
    {Group: "rbac.authorization.k8s.io", Kind: "Role"},
    {Group: "rbac.authorization.k8s.io", Kind: "RoleBinding"},
}
```

Cluster bindings can restrict allowed resource types using a separate field:

```yaml
spec:
  # Restrict which auxiliary resource types can be created on this cluster
  auxiliaryResourceKindRestrictions:
    allowedKinds:
      - group: ""
        kind: "ConfigMap"
      - group: "networking.k8s.io"
        kind: "NetworkPolicy"
    # Deny specific kinds
    deniedKinds:
      - group: "rbac.authorization.k8s.io"
        kind: "*"  # No RBAC resources on this cluster
```

> **Note**: `auxiliaryResourceKindRestrictions` is separate from `auxiliaryResourceOverrides` (which enables/disables categories). This field is optional and primarily used for security-sensitive clusters.

---

## Required Auxiliary Resource Categories

Clusters and bindings can **require** certain auxiliary resource categories to be enabled. This ensures compliance (e.g., "all production sessions MUST have NetworkPolicies").

### Configuration Levels

```yaml
# At ClusterConfig level - applies to ALL sessions on this cluster
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: prod-cluster-a
spec:
  # ... existing fields ...
  
  # Required for ANY debug session on this cluster
  requiredAuxiliaryResourceCategories:
    - "network-isolation"  # NetworkPolicies required
    - "audit-logging"      # Audit sidecar required
```

```yaml
# At DebugSessionClusterBinding level
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionClusterBinding
metadata:
  name: prod-binding
spec:
  # ... existing fields ...
  
  # Required for sessions using THIS binding
  requiredAuxiliaryResourceCategories:
    - "network-isolation"
```

```yaml
# At DebugSessionTemplate level
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionTemplate
metadata:
  name: secure-debug
spec:
  # ... existing fields ...
  
  # Required for ALL sessions using this template (cannot be disabled by bindings)
  requiredAuxiliaryResourceCategories:
    - "network-isolation"
```

### Validation Logic

```text
1. Collect required categories from:
   - ClusterConfig.spec.requiredAuxiliaryResourceCategories
   - DebugSessionTemplate.spec.requiredAuxiliaryResourceCategories
   - DebugSessionClusterBinding.spec.requiredAuxiliaryResourceCategories

2. For each required category:
   a. Check if DebugPodTemplate defines resources in this category
   b. Check if category is enabled (not disabled by binding overrides)
   c. If missing or disabled, REJECT session creation

3. Error message example:
   "Cluster prod-cluster-a requires 'network-isolation' category, 
    but it is disabled in binding 'team-a-binding'"
```

---

## AuxiliaryResourceTemplate CRD (Optional)

For complex deployments with many reusable auxiliary resources, an optional **AuxiliaryResourceTemplate** CRD provides better organization:

### When to Use

| Approach | Use Case |
|----------|----------|
| Inline in DebugPodTemplate | Simple, few resources, template-specific |
| AuxiliaryResourceTemplate CRD | Complex, reusable across templates, versioned |

### AuxiliaryResourceTemplate CRD

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: AuxiliaryResourceTemplate
metadata:
  name: standard-network-isolation
  labels:
    category: network-isolation
    tier: security
spec:
  displayName: "Standard Network Isolation"
  description: "Applies default-deny ingress and restricted egress"
  category: "network-isolation"
  
  # Resources in this template
  resources:
    - name: default-deny-ingress
      description: "Deny all ingress traffic"
      createBefore: true
      deleteAfter: true
      failurePolicy: fail
      template:
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        metadata:
          name: "debug-deny-ingress-{{ .Session.Name }}"
          namespace: "{{ .Target.Namespace }}"
        spec:
          podSelector:
            matchLabels:
              breakglass.t-caas.telekom.com/session: "{{ .Session.Name }}"
          policyTypes:
            - Ingress
          ingress: []
    
    - name: restricted-egress
      description: "Allow egress to internal networks and DNS only"
      createBefore: true
      deleteAfter: true
      failurePolicy: fail
      template:
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        metadata:
          name: "debug-egress-{{ .Session.Name }}"
          namespace: "{{ .Target.Namespace }}"
        spec:
          podSelector:
            matchLabels:
              breakglass.t-caas.telekom.com/session: "{{ .Session.Name }}"
          policyTypes:
            - Egress
          egress:
            - to:
                - namespaceSelector:
                    matchLabels:
                      kubernetes.io/metadata.name: kube-system
              ports:
                - protocol: UDP
                  port: 53
            - to:
                - ipBlock:
                    cidr: 10.0.0.0/8
```

### Referencing in DebugPodTemplate

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugPodTemplate
metadata:
  name: network-debug-pod
spec:
  # Pod spec...
  template:
    spec:
      containers:
        - name: debug
          image: debug-tools:latest
  
  # Reference external auxiliary resource templates
  auxiliaryResourceTemplateRefs:
    - name: standard-network-isolation
      # Optional: override category (useful for same template, different contexts)
      # categoryOverride: "custom-network"
    - name: standard-audit-logging
  
  # Can also have inline resources
  auxiliaryResources:
    - name: custom-configmap
      category: "config"
      template:
        apiVersion: v1
        kind: ConfigMap
        # ...
```

### Type Definition

```go
// +kubebuilder:object:root=true
// +kubebuilder:resource:scope=Cluster,shortName=art
// +kubebuilder:printcolumn:name="Category",type=string,JSONPath=`.spec.category`
// +kubebuilder:printcolumn:name="Resources",type=integer,JSONPath=`.status.resourceCount`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// AuxiliaryResourceTemplate defines a reusable set of auxiliary resources.
type AuxiliaryResourceTemplate struct {
    metav1.TypeMeta   `json:",inline"`
    metav1.ObjectMeta `json:"metadata,omitempty"`
    
    Spec   AuxiliaryResourceTemplateSpec   `json:"spec,omitempty"`
    Status AuxiliaryResourceTemplateStatus `json:"status,omitempty"`
}

type AuxiliaryResourceTemplateSpec struct {
    // DisplayName is a human-readable name.
    DisplayName string `json:"displayName,omitempty"`
    
    // Description explains what these resources do.
    Description string `json:"description,omitempty"`
    
    // Category is the resource category for enable/disable logic.
    // +required
    Category string `json:"category"`
    
    // Resources is the list of auxiliary resources in this template.
    // +required
    Resources []AuxiliaryResource `json:"resources"`
}

type AuxiliaryResourceTemplateStatus struct {
    // ResourceCount is the number of resources in this template.
    ResourceCount int32 `json:"resourceCount,omitempty"`
    
    // UsedBy lists DebugPodTemplates referencing this template.
    UsedBy []string `json:"usedBy,omitempty"`
}
```

---

## Label Selectors Summary

Label selectors are supported in multiple places for flexible matching:

| Location | Field | Matches Against | Use Case |
|----------|-------|-----------------|----------|
| `DebugSessionTemplate.spec.allowed.clusterSelector` | ClusterConfig labels | Template targets clusters by label |
| `DebugSessionClusterBinding.spec.clusterSelector` | ClusterConfig labels | Binding targets clusters by label |
| `DebugSessionClusterBinding.spec.templateSelector` | DebugSessionTemplate labels | Binding matches multiple templates |
| `NamespaceConstraints.allowedNamespaces.selectorTerms` | Namespace labels | Restrict by namespace labels |
| `SchedulingConstraints.requiredNodeAffinity` | Node labels | Mandatory node selection |
| All resources | Standard Kubernetes labels | Metadata-based selection |

---

## Complete DebugSessionClusterBinding CRD

### Helper Types

```go
// DebugSessionTemplateReference references a cluster-scoped DebugSessionTemplate.
// Since DebugSessionTemplate is cluster-scoped, only the name is required.
type DebugSessionTemplateReference struct {
    // Name is the DebugSessionTemplate name.
    // +required
    Name string `json:"name"`
}
```

### CRD Definition

```go
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=dscb
// +kubebuilder:printcolumn:name="Template",type=string,JSONPath=`.spec.templateRef.name`
// +kubebuilder:printcolumn:name="Clusters",type=string,JSONPath=`.status.matchedClusters`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// DebugSessionClusterBinding binds a DebugSessionTemplate to specific clusters
// with cluster-specific permissions, constraints, and resources.
// Bindings are namespaced resources for RBAC delegation purposes.
// Since DebugSessionTemplate is cluster-scoped, bindings reference templates by name only.
type DebugSessionClusterBinding struct {
    metav1.TypeMeta   `json:",inline"`
    metav1.ObjectMeta `json:"metadata,omitempty"`
    
    Spec   DebugSessionClusterBindingSpec   `json:"spec,omitempty"`
    Status DebugSessionClusterBindingStatus `json:"status,omitempty"`
}

type DebugSessionClusterBindingSpec struct {
    // DisplayName is the human-readable name shown in UI.
    // When using templateRef, this overrides the template's displayName.
    // When using templateSelector, use displayNamePrefix instead.
    // +optional
    DisplayName string `json:"displayName,omitempty"`
    
    // DisplayNamePrefix is prepended to each matched template's displayName.
    // Only used with templateSelector. Format: "{prefix} - {template.displayName}"
    // +optional
    DisplayNamePrefix string `json:"displayNamePrefix,omitempty"`
    
    // TemplateRef references the DebugSessionTemplate to bind.
    // Since DebugSessionTemplate is cluster-scoped, only the name is needed.
    // Mutually exclusive with TemplateSelector.
    // +optional
    TemplateRef *DebugSessionTemplateReference `json:"templateRef,omitempty"`
    
    // TemplateSelector selects DebugSessionTemplates by labels.
    // Allows binding multiple templates with a single binding.
    // When multiple templates match, each appears separately in the API with
    // the binding's constraints applied. Use displayNamePrefix to differentiate.
    // Mutually exclusive with TemplateRef.
    // +optional
    TemplateSelector *metav1.LabelSelector `json:"templateSelector,omitempty"`
    
    // Clusters is a list of cluster names this binding applies to.
    // Supports glob patterns (e.g., "prod-*").
    // Use "*" to match all clusters (for platform admin bindings).
    // +optional
    Clusters []string `json:"clusters,omitempty"`
    
    // ClusterSelector selects clusters by labels on ClusterConfig resources.
    // +optional
    ClusterSelector *metav1.LabelSelector `json:"clusterSelector,omitempty"`
    
    // Allowed specifies who can use this template on these clusters.
    // Overrides the template's allowed field for matched clusters.
    // +optional
    Allowed *DebugSessionAllowed `json:"allowed,omitempty"`
    
    // Approvers specifies approval requirements for these clusters.
    // Overrides the template's approvers field for matched clusters.
    // +optional
    Approvers *DebugSessionApprovers `json:"approvers,omitempty"`
    
    // SchedulingConstraints defines mandatory pod scheduling rules.
    // These CANNOT be overridden by templates or users.
    // Applied as base constraints for all scheduling options.
    // +optional
    SchedulingConstraints *SchedulingConstraints `json:"schedulingConstraints,omitempty"`
    
    // SchedulingOptions provides users with a choice of scheduling configurations.
    // Each option adds constraints on top of the base SchedulingConstraints.
    // Reduces the need for multiple bindings for the same template+cluster.
    // +optional
    SchedulingOptions *SchedulingOptions `json:"schedulingOptions,omitempty"`
    
    // NamespaceConstraints defines rules for target namespace selection.
    // Controls whether users can select namespace and what patterns are allowed.
    // +optional
    NamespaceConstraints *NamespaceConstraints `json:"namespaceConstraints,omitempty"`
    
    // Impersonation configures ServiceAccount impersonation for deployment.
    // When enabled, debug resources are deployed using the specified ServiceAccount.
    // +optional
    Impersonation *ImpersonationConfig `json:"impersonation,omitempty"`
    
    // RequiredAuxiliaryResourceCategories lists auxiliary resource categories
    // that MUST be present in the template for this binding to be valid.
    // e.g., ["networkPolicy", "resourceQuota"]
    // +optional
    RequiredAuxiliaryResourceCategories []string `json:"requiredAuxiliaryResourceCategories,omitempty"`
    
    // Constraints defines session limits for these clusters.
    // Overrides the template's constraints field for matched clusters.
    // +optional
    Constraints *DebugSessionConstraints `json:"constraints,omitempty"`
    
    // TargetNamespace overrides the template's target namespace.
    // Deprecated: Use NamespaceConstraints.DefaultNamespace instead.
    // +optional
    TargetNamespace string `json:"targetNamespace,omitempty"`
    
    // AuxiliaryResourceOverrides allows enabling/disabling resource categories.
    // Only specify categories you want to change from the template's defaults.
    // e.g., {"rbac": true, "network-isolation": false}
    // +optional
    AuxiliaryResourceOverrides AuxiliaryResourceOverrides `json:"auxiliaryResourceOverrides,omitempty"`
    
    // AuxiliaryResourceKindRestrictions restricts which resource types can be created.
    // Used for security-sensitive clusters that need to limit auxiliary resources.
    // +optional
    AuxiliaryResourceKindRestrictions *AuxiliaryResourceKindRestrictions `json:"auxiliaryResourceKindRestrictions,omitempty"`
    
    // AllowUserNodeSelector permits users to specify additional nodeSelector labels.
    // The user's nodeSelector is merged with binding constraints (binding takes precedence).
    // +optional
    // +kubebuilder:default=false
    AllowUserNodeSelector bool `json:"allowUserNodeSelector,omitempty"`
    
    // Disabled temporarily disables this binding without deleting it.
    // +optional
    Disabled bool `json:"disabled,omitempty"`
}

// AuxiliaryResourceKindRestrictions limits which Kubernetes resource types
// can be created as auxiliary resources on a cluster.
type AuxiliaryResourceKindRestrictions struct {
    // AllowedKinds is a whitelist of allowed resource types.
    // If specified, only these types can be created.
    // +optional
    AllowedKinds []GroupKind `json:"allowedKinds,omitempty"`
    
    // DeniedKinds is a blocklist of denied resource types.
    // These types cannot be created, even if in allowedKinds.
    // Kind can be "*" to match all kinds in a group.
    // +optional
    DeniedKinds []GroupKind `json:"deniedKinds,omitempty"`
}

// GroupKind identifies a Kubernetes resource type by group and kind.
type GroupKind struct {
    // Group is the API group (empty string for core resources).
    Group string `json:"group"`
    
    // Kind is the resource kind. Can be "*" to match all kinds.
    Kind string `json:"kind"`
}

type DebugSessionClusterBindingStatus struct {
    // ObservedGeneration is the last observed generation.
    ObservedGeneration int64 `json:"observedGeneration,omitempty"`
    
    // Conditions provide detailed status.
    Conditions []metav1.Condition `json:"conditions,omitempty"`
    
    // MatchedClusters lists clusters this binding currently applies to.
    MatchedClusters []string `json:"matchedClusters,omitempty"`
    
    // MatchedTemplates lists templates this binding currently applies to.
    // Only populated when using templateSelector.
    MatchedTemplates []string `json:"matchedTemplates,omitempty"`
    
    // ActiveSessions counts active debug sessions using this binding.
    ActiveSessions int32 `json:"activeSessions,omitempty"`
    
    // NameCollisions lists any name collisions detected with other bindings.
    // Webhook will reject bindings that would cause collisions.
    NameCollisions []NameCollision `json:"nameCollisions,omitempty"`
}

// NameCollision describes a collision between two bindings
type NameCollision struct {
    // TemplateName is the template that has a collision
    TemplateName string `json:"templateName"`
    // ClusterName is the cluster where collision occurs
    ClusterName string `json:"clusterName"`
    // EffectiveName is the resulting display name that collides
    EffectiveName string `json:"effectiveName"`
    // CollidingBinding is the other binding causing the collision
    CollidingBinding string `json:"collidingBinding"`
}
```

### Binding Validation Rules

The webhook validates bindings to prevent invalid configurations:

#### Name Collision Detection

Multiple bindings for the same template+cluster combination are **allowed** if they produce different effective names:

```text
Effective Name Calculation:
1. If binding.displayName is set: use binding.displayName
2. If binding.displayNamePrefix is set: use "{prefix} - {template.displayName}"
3. Otherwise: use template.displayName
```

**Example - Allowed (different names):**
```yaml
# Binding 1: "Network Debug (SRIOV)"
spec:
  templateRef: {name: netops-debug}
  displayName: "Network Debug (SRIOV)"
  clusters: ["prod-cluster-a"]

# Binding 2: "Network Debug (Standard)"  
spec:
  templateRef: {name: netops-debug}
  displayName: "Network Debug (Standard)"
  clusters: ["prod-cluster-a"]
```

**Example - Rejected (same name):**
```yaml
# Binding 1
spec:
  templateRef: {name: netops-debug}
  # No displayName - uses template's displayName
  clusters: ["prod-cluster-a"]

# Binding 2 - REJECTED: would produce same effective name
spec:
  templateRef: {name: netops-debug}
  # No displayName - would also use template's displayName
  clusters: ["prod-cluster-a"]
```

#### Other Validation Rules

| Validation | Behavior |
|------------|----------|
| `templateRef` XOR `templateSelector` | Error if both set or neither set |
| `displayName` with `templateSelector` | Warning (use `displayNamePrefix` instead) |
| Template doesn't exist | Warning in status, binding is inactive |
| No clusters match | Warning in status, binding is inactive |
| Conflicting scheduling constraints | Error (e.g., nodeSelector conflicts with deniedNodeLabels) |
| Invalid namespace pattern | Error (regex validation) |
| Impersonation SA doesn't exist | Error at creation time |
| Controller can't impersonate SA | Error at creation time |
```

---

## Template Resolution Algorithm

Resolution happens in two phases: **Discovery** (API calls) and **Session Creation** (when user submits request).

### Phase 1: Discovery (API - GET /templates and GET /templates/{name}/clusters)

```text
1. List all DebugSessionTemplates
   - Filter by user's group membership against template.spec.allowed.groups
   - Filter by user's email against template.spec.allowed.users

2. For each accessible template, find applicable DebugSessionClusterBindings:
   a. Match bindings by templateRef.name = template.name
   b. Match bindings by templateSelector labels against template.metadata.labels
   c. Filter out disabled bindings
   d. Group by template (for templateSelector, same binding may match multiple templates)

3. For each template, resolve accessible clusters:
   a. From bindings: expand binding.spec.clusters (glob patterns)
   b. From bindings: evaluate binding.spec.clusterSelector against ClusterConfig labels
   c. From template (fallback): expand template.spec.allowed.clusters
   d. Merge and deduplicate cluster list

4. For each template+cluster combination:
   a. Collect all matching bindings (each produces a distinct UI entry)
   b. Resolve merged constraints (template + binding)
   c. Build display name using binding.displayNamePrefix if applicable
   d. Include cluster health status

5. Return structured response (templates with cluster counts, then details on demand)
```

### Phase 2: Session Creation (API - POST /debug-sessions)

When a user requests a specific template + cluster combination:

```text
1. Validate user still has access to the template
   - Re-check group/user membership (permissions may have changed)

2. Find the applicable binding for this template+cluster:
   a. Match by templateRef.name OR templateSelector labels
   b. Match binding.spec.clusters (glob) against request.cluster
   c. Match binding.spec.clusterSelector against ClusterConfig labels
   d. Filter out disabled bindings
   e. User selected specific binding via displayName in request

3. If no binding found:
   - Fall back to template's allowed.clusters check (backward compat)
   - If cluster not in allowed.clusters, reject request

4. Validate Required Auxiliary Resource Categories:
   - Collect required categories from: ClusterConfig, Template, Binding
   - Check DebugPodTemplate.spec.auxiliaryResources contains matching category
   - Reject if any required category is missing or disabled

5. Resolve Target Namespace:
   a. Get constraints from binding.spec.namespaceConstraints (or template fallback)
   b. If user requested namespace: validate against allowedPatterns/deniedPatterns
   c. If no user request: use defaultNamespace
   d. Reject if namespace doesn't match constraints

6. Merge Configuration (later overrides earlier):
   a. DebugPodTemplate base settings (affinity, tolerations, nodeSelector)
   b. DebugSessionTemplate overrides
   c. ClusterBinding mandatory constraints (CANNOT be overridden)
   d. User request settings (only nodeSelector, if allowed)

7. Apply Impersonation (if configured):
   - Get SA from binding.spec.impersonation (or template fallback)
   - Validate controller has impersonation permissions for the SA
   - Add impersonation headers to deployment client

8. Final Validation:
   - Ensure scheduling constraints don't conflict
   - Validate auxiliary resource templates render correctly
   - Check resource quotas on target cluster
   - Validate target namespace exists (or create if allowed)

9. Create DebugSession with merged configuration:
   - Store resolvedTemplate with all merged settings
   - Record binding reference for audit trail
   - Store resolved impersonation details
   - Set initial state based on approval requirements
```

### Conflict Resolution Rules

| Conflict Type | Resolution |
|--------------|------------|
| Multiple bindings match template+cluster | Must have different display names (webhook rejects duplicates) |
| Template constraint vs Binding constraint | Binding's mandatory constraints always win |
| User nodeSelector vs Binding constraint | Binding's deniedNodeLabels reject request |
| Template namespace vs Binding namespace | Binding's constraints are intersected (more restrictive) |

---

## Downstream API Design

The API follows a **two-step discovery pattern** for better performance and UX:

1. **List Templates** - Fast endpoint returning available templates (lightweight)
2. **Get Template Clusters** - Detailed endpoint returning cluster-specific constraints

This separation allows:
- Fast initial page load (templates only)
- Lazy loading of cluster details when user selects a template
- Reduced payload size for users with access to many clusters
- Better caching (templates change less frequently than cluster status)

### Endpoint 1: List Available Templates

Returns all templates the user can access, without cluster details.

```text
GET /api/v1/debug-sessions/templates
```

#### Response Structure

```json
{
  "templates": [
    {
      "name": "netops-debug",
      "displayName": "Network Operations Debug",
      "description": "Debug pod with network tools for troubleshooting",
      "mode": "workload",
      "workloadType": "DaemonSet",
      "clusterCount": 5,
      "auxiliaryResources": [
        {
          "name": "network-policy",
          "category": "networkPolicy",
          "description": "Isolates debug pod network traffic",
          "optional": false
        }
      ],
      "bindingRef": {
        "name": "netops-prod-binding",
        "namespace": "breakglass-system"
      }
    },
    {
      "name": "privileged-debug",
      "displayName": "Privileged Debug (SRE Only)",
      "description": "Full host access for critical incidents",
      "mode": "workload",
      "workloadType": "Pod",
      "clusterCount": 2,
      "auxiliaryResources": [],
      "bindingRef": null
    }
  ],
  "userInfo": {
    "email": "user@example.com",
    "groups": ["netops-team", "developers"],
    "canApprove": ["netops-debug"]
  }
}
```

### Endpoint 2: Get Template Clusters

Returns cluster-specific details for a specific template.

```text
GET /api/v1/debug-sessions/templates/{templateName}/clusters
```

#### Query Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `environment` | string | Filter by cluster environment (e.g., "production") |
| `location` | string | Filter by cluster location |
| `bindingName` | string | Filter by specific binding (for multi-binding scenarios) |

#### Response Structure

```json
{
  "templateName": "netops-debug",
  "templateDisplayName": "Network Operations Debug",
  "clusters": [
    {
      "name": "prod-cluster-a",
      "displayName": "Production Cluster A",
      "environment": "production",
      "location": "eu-west-1",
      "site": "frankfurt",
      "tenant": "platform",
      "bindingRef": {
        "name": "netops-prod-binding",
        "namespace": "breakglass-system",
        "displayNamePrefix": "Production"
      },
      "constraints": {
        "maxDuration": "2h",
        "defaultDuration": "30m",
        "maxConcurrentSessions": 1,
        "maxRenewals": 1,
        "allowRenewal": true
      },
      "schedulingConstraints": {
        "summary": "Control-plane nodes excluded, worker nodes only",
        "deniedNodeLabels": {
          "node-role.kubernetes.io/control-plane": "*"
        },
        "requiredNodeLabels": {
          "node-pool": "general-purpose"
        },
        "allowedNodePools": ["general-purpose", "compute"],
        "requiredTolerations": []
      },
      "schedulingOptions": {
        "required": true,
        "options": [
          {
            "name": "sriov",
            "displayName": "SRIOV Nodes",
            "description": "Deploy on nodes with SR-IOV network interfaces",
            "default": false,
            "available": true
          },
          {
            "name": "standard",
            "displayName": "Standard Nodes",
            "description": "Deploy on regular worker nodes without SR-IOV",
            "default": true,
            "available": true
          },
          {
            "name": "any",
            "displayName": "Any Worker Node",
            "description": "Deploy on any available worker node",
            "default": false,
            "available": true
          }
        ]
      },
      "namespaceConstraints": {
        "summary": "Allowed namespaces: debug-*",
        "allowedPatterns": ["debug-*"],
        "deniedPatterns": ["kube-system", "kube-public"],
        "defaultNamespace": "debug-sessions",
        "userSelectable": true
      },
      "impersonation": {
        "enabled": true,
        "serviceAccount": "debug-deployer",
        "reason": "Enforced for audit compliance"
      },
      "requiredAuxiliaryResourceCategories": ["networkPolicy", "resourceQuota"],
      "approval": {
        "required": true,
        "approverGroups": ["security-team"],
        "canAutoApprove": false
      },
      "status": {
        "healthy": true,
        "lastChecked": "2026-01-23T10:30:00Z"
      }
    },
    {
      "name": "dev-cluster-1",
      "displayName": "Development Cluster 1",
      "environment": "development",
      "location": "eu-west-1",
      "bindingRef": null,
      "constraints": {
        "maxDuration": "8h",
        "defaultDuration": "2h",
        "maxConcurrentSessions": 5,
        "maxRenewals": 3,
        "allowRenewal": true
      },
      "schedulingConstraints": null,
      "schedulingOptions": null,
      "namespaceConstraints": {
        "summary": "User-selectable, any namespace allowed",
        "allowedPatterns": [".*"],
        "defaultNamespace": "breakglass-debug",
        "userSelectable": true
      },
      "impersonation": null,
      "requiredAuxiliaryResourceCategories": [],
      "approval": {
        "required": false,
        "approverGroups": [],
        "canAutoApprove": true
      },
      "status": {
        "healthy": true,
        "lastChecked": "2026-01-23T10:30:00Z"
      }
    }
  ]
}
```

### Endpoint 3: Create Debug Session

Creates a new debug session request.

```text
POST /api/v1/debug-sessions
```

#### Request Body

```json
{
  "templateName": "netops-debug",
  "clusterName": "prod-cluster-a",
  "reason": "Investigating network latency issue",
  "duration": "1h",
  "targetNamespace": "debug-sessions",
  "schedulingOption": "sriov",
  "nodeSelector": {
    "node-pool": "general-purpose"
  }
}
```

| Field | Required | Description |
|-------|----------|-------------|
| `templateName` | Yes | Name of the DebugSessionTemplate |
| `clusterName` | Yes | Target cluster name |
| `reason` | Yes | Reason for the debug session |
| `duration` | No | Requested duration (default from binding) |
| `targetNamespace` | No | Target namespace (if user-selectable) |
| `schedulingOption` | Conditional | Required if binding has `schedulingOptions.required=true` |
| `nodeSelector` | No | Additional node selector (if allowed) |

#### Response

```json
{
  "session": {
    "name": "debug-session-abc123",
    "namespace": "breakglass-system",
    "state": "pending-approval",
    "templateName": "netops-debug",
    "clusterName": "prod-cluster-a",
    "schedulingOption": "sriov",
    "requestedBy": "user@example.com",
    "requestedAt": "2026-01-23T10:35:00Z",
    "expiresAt": "2026-01-23T11:35:00Z",
    "approvalRequired": true,
    "approverGroups": ["security-team"]
  }
}
```

### API Implementation Notes

```go
// AvailableTemplate represents a template summary for listing
type AvailableTemplate struct {
    Name               string                   `json:"name"`
    DisplayName        string                   `json:"displayName"`
    Description        string                   `json:"description"`
    Mode               string                   `json:"mode"`
    WorkloadType       string                   `json:"workloadType,omitempty"`
    ClusterCount       int                      `json:"clusterCount"`
    AuxiliaryResources []AuxiliaryResourceInfo  `json:"auxiliaryResources,omitempty"`
    BindingRef         *BindingReference        `json:"bindingRef,omitempty"`
}

// TemplateClusterDetails represents cluster-specific configuration
type TemplateClusterDetails struct {
    TemplateName        string             `json:"templateName"`
    TemplateDisplayName string             `json:"templateDisplayName"`
    Clusters            []AvailableCluster `json:"clusters"`
}

// AvailableCluster represents a cluster with resolved constraints
type AvailableCluster struct {
    Name                              string                          `json:"name"`
    DisplayName                       string                          `json:"displayName,omitempty"`
    Environment                       string                          `json:"environment,omitempty"`
    Location                          string                          `json:"location,omitempty"`
    Site                              string                          `json:"site,omitempty"`
    Tenant                            string                          `json:"tenant,omitempty"`
    BindingRef                        *BindingReference               `json:"bindingRef,omitempty"`
    Constraints                       *ResolvedConstraints            `json:"constraints"`
    SchedulingConstraints             *SchedulingConstraintsSummary   `json:"schedulingConstraints,omitempty"`
    SchedulingOptions                 *SchedulingOptionsSummary       `json:"schedulingOptions,omitempty"`
    NamespaceConstraints              *NamespaceConstraintsSummary    `json:"namespaceConstraints,omitempty"`
    Impersonation                     *ImpersonationSummary           `json:"impersonation,omitempty"`
    RequiredAuxiliaryResourceCategories []string                      `json:"requiredAuxiliaryResourceCategories,omitempty"`
    Approval                          *ApprovalInfo                   `json:"approval"`
    Status                            *ClusterStatus                  `json:"status,omitempty"`
}

// BindingReference identifies the binding that enabled access
type BindingReference struct {
    Name              string `json:"name"`
    Namespace         string `json:"namespace"`
    DisplayNamePrefix string `json:"displayNamePrefix,omitempty"`
}

// ApprovalInfo contains approval requirements for a cluster
type ApprovalInfo struct {
    Required       bool     `json:"required"`
    ApproverGroups []string `json:"approverGroups,omitempty"`
    CanAutoApprove bool     `json:"canAutoApprove"`
}

// ClusterStatus contains health information
type ClusterStatus struct {
    Healthy     bool      `json:"healthy"`
    LastChecked time.Time `json:"lastChecked"`
}

// Existing types remain the same
type SchedulingConstraintsSummary struct {
    Summary             string            `json:"summary"`
    DeniedNodeLabels    map[string]string `json:"deniedNodeLabels,omitempty"`
    RequiredNodeLabels  map[string]string `json:"requiredNodeLabels,omitempty"`
    AllowedNodePools    []string          `json:"allowedNodePools,omitempty"`
    RequiredTolerations []string          `json:"requiredTolerations,omitempty"`
}

type NamespaceConstraintsSummary struct {
    Summary          string   `json:"summary"`
    AllowedPatterns  []string `json:"allowedPatterns,omitempty"`
    DeniedPatterns   []string `json:"deniedPatterns,omitempty"`
    DefaultNamespace string   `json:"defaultNamespace,omitempty"`
    UserSelectable   bool     `json:"userSelectable"`
}

type ImpersonationSummary struct {
    Enabled        bool   `json:"enabled"`
    ServiceAccount string `json:"serviceAccount,omitempty"`
    Reason         string `json:"reason,omitempty"`
}

type AuxiliaryResourceInfo struct {
    Name        string `json:"name"`
    Category    string `json:"category,omitempty"`
    Description string `json:"description,omitempty"`
    Optional    bool   `json:"optional"`
}

type ResolvedConstraints struct {
    MaxDuration           string `json:"maxDuration,omitempty"`
    DefaultDuration       string `json:"defaultDuration,omitempty"`
    MaxConcurrentSessions int    `json:"maxConcurrentSessions,omitempty"`
    MaxRenewals           int    `json:"maxRenewals,omitempty"`
    AllowRenewal          bool   `json:"allowRenewal"`
}

// SchedulingOptionsSummary is returned in API responses
type SchedulingOptionsSummary struct {
    Required bool                       `json:"required"`
    Options  []SchedulingOptionSummary  `json:"options"`
}

// SchedulingOptionSummary represents a single option in the API response
type SchedulingOptionSummary struct {
    Name        string `json:"name"`
    DisplayName string `json:"displayName"`
    Description string `json:"description,omitempty"`
    Default     bool   `json:"default"`
    Available   bool   `json:"available"`  // false if user doesn't have access (group restriction)
}
```

---

## CLI Changes

### New Commands

```bash
# List available templates (fast, lightweight)
bgctl debug templates list
bgctl debug templates list --output wide
bgctl debug templates list --output json

# Get clusters for a specific template (detailed)
bgctl debug templates clusters <template-name>
bgctl debug templates clusters netops-debug --environment production
bgctl debug templates clusters netops-debug --output json

# Create debug session (interactive mode)
bgctl debug session create
# Step 1: Select template from list
# Step 2: Select cluster from list (shows constraints)
# Step 3: Select scheduling option (if required)
# Step 4: Confirm and submit

# Create debug session (non-interactive)
bgctl debug session create \
  --template netops-debug \
  --cluster prod-cluster-a \
  --scheduling-option sriov \
  --reason "Investigating issue" \
  --duration 1h \
  --namespace debug-sessions
```

### Example CLI Output

```bash
$ bgctl debug templates list

NAME              DISPLAY NAME                    MODE      CLUSTERS  BINDING
netops-debug      Network Operations Debug        workload  5         netops-prod-binding
privileged-debug  Privileged Debug (SRE Only)     workload  2         -
storage-debug     Storage Debug Tools             workload  3         storage-team-binding

$ bgctl debug templates clusters netops-debug

CLUSTER          ENVIRONMENT  LOCATION   MAX DURATION  APPROVAL   CONSTRAINTS
prod-cluster-a   production   eu-west-1  2h            required   control-plane excluded
prod-cluster-b   production   eu-west-2  2h            required   control-plane excluded
dev-cluster-1    development  eu-west-1  8h            auto       none
dev-cluster-2    development  us-east-1  8h            auto       none
staging-1        staging      eu-west-1  4h            required   worker nodes only

$ bgctl debug templates clusters netops-debug --output wide

CLUSTER          ENVIRONMENT  LOCATION   MAX DURATION  NAMESPACE          IMPERSONATION    APPROVAL
prod-cluster-a   production   eu-west-1  2h            debug-* (default)  debug-deployer   required (security-team)
prod-cluster-b   production   eu-west-2  2h            debug-* (default)  debug-deployer   required (security-team)
dev-cluster-1    development  eu-west-1  8h            any               -                auto
...

$ bgctl debug session create --template netops-debug --cluster prod-cluster-a --reason "Network issue" --duration 1h

Debug session created:
  Name:      debug-session-abc123
  Template:  netops-debug
  Cluster:   prod-cluster-a
  State:     pending-approval
  Expires:   2026-01-23T11:35:00Z

Waiting for approval from: security-team
Use 'bgctl debug session status debug-session-abc123' to check status.
```

---

## UI Changes

### Template Selection View (Step 1)

The UI now shows a **template list first**, with cluster count as a summary:

```
┌─────────────────────────────────────────────────────────────────────┐
│  Available Debug Sessions                                           │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ 🔧 Network Operations Debug                                  │   │
│  │    Debug pod with network tools for troubleshooting          │   │
│  │    Mode: workload (DaemonSet)                                │   │
│  │    Available on: 5 clusters                                  │   │
│  │    [Select Template →]                                       │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ 🔒 Privileged Debug (SRE Only)                               │   │
│  │    Full host access for critical incidents                   │   │
│  │    Mode: workload (Pod)                                      │   │
│  │    Available on: 2 clusters                                  │   │
│  │    [Select Template →]                                       │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Cluster Selection View (Step 2)

After selecting a template, the UI fetches cluster details:

```
┌─────────────────────────────────────────────────────────────────────┐
│  Network Operations Debug → Select Cluster                          │
│  [← Back to Templates]                                              │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Filter: [Environment ▼] [Location ▼] [Search...]                  │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ prod-cluster-a                                    Production │   │
│  │ Frankfurt, EU                                                │   │
│  ├─────────────────────────────────────────────────────────────┤   │
│  │ ⏱ Max Duration: 2h        📋 Approval: Required             │   │
│  │ 📍 Namespace: debug-*     👥 Approvers: security-team       │   │
│  │ 🚫 Excluded: control-plane nodes                            │   │
│  │ 🔐 Impersonation: debug-deployer (audit compliance)         │   │
│  │                                                              │   │
│  │ [Select Cluster →]                                           │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ dev-cluster-1                                   Development  │   │
│  │ Ireland, EU                                                  │   │
│  ├─────────────────────────────────────────────────────────────┤   │
│  │ ⏱ Max Duration: 8h        📋 Approval: Auto-approved        │   │
│  │ 📍 Namespace: user choice 👥 Approvers: -                   │   │
│  │ 🚫 Excluded: none                                            │   │
│  │ 🔐 Impersonation: none                                       │   │
│  │                                                              │   │
│  │ [Select Cluster →]                                           │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### Session Configuration View (Step 3)

After selecting a cluster, show configuration form with constraints:

```
┌─────────────────────────────────────────────────────────────────────┐
│  Network Operations Debug → prod-cluster-a → Configure              │
│  [← Back to Clusters]                                               │
├─────────────────────────────────────────────────────────────────────┤
│                                                                     │
│  Reason for Access: *                                               │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ Investigating network latency between pods                   │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  Duration:                                                          │
│  [30m] [1h] [2h (max)]                                             │
│                                                                     │
│  Node Type: *                                                       │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ ○ SRIOV Nodes                                                │   │
│  │   Deploy on nodes with SR-IOV network interfaces             │   │
│  │                                                              │   │
│  │ ● Standard Nodes (default)                                   │   │
│  │   Deploy on regular worker nodes without SR-IOV              │   │
│  │                                                              │   │
│  │ ○ Any Worker Node                                            │   │
│  │   Deploy on any available worker node                        │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  Namespace:                                                         │
│  [debug-sessions ▼] (allowed: debug-*)                             │
│                                                                     │
│  ┌─────────────────────────────────────────────────────────────┐   │
│  │ ℹ️ Constraints Applied:                                      │   │
│  │ • Control-plane nodes excluded                               │   │
│  │ • Standard worker nodes selected                             │   │
│  │ • Resources deployed as: debug-deployer                      │   │
│  │ • NetworkPolicy will be created                              │   │
│  │ • ResourceQuota will be enforced                             │   │
│  └─────────────────────────────────────────────────────────────┘   │
│                                                                     │
│  ⚠️ This request requires approval from: security-team             │
│                                                                     │
│  [Cancel]                                    [Request Debug Session] │
│                                                                     │
└─────────────────────────────────────────────────────────────────────┘
```

### UI State Diagram

```text
┌─────────────────┐     Select      ┌─────────────────┐     Select     ┌─────────────────┐
│                 │    Template     │                 │    Cluster     │                 │
│  Template List  │ ──────────────► │  Cluster List   │ ─────────────► │  Configure &    │
│  (cached)       │                 │  (lazy loaded)  │                │  Submit         │
│                 │ ◄────────────── │                 │ ◄───────────── │                 │
└─────────────────┘      Back       └─────────────────┘     Back       └─────────────────┘
        │                                   │                                   │
        │ GET /templates                    │ GET /templates/{name}/clusters    │ POST /debug-sessions
        └───────────────────────────────────┴───────────────────────────────────┘
```

---

## API Migration Notes

### Backward Compatibility

The old unified endpoint is **deprecated but still functional**:

```text
GET /api/v1/debug-sessions/available  (DEPRECATED)
```

Returns the same format as before, but with a deprecation warning header:

```
X-Deprecated: true
X-Deprecation-Message: Use /api/v1/debug-sessions/templates and /api/v1/debug-sessions/templates/{name}/clusters
X-Sunset-Date: 2027-01-01
```

### Migration Timeline

| Phase | Date | Action |
|-------|------|--------|
| v1.5.0 | 2026-Q2 | New endpoints available, old endpoint deprecated |
| v1.6.0 | 2026-Q3 | Old endpoint logs warning |
| v2.0.0 | 2027-Q1 | Old endpoint removed |

---

## Platform Admin Bindings

Platform administrators who need access to all clusters should use **wildcard bindings**:

### Global Binding Example

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionClusterBinding
metadata:
  name: platform-admin-global
  namespace: breakglass-system
spec:
  templateRef:
    name: privileged-debug
  
  # Wildcard matches ALL clusters
  clusters:
    - "*"
  
  # Platform admin group
  allowed:
    groups:
      - "platform-admins"
      - "sre-oncall"
  
  # Auto-approve for platform admins (they approve themselves)
  approvers:
    autoApproveFor:
      groups:
        - "platform-admins"
  
  # Minimal constraints even for admins (safety net)
  schedulingConstraints:
    # Even admins shouldn't accidentally schedule on control-plane
    # unless they explicitly override with nodeSelector
    preferredNodeAffinity:
      - weight: 100
        preference:
          matchExpressions:
            - key: node-role.kubernetes.io/control-plane
              operator: DoesNotExist
  
  # But can be overridden if needed
  allowUserNodeSelector: true
```

---

## Auxiliary Resources in DebugPodTemplate (Confirmed)

Auxiliary resources are defined in the `DebugPodTemplate` with conditional inclusion via bindings. This is the **recommended approach** because:

- **Reusability**: Same resource definitions across multiple templates
- **Consistency**: Cluster-agnostic resource templates
- **Conditional activation**: Bindings enable/disable specific resources per cluster
- **Single source of truth**: Pod template authors define what's possible, bindings control what's enabled

### Enhanced DebugPodTemplate with Auxiliary Resources

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugPodTemplate
metadata:
  name: network-debug-pod
  namespace: breakglass-system
spec:
  displayName: "Network Debug Pod"
  
  # Pod specification (existing)
  template:
    spec:
      containers:
        - name: debug
          image: registry.example.com/debug-tools:latest
          securityContext:
            capabilities:
              add: ["NET_ADMIN", "NET_RAW"]
  
  # Auxiliary resources defined at pod template level
  auxiliaryResources:
    - name: egress-network-policy
      description: "Restricts egress to internal networks only"
      # Category for enable/disable logic
      category: "network-isolation"
      template:
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        metadata:
          name: "debug-egress-{{ .Session.Name }}"
          namespace: "{{ .Target.Namespace }}"
        spec:
          podSelector:
            matchLabels:
              breakglass.t-caas.telekom.com/session: "{{ .Session.Name }}"
          policyTypes:
            - Egress
          egress:
            - to:
                - ipBlock:
                    cidr: 10.0.0.0/8
    
    - name: debug-service-account
      description: "ServiceAccount with read-only cluster access"
      category: "rbac"
      template:
        apiVersion: v1
        kind: ServiceAccount
        metadata:
          name: "debug-sa-{{ .Session.Name }}"
          namespace: "{{ .Target.Namespace }}"
    
    - name: cluster-reader-role
      description: "ClusterRole for read-only access"
      category: "rbac"
      # Requires explicit approval even if session is auto-approved
      requiresApproval: true
      template:
        apiVersion: rbac.authorization.k8s.io/v1
        kind: RoleBinding
        metadata:
          name: "debug-reader-{{ .Session.Name }}"
          namespace: "{{ .Target.Namespace }}"
        roleRef:
          apiGroup: rbac.authorization.k8s.io
          kind: ClusterRole
          name: view
        subjects:
          - kind: ServiceAccount
            name: "debug-sa-{{ .Session.Name }}"
            namespace: "{{ .Target.Namespace }}"
```

### DebugSessionTemplate with Auxiliary Resource Defaults

The DebugSessionTemplate defines which categories are enabled by default:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionTemplate
metadata:
  name: network-debug-session
  namespace: breakglass-system
spec:
  displayName: "Network Debug Session"
  podTemplateRef:
    name: network-debug-pod
  
  # Global access - still works for platform enablement
  allowed:
    clusters:
      - "*"  # Available on all clusters
    groups:
      - "netops-team"
      - "sre-oncall"
  
  # Defaults for auxiliary resources by category
  # Categories not listed here are disabled by default
  auxiliaryResourceDefaults:
    network-isolation: true   # Deploy NetworkPolicies by default
    rbac: false               # Don't deploy RBAC resources by default
```

### Binding Overrides (Optional)

Bindings can override the template's defaults for specific clusters:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionClusterBinding
metadata:
  name: prod-network-debug
  namespace: breakglass-system
spec:
  templateRef:
    name: network-debug-session
  clusters:
    - "prod-*"
  
  # Only specify if you need to change from template defaults
  auxiliaryResourceOverrides:
      # Disable RBAC resources on this cluster
      rbac: false
      # Ensure network policies are deployed
      network-isolation: true
```

### Resolution Logic for Auxiliary Resources

```text
1. Collect auxiliary resources from DebugPodTemplate.spec.auxiliaryResources

2. Apply DebugSessionTemplate defaults:
   - Template specifies which resource categories are enabled by default
   - e.g., auxiliaryResourceDefaults: { network-isolation: true, rbac: false }

3. Apply binding overrides (if any):
   - Binding can flip specific categories on/off
   - e.g., auxiliaryResourceOverrides: { rbac: true }

4. For each enabled resource:
   a. If requiresApproval=true, mark session as requiring approval
   b. Render template with session context

5. Deploy resources in order:
   a. createBefore=true resources first
   b. Then debug pods
   c. Then createBefore=false resources
```

### Updated Type Definitions

The following types extend the base `AuxiliaryResource` type with additional fields specific to `DebugPodTemplate`:

```go
// PodTemplateAuxiliaryResource extends AuxiliaryResource with fields specific to DebugPodTemplate.
// This is the full type used when defining auxiliary resources in a pod template.
type PodTemplateAuxiliaryResource struct {
    // Name is a unique identifier
    Name string `json:"name"`
    
    // Description explains what this resource does
    Description string `json:"description,omitempty"`
    
    // Category is the resource category for enable/disable logic
    // e.g., "network-isolation", "rbac", "monitoring"
    // +required
    Category string `json:"category"`
    
    // RequiresApproval forces approval even for auto-approve sessions
    RequiresApproval bool `json:"requiresApproval,omitempty"`
    
    // CreateBefore deploys before debug pods
    // +kubebuilder:default=true
    CreateBefore bool `json:"createBefore,omitempty"`
    
    // DeleteAfter cleans up when session ends
    // +kubebuilder:default=true
    DeleteAfter bool `json:"deleteAfter,omitempty"`
    
    // Template is the resource template
    Template runtime.RawExtension `json:"template"`
}

// AuxiliaryResourceDefaults in DebugSessionTemplate
// Maps category names to enabled/disabled state
// e.g., { "network-isolation": true, "rbac": false }
type AuxiliaryResourceDefaults map[string]bool

// AuxiliaryResourceOverrides in DebugSessionClusterBinding
// Simple category-based enable/disable overrides
// Only specify categories you want to change from the template defaults
type AuxiliaryResourceOverrides map[string]bool
```

---

## Migration Path

### Phase 1: Add ClusterBinding CRD (Non-Breaking)

- Add `DebugSessionClusterBinding` CRD
- Templates continue to work without bindings
- Bindings are optional and take precedence when present

### Phase 2: Add Scheduling Constraints to Template

- Add `schedulingConstraints` to `DebugSessionTemplateSpec`
- Allows templates to have default constraints
- Bindings can add mandatory constraints on top

### Phase 3: Add Auxiliary Resources

- Add `auxiliaryResources` to both Template and Binding
- Template defines defaults, Binding can override

### Phase 4: Deprecation (Optional)

- Consider deprecating `template.allowed.clusters` in favor of bindings
- Long deprecation period (6+ months)
- Keep backward compatibility

---

## Security Considerations

1. **Binding RBAC**: Only cluster admins should create/modify bindings
2. **Scheduling Constraints**: Bindings' constraints are mandatory and cannot be bypassed
3. **Auxiliary Resources**: Limit allowed resource types to prevent privilege escalation
4. **Template Validation**: Reject auxiliary resources that create ClusterRoles, etc.
5. **Namespace Isolation**: Auxiliary resources are created in `targetNamespace` only

---

## API Examples

### Tenant Isolation Example

```yaml
# Template for tenant debugging
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionTemplate
metadata:
  name: tenant-debug
spec:
  mode: workload
  workloadType: DaemonSet
  podTemplateRef:
    name: basic-debug-pod
---
# Binding for Tenant A - can only use tenant-a nodes
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionClusterBinding
metadata:
  name: tenant-a-debug
spec:
  templateRef:
    name: tenant-debug
  clusterSelector:
    matchLabels:
      tenant: tenant-a
  allowed:
    groups: ["tenant-a-admins"]
  schedulingConstraints:
    requiredNodeAffinity:
      nodeSelectorTerms:
        - matchExpressions:
            - key: tenant
              operator: In
              values: ["tenant-a"]
            - key: node-role.kubernetes.io/control-plane
              operator: DoesNotExist
---
# Binding for Tenant B - separate constraints
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionClusterBinding
metadata:
  name: tenant-b-debug
spec:
  templateRef:
    name: tenant-debug
  clusterSelector:
    matchLabels:
      tenant: tenant-b
  allowed:
    groups: ["tenant-b-admins"]
  schedulingConstraints:
    requiredNodeAffinity:
      nodeSelectorTerms:
        - matchExpressions:
            - key: tenant
              operator: In
              values: ["tenant-b"]
            - key: node-role.kubernetes.io/control-plane
              operator: DoesNotExist
```

### Production Cluster with NetworkPolicy

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionClusterBinding
metadata:
  name: prod-binding
spec:
  templateRef:
    name: network-debug
  clusters:
    - "prod-*"
  allowed:
    groups: ["sre-team"]
  approvers:
    groups: ["security-team"]
    autoApproveFor:
      groups: ["sre-oncall"]
  schedulingConstraints:
    requiredNodeAffinity:
      nodeSelectorTerms:
        - matchExpressions:
            - key: node-role.kubernetes.io/control-plane
              operator: DoesNotExist
            - key: workload-type
              operator: In
              values: ["general", "debug"]
    deniedNodeLabels:
      node-restriction.kubernetes.io/critical: "*"
  
  # Enable network isolation category defined in DebugPodTemplate
  requiredAuxiliaryResourceCategories:
    - "network-isolation"
  auxiliaryResourceOverrides:
    network-isolation: true  # Ensure NetworkPolicies are deployed
```

> **Note**: The actual NetworkPolicy template is defined in the `DebugPodTemplate`. The binding only controls which categories are enabled. See [Auxiliary Resources in DebugPodTemplate](#auxiliary-resources-in-debugpodtemplate-confirmed) for the full resource definition.

---

## Open Questions

1. ~~**Binding Namespace**: Should bindings be cluster-scoped or namespace-scoped?~~
   - **DECIDED**: Namespace-scoped for RBAC delegation and multi-tenancy

2. ~~**Multiple Bindings**: How to handle when multiple bindings match the same template+cluster?~~
   - **DECIDED**: Multiple bindings for same template+cluster ARE allowed if resulting display name is different
   - If two bindings would produce the same effective name, webhook rejects the second binding
   - No priority system - each binding produces a distinct entry in the UI
   - Warn on ambiguous matches in binding status

3. ~~**Auxiliary Resource Quotas**: Should there be limits on auxiliary resources?~~
   - **DECIDED**: Start without quotas, add if needed based on usage patterns

4. ~~**Binding Validation**: Should bindings validate against templates?~~
   - **DECIDED**: 
     - Warn in binding status if referenced template doesn't exist
     - Error on invalid constraint combinations (e.g., conflicting node selectors)

5. ~~**AuxiliaryResourceTemplate CRD**: Should we implement the separate CRD?~~
   - **DECIDED**: Start with inline Go template strings (no separate CRD)
   - Use [Sprout](https://docs.atom.codes/sprout) as template helper library
   - Define well-documented context variables
   - Add typed CRD later if reusability patterns emerge

6. ~~**Impersonation Security**: How to validate ServiceAccount permissions?~~
   - **DECIDED**: Both pre-validation AND runtime validation
     - Pre-validate during binding creation (webhook checks controller can impersonate SA)
     - Runtime validation before each deployment (SA still exists, permissions unchanged)
     - Audit log both validation points

---

## Implementation Phases

### Phase 1: Core Framework (4-6 weeks)

- [ ] Add `DebugSessionClusterBinding` CRD
- [ ] Implement binding resolution logic with templateSelector support
- [ ] Add `schedulingConstraints` to binding and template
- [ ] Add `namespaceConstraints` to binding and template
- [ ] Update debug pod creation to apply constraints
- [ ] Add webhook validation for constraints
- [ ] Add name collision detection for bindings (webhook)
- [ ] Add `MatchedTemplates` and `NameCollisions` to binding status

### Phase 2: API Redesign (2-3 weeks)

- [ ] Implement `GET /api/v1/debug-sessions/templates` endpoint
- [ ] Implement `GET /api/v1/debug-sessions/templates/{name}/clusters` endpoint
- [ ] Deprecate `GET /api/v1/debug-sessions/available` endpoint
- [ ] Update session creation endpoint to use new resolution logic

### Phase 3: Namespace & Impersonation (3-4 weeks)

- [ ] Implement namespace constraint validation
- [ ] Add `impersonation` configuration to CRD
- [ ] Implement impersonation pre-validation (webhook)
- [ ] Implement impersonation runtime validation (session controller)
- [ ] Update deployment logic to use impersonation
- [ ] Add SelfSubjectAccessReview for permission checks
- [ ] Add audit logging for impersonation validation (pre + runtime)
- [ ] Add audit logging for impersonated deployments

### Phase 4: Auxiliary Resources (3-4 weeks)

- [ ] Add `auxiliaryResources` to DebugPodTemplate
- [ ] Add `requiredAuxiliaryResourceCategories` validation
- [ ] Implement template rendering engine
- [ ] Add resource creation/cleanup lifecycle
- [ ] Add allowed/denied resource type filtering

### Phase 5: Enhanced DebugSessionTemplate (2-3 weeks)

- [ ] Add all new fields to DebugSessionTemplate for parity
- [ ] Implement standalone platform admin mode
- [ ] Validate feature parity between template and binding

### Phase 6: UI Redesign (3-4 weeks)

- [ ] Implement two-step selection flow (template → cluster)
- [ ] Update frontend to show all constraint information
- [ ] Add namespace selection with constraint hints
- [ ] Add loading states for lazy-loaded cluster details
- [ ] Show active constraints when creating session

### Phase 7: CLI Updates (2 weeks)

- [ ] Add `bgctl debug templates list` command
- [ ] Add `bgctl debug templates clusters <name>` command
- [ ] Add `bgctl debug binding list/create/delete` commands
- [ ] Update interactive session creation flow

### Phase 8: Documentation and Migration (1-2 weeks)

- [ ] Update all documentation
- [ ] Migration guide for existing templates
- [ ] Example library of common bindings
- [ ] Helm chart updates for new CRDs
- [ ] API migration guide for consumers

---

## Appendix: Full Type Definitions

