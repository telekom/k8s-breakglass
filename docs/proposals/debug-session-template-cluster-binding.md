# Proposal: Enhanced DebugSessionTemplate-Cluster Binding and Resource Deployment

**Status**: Draft  
**Date**: 2026-01-21  
**Issue**: Enhanced cluster-template binding, scheduling constraints, and auxiliary resource deployment

## Problem Statement

The current DebugSessionTemplate design has several limitations:

1. **Weak Cluster-Template Binding**: The `allowed.clusters` field provides a simple glob-based list, but doesn't allow:
   - Different permission groups per cluster
   - Cluster-specific scheduling constraints
   - Cluster-specific resource requirements

2. **No Scheduling Constraints**: There's no way to:
   - Prevent debug pods from spawning on control-plane nodes
   - Enforce affinity/anti-affinity rules per cluster or tenant
   - Restrict node pools that can run debug pods

3. **No Auxiliary Resources**: Debug sessions may need:
   - NetworkPolicies for secure communication
   - PodDisruptionBudgets for stability
   - ServiceAccounts with specific permissions
   - ConfigMaps/Secrets for tooling configuration

## Goals

1. Enable per-cluster binding with distinct permission groups and constraints
2. Provide mandatory scheduling constraints that cannot be overridden by users
3. Support deployment of auxiliary Kubernetes resources alongside debug pods
4. Maintain backward compatibility with existing templates

## Non-Goals

- Changing the fundamental DebugSession workflow
- Implementing cluster auto-discovery
- Real-time cluster capability detection

---

## Proposed Solution

### ClusterBinding Resource

Introduce a new **namespaced** CRD `DebugSessionClusterBinding` that acts as a binding between templates and clusters with cluster-specific configuration.

**Why namespaced?**

- **RBAC delegation**: Teams can manage their own bindings in their namespace
- **Multi-tenancy**: Different teams can have different bindings for the same template
- **Audit**: Namespace provides ownership context in audit logs
- **Consistency**: Aligns with DebugSessionTemplate which is also namespaced

Bindings reference templates in the same namespace by default, or can cross-reference templates in other namespaces if permitted by RBAC.

```yaml
apiVersion: breakglass.telekom.de/v1alpha1
kind: DebugSessionClusterBinding
metadata:
  name: netops-debug-prod-cluster-a
  namespace: breakglass-system  # Same namespace as the template
spec:
  # Which template this binding applies to
  templateRef:
    name: netops-debug-template
  
  # Which clusters this binding applies to (supports glob patterns)
  clusters:
    - "prod-cluster-a"
    - "prod-cluster-b"
    # OR use label selectors on ClusterConfig resources
    # clusterSelector:
    #   matchLabels:
    #     environment: production
    #     region: eu-west

  # Cluster-specific permissions (overrides template's allowed.groups)
  allowed:
    groups:
      - "netops-team"
      - "sre-oncall"
    users:
      - "admin@example.com"
  
  # Cluster-specific approvers (overrides template's approvers)
  approvers:
    groups:
      - "security-team"
    autoApproveFor:
      groups:
        - "sre-oncall"  # SRE on-call can auto-approve on these clusters
  
  # Mandatory scheduling constraints (cannot be overridden)
  schedulingConstraints:
    # Node affinity to prevent control-plane scheduling
    requiredNodeAffinity:
      nodeSelectorTerms:
        - matchExpressions:
            - key: node-role.kubernetes.io/control-plane
              operator: DoesNotExist
            - key: node.kubernetes.io/instance-type
              operator: In
              values:
                - "worker"
                - "compute"
    
    # Preferred affinity (best-effort)
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
            breakglass.telekom.de/session-type: debug
        topologyKey: kubernetes.io/hostname
    
    # Tolerations to add (e.g., for dedicated debug nodes)
    tolerations:
      - key: "dedicated"
        value: "debug-workloads"
        effect: NoSchedule
    
    # Node selector (additive with user's nodeSelector)
    nodeSelector:
      node-pool: "general-purpose"
    
    # Topology spread constraints
    topologySpreadConstraints:
      - maxSkew: 1
        topologyKey: topology.kubernetes.io/zone
        whenUnsatisfiable: ScheduleAnyway
        labelSelector:
          matchLabels:
            breakglass.telekom.de/session-type: debug

  # Cluster-specific constraints (override template defaults)
  constraints:
    maxDuration: "2h"          # Shorter for production
    maxConcurrentSessions: 1   # Stricter limits
    maxRenewals: 1

  # Cluster-specific target namespace
  targetNamespace: "debug-sessions-prod"
```

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
    // "fail" aborts the session, "ignore" continues anyway.
    // +optional
    // +kubebuilder:default="fail"
    // +kubebuilder:validation:Enum=fail;ignore
    FailurePolicy string `json:"failurePolicy,omitempty"`
}
```

### Template Variables

Auxiliary resource templates support Go templating with these variables:

| Variable                     | Description              | Example                 |
| ---------------------------- | ------------------------ | ----------------------- |
| `{{ .Session.Name }}`        | DebugSession name        | `debug-session-abc123`  |
| `{{ .Session.Namespace }}`   | DebugSession namespace   | `breakglass-system`     |
| `{{ .Session.Cluster }}`     | Target cluster name      | `prod-cluster-a`        |
| `{{ .Session.RequestedBy }}` | Requesting user          | `user@example.com`      |
| `{{ .TargetNamespace }}`     | Debug pod namespace      | `debug-sessions-prod`   |
| `{{ .Labels }}`              | Standard labels to apply | `map[string]string`     |
| `{{ .Annotations }}`         | Standard annotations     | `map[string]string`     |

### Example: NetworkPolicy Auxiliary Resource

```yaml
apiVersion: breakglass.telekom.de/v1alpha1
kind: DebugSessionTemplate
metadata:
  name: isolated-debug
spec:
  # ... standard fields ...
  
  auxiliaryResources:
    - name: egress-network-policy
      createBefore: true
      deleteAfter: true
      failurePolicy: fail
      template:
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        metadata:
          name: "debug-egress-{{ .Session.Name }}"
          namespace: "{{ .TargetNamespace }}"
          labels: "{{ .Labels | toYaml | nindent 12 }}"
        spec:
          podSelector:
            matchLabels:
              breakglass.telekom.de/session: "{{ .Session.Name }}"
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
      createBefore: true
      deleteAfter: true
      template:
        apiVersion: v1
        kind: ServiceAccount
        metadata:
          name: "debug-sa-{{ .Session.Name }}"
          namespace: "{{ .TargetNamespace }}"
          labels: "{{ .Labels | toYaml | nindent 12 }}"
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

Cluster bindings can restrict this further:

```yaml
spec:
  auxiliaryResources:
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

---

## Complete DebugSessionClusterBinding CRD

```go
// +kubebuilder:object:root=true
// +kubebuilder:subresource:status
// +kubebuilder:resource:shortName=dscb
// +kubebuilder:printcolumn:name="Template",type=string,JSONPath=`.spec.templateRef.name`
// +kubebuilder:printcolumn:name="Clusters",type=string,JSONPath=`.status.matchedClusters`
// +kubebuilder:printcolumn:name="Priority",type=integer,JSONPath=`.spec.priority`
// +kubebuilder:printcolumn:name="Age",type=date,JSONPath=`.metadata.creationTimestamp`

// DebugSessionClusterBinding binds a DebugSessionTemplate to specific clusters
// with cluster-specific permissions, constraints, and resources.
// Bindings are namespaced resources, typically created in the same namespace
// as the DebugSessionTemplate they reference.
type DebugSessionClusterBinding struct {
    metav1.TypeMeta   `json:",inline"`
    metav1.ObjectMeta `json:"metadata,omitempty"`
    
    Spec   DebugSessionClusterBindingSpec   `json:"spec,omitempty"`
    Status DebugSessionClusterBindingStatus `json:"status,omitempty"`
}

type DebugSessionClusterBindingSpec struct {
    // TemplateRef references the DebugSessionTemplate to bind.
    // If namespace is empty, the binding's namespace is used.
    // +required
    TemplateRef DebugSessionTemplateReference `json:"templateRef"`
    
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
    // +optional
    SchedulingConstraints *SchedulingConstraints `json:"schedulingConstraints,omitempty"`
    
    // Constraints defines session limits for these clusters.
    // Overrides the template's constraints field for matched clusters.
    // +optional
    Constraints *DebugSessionConstraints `json:"constraints,omitempty"`
    
    // TargetNamespace overrides the template's target namespace.
    // +optional
    TargetNamespace string `json:"targetNamespace,omitempty"`
    
    // AuxiliaryResourceOverrides allows enabling/disabling resource categories.
    // Only specify categories you want to change from the template's defaults.
    // e.g., {"rbac": true, "network-isolation": false}
    // +optional
    AuxiliaryResourceOverrides AuxiliaryResourceOverrides `json:"auxiliaryResourceOverrides,omitempty"`
    
    // Disabled temporarily disables this binding without deleting it.
    // +optional
    Disabled bool `json:"disabled,omitempty"`
    
    // Priority determines binding precedence when multiple bindings match.
    // Higher values take precedence. Default is 0.
    // +optional
    // +kubebuilder:default=0
    Priority int32 `json:"priority,omitempty"`
}

type DebugSessionClusterBindingStatus struct {
    // ObservedGeneration is the last observed generation.
    ObservedGeneration int64 `json:"observedGeneration,omitempty"`
    
    // Conditions provide detailed status.
    Conditions []metav1.Condition `json:"conditions,omitempty"`
    
    // MatchedClusters lists clusters this binding currently applies to.
    MatchedClusters []string `json:"matchedClusters,omitempty"`
    
    // ActiveSessions counts active debug sessions using this binding.
    ActiveSessions int32 `json:"activeSessions,omitempty"`
}
```

---

## Template Resolution Algorithm

When a user requests a debug session:

```text
1. Validate user has access to the requested DebugSessionTemplate

2. Find applicable DebugSessionClusterBindings:
   - Match binding.spec.clusters (glob) against request.cluster
   - Match binding.spec.clusterSelector against ClusterConfig labels
   - Filter out disabled bindings
   - Sort by priority (descending)
   - Take the first matching binding

3. If no binding found:
   - Fall back to template's allowed.clusters check (backward compat)
   - If cluster not in allowed.clusters, reject request

4. Merge configuration (later overrides earlier):
   a. DebugPodTemplate base settings
   b. DebugSessionTemplate settings
   c. ClusterBinding settings (mandatory constraints, auxiliary resources)
   d. User request settings (only nodeSelector, if allowed by binding)

5. Validate merged configuration:
   - Ensure scheduling constraints don't conflict
   - Validate auxiliary resource templates
   - Check resource quotas on target cluster

6. Create DebugSession with resolvedTemplate containing merged config
```

---

## Downstream API Design

### Unified Endpoint: Available Debug Sessions

The API must provide a single endpoint that returns everything a user needs to request a debug session:

```text
GET /api/v1/debug-sessions/available
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
      "clusters": [
        {
          "name": "prod-cluster-a",
          "displayName": "Production Cluster A",
          "environment": "production",
          "location": "eu-west-1",
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
            }
          },
          "requiresApproval": true,
          "approverGroups": ["security-team"],
          "canAutoApprove": false
        },
        {
          "name": "dev-cluster-1",
          "displayName": "Development Cluster 1",
          "environment": "development",
          "location": "eu-west-1",
          "constraints": {
            "maxDuration": "8h",
            "defaultDuration": "2h",
            "maxConcurrentSessions": 5,
            "maxRenewals": 3,
            "allowRenewal": true
          },
          "schedulingConstraints": null,
          "requiresApproval": false,
          "approverGroups": [],
          "canAutoApprove": true
        }
      ],
      "auxiliaryResources": [
        {
          "name": "network-policy",
          "description": "Isolates debug pod network traffic",
          "optional": false
        }
      ]
    },
    {
      "name": "privileged-debug",
      "displayName": "Privileged Debug (SRE Only)",
      "description": "Full host access for critical incidents",
      "mode": "workload",
      "clusters": [
        {
          "name": "prod-cluster-a",
          "displayName": "Production Cluster A",
          "constraints": {
            "maxDuration": "1h",
            "maxConcurrentSessions": 1
          },
          "requiresApproval": true,
          "approverGroups": ["sre-leads", "security-team"]
        }
      ]
    }
  ],
  "userInfo": {
    "email": "user@example.com",
    "groups": ["netops-team", "developers"],
    "canApprove": ["netops-debug"]
  }
}
```

#### API Implementation Notes

```go
// AvailableDebugSession represents a template with resolved cluster access
type AvailableDebugSession struct {
    Name              string                    `json:"name"`
    DisplayName       string                    `json:"displayName"`
    Description       string                    `json:"description"`
    Mode              string                    `json:"mode"`
    Clusters          []AvailableCluster        `json:"clusters"`
    AuxiliaryResources []AuxiliaryResourceInfo  `json:"auxiliaryResources,omitempty"`
}

type AvailableCluster struct {
    Name                  string                     `json:"name"`
    DisplayName           string                     `json:"displayName,omitempty"`
    Environment           string                     `json:"environment,omitempty"`
    Location              string                     `json:"location,omitempty"`
    Constraints           *ResolvedConstraints       `json:"constraints"`
    SchedulingConstraints *SchedulingConstraintsSummary `json:"schedulingConstraints,omitempty"`
    RequiresApproval      bool                       `json:"requiresApproval"`
    ApproverGroups        []string                   `json:"approverGroups,omitempty"`
    CanAutoApprove        bool                       `json:"canAutoApprove"`
}

type SchedulingConstraintsSummary struct {
    Summary            string            `json:"summary"`
    DeniedNodeLabels   map[string]string `json:"deniedNodeLabels,omitempty"`
    RequiredNodeLabels map[string]string `json:"requiredNodeLabels,omitempty"`
    AllowedNodePools   []string          `json:"allowedNodePools,omitempty"`
}
```

The backend resolves all bindings and returns only what the user can actually access, with pre-computed constraints per cluster.

---

## Platform Admin Bindings

Platform administrators who need access to all clusters should use **wildcard bindings**:

### Global Binding Example

```yaml
apiVersion: breakglass.telekom.de/v1alpha1
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
  
  # Higher priority than cluster-specific bindings
  priority: 1000
```

### Binding Priority Rules

When multiple bindings match, priority determines which one is used:

| Priority  | Use Case                   | Example                  |
| --------- | -------------------------- | ------------------------ |
| 1000+     | Platform admin overrides   | Global emergency access  |
| 100-999   | Environment-wide defaults  | All production clusters  |
| 1-99      | Cluster-specific settings  | Single cluster config    |
| 0         | Default bindings           | Fallback configuration   |

```yaml
# Environment-wide binding (priority 100)
apiVersion: breakglass.telekom.de/v1alpha1
kind: DebugSessionClusterBinding
metadata:
  name: production-defaults
spec:
  templateRef:
    name: netops-debug
  clusterSelector:
    matchLabels:
      environment: production
  priority: 100
  schedulingConstraints:
    requiredNodeAffinity:
      nodeSelectorTerms:
        - matchExpressions:
            - key: node-role.kubernetes.io/control-plane
              operator: DoesNotExist
---
# Cluster-specific override (priority 50, won't override production-defaults)
apiVersion: breakglass.telekom.de/v1alpha1
kind: DebugSessionClusterBinding
metadata:
  name: prod-cluster-a-specific
spec:
  templateRef:
    name: netops-debug
  clusters:
    - "prod-cluster-a"
  priority: 50
  constraints:
    maxDuration: "1h"  # Stricter than default
```

### Binding Inheritance Model

For complex scenarios, bindings can be layered:

```text
Platform Admin Binding (priority 1000, clusters: ["*"])
    └── Production Binding (priority 100, clusterSelector: env=prod)
        └── Cluster-Specific Binding (priority 50, clusters: ["prod-eu-1"])
```

The highest-priority matching binding wins. For additive behavior (e.g., merging constraints), use a different field:

```yaml
spec:
  # Instead of override, merge with lower-priority bindings
  mergeMode: "additive"  # or "override" (default)
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
apiVersion: breakglass.telekom.de/v1alpha1
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
          namespace: "{{ .TargetNamespace }}"
        spec:
          podSelector:
            matchLabels:
              breakglass.telekom.de/session: "{{ .Session.Name }}"
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
          namespace: "{{ .TargetNamespace }}"
    
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
          namespace: "{{ .TargetNamespace }}"
        roleRef:
          apiGroup: rbac.authorization.k8s.io
          kind: ClusterRole
          name: view
        subjects:
          - kind: ServiceAccount
            name: "debug-sa-{{ .Session.Name }}"
            namespace: "{{ .TargetNamespace }}"
```

### DebugSessionTemplate with Auxiliary Resource Defaults

The DebugSessionTemplate defines which categories are enabled by default:

```yaml
apiVersion: breakglass.telekom.de/v1alpha1
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
apiVersion: breakglass.telekom.de/v1alpha1
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

```go
// AuxiliaryResource in DebugPodTemplate
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
apiVersion: breakglass.telekom.de/v1alpha1
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
apiVersion: breakglass.telekom.de/v1alpha1
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
apiVersion: breakglass.telekom.de/v1alpha1
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
apiVersion: breakglass.telekom.de/v1alpha1
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
  auxiliaryResources:
    - name: debug-network-policy
      createBefore: true
      template:
        apiVersion: networking.k8s.io/v1
        kind: NetworkPolicy
        metadata:
          name: "debug-isolation-{{ .Session.Name }}"
          namespace: "{{ .TargetNamespace }}"
        spec:
          podSelector:
            matchLabels:
              breakglass.telekom.de/session: "{{ .Session.Name }}"
          policyTypes:
            - Ingress
            - Egress
          ingress: []  # Deny all ingress
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

---

## Open Questions

1. **Binding Namespace**: Should bindings be cluster-scoped or namespace-scoped?
   - Cluster-scoped: Easier to manage, matches ClusterConfig
   - Namespace-scoped: Multi-tenancy support, RBAC delegation

2. **Priority Conflicts**: How to handle when multiple bindings have the same priority?
   - Option A: Reject session creation, require explicit priority
   - Option B: Merge all matching bindings (complex)
   - Option C: Use most specific match (glob vs. exact)

3. **Auxiliary Resource Quotas**: Should there be limits on auxiliary resources?
   - Count limit per session
   - Total resource consumption limit

4. **Binding Validation**: Should bindings validate against templates?
   - Warn if template doesn't exist
   - Validate constraint compatibility

---

## Implementation Phases

### Phase 1: Core Framework (4-6 weeks)

- [ ] Add `DebugSessionClusterBinding` CRD
- [ ] Implement binding resolution logic
- [ ] Add `schedulingConstraints` to binding
- [ ] Update debug pod creation to apply constraints
- [ ] Add webhook validation for constraints

### Phase 2: Auxiliary Resources (3-4 weeks)

- [ ] Add `auxiliaryResources` to template and binding
- [ ] Implement template rendering engine
- [ ] Add resource creation/cleanup lifecycle
- [ ] Add allowed/denied resource type filtering

### Phase 3: UI and CLI (2-3 weeks)

- [ ] Update frontend to show binding information
- [ ] Add binding management to CLI (`bgctl binding list/create/delete`)
- [ ] Show active constraints when creating session

### Phase 4: Documentation and Migration (1-2 weeks)

- [ ] Update all documentation
- [ ] Migration guide for existing templates
- [ ] Example library of common bindings

---

## Appendix: Full Type Definitions

See the accompanying `debug_session_cluster_binding_types.go` file for complete Go type definitions.

