# Escalation Config Helm Chart

Helm chart for deploying BreakglassEscalation and ClusterConfig custom resources to the breakglass system.

## Overview

This chart simplifies the configuration of privilege escalation policies by providing a declarative way to create:

- **ClusterConfig** - Defines tenant cluster connections (kubeconfig or OIDC auth)
- **BreakglassEscalation** - Defines escalation policies with allowed groups, approvers, and settings
- **DebugSessionClusterBinding** - Connects debug session templates to specific clusters with optional overrides
- **DenyPolicy** - Defines rules that block specific actions during breakglass sessions

## Prerequisites

- Kubernetes 1.24+
- Helm 3.0+
- Breakglass controller installed and running
- CRDs installed (BreakglassEscalation, ClusterConfig, DebugSessionClusterBinding, DenyPolicy)

## Installation

### Basic Installation

```bash
helm install my-escalation ./charts/escalation-config -f values.yaml
```

### Installation with Custom Values

```bash
helm install my-escalation ./charts/escalation-config \
  --set cluster.clusterID=production-cluster \
  --set cluster.tenant=production
```

## Configuration

### Cluster Configuration

The `cluster` section defines the target cluster connection:

| Parameter | Description | Default |
|-----------|-------------|---------|
| `cluster.clusterID` | Unique identifier for the cluster | `tenant-b-virtual-test` |
| `cluster.tenant` | Tenant name | `tenant-b` |
| `cluster.environment` | Environment label | `development` |
| `cluster.site` | Site label (optional) | - |
| `cluster.location` | Location label (optional) | - |

#### Kubeconfig Authentication (Default)

```yaml
cluster:
  clusterID: production-cluster
  tenant: production
  kubeconfigSecretRef:
    name: cluster-kubeconfig
    namespace: default
    key: value  # Optional, defaults to "value" for Cluster API compatibility
```

#### OIDC Authentication

**Direct OIDC Configuration:**

```yaml
cluster:
  clusterID: production-cluster
  authType: OIDC
  oidcAuth:
    issuerURL: https://keycloak.example.com/realms/kubernetes
    clientID: breakglass-controller
    server: https://api.cluster.example.com:6443
    clientSecretRef:
      name: oidc-client-secret
      namespace: breakglass-system
      key: client-secret
    caSecretRef:
      name: cluster-ca
      namespace: breakglass-system
      key: ca.crt
    scopes:
      - groups
      - email
```

**OIDC from IdentityProvider Reference:**

```yaml
cluster:
  clusterID: production-cluster
  authType: OIDC
  oidcFromIdentityProvider:
    name: my-keycloak-idp
    server: https://api.cluster.example.com:6443
    clientSecretRef:
      name: cluster-client-secret
      namespace: breakglass-system
```

### Escalation Policies

The `escalations` array defines privilege escalation policies:

```yaml
escalations:
  - name: production-admin-access
    allowed:
      clusters:
        - production-cluster
      groups:
        - platform-engineers
        - sre-team
      users:
        - emergency@example.com
    escalatedGroup: cluster-admin
    approvers:
      groups:
        - senior-sre
      users:
        - manager@example.com
    maxValidFor: 2h
    retainFor: 168h  # 7 days
    requestReason:
      mandatory: true
      description: "Provide incident ticket or justification"
    blockSelfApproval: true
```

### Escalation Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `name` | Unique escalation name | Required |
| `allowed.clusters` | Clusters this escalation applies to | - |
| `allowed.groups` | Groups allowed to request | Required |
| `escalatedGroup` | Target group for elevated privileges | Required |
| `approvers.groups` | Groups that can approve requests | - |
| `approvers.users` | Individual users that can approve | - |
| `approvers.hiddenFromUI` | Approver groups hidden from UI | - |
| `maxValidFor` | Maximum session duration | `1h` |
| `retainFor` | Session retention for audit | `24h` |
| `approvalTimeout` | Auto-expire pending requests | - |
| `requestReason.mandatory` | Require reason for requests | `false` |
| `requestReason.description` | Reason field description | - |
| `blockSelfApproval` | Prevent self-approval | `false` |
| `disableNotifications` | Disable email notifications | `false` |
| `clusterConfigRefs` | Alternative to `allowed.clusters` | - |
| `denyPolicyRefs` | Attach DenyPolicy restrictions | - |
| `mailProvider` | Specific mail provider to use | - |

### Multi-IDP Configuration

For organizations with multiple identity providers:

```yaml
escalations:
  - name: multi-idp-escalation
    # ... other config
    # Option 1: Single list (all listed IDPs can request AND approve)
    allowedIdentityProviders:
      - corporate-oidc
      - external-keycloak
    
    # Option 2: Split lists (fine-grained control)
    # allowedIdentityProvidersForRequests:
    #   - corporate-oidc
    #   - external-keycloak
    # allowedIdentityProvidersForApprovers:
    #   - corporate-oidc  # Only corporate users can approve
```

### Glob Patterns

Cluster references support glob patterns:

```yaml
escalations:
  - name: global-escalation
    clusterConfigRefs:
      - "*"  # All clusters
      - "prod-*"  # All production clusters
      - "*-staging"  # All staging clusters
```

### Pod Security Overrides

For escalations that need to bypass DenyPolicy restrictions:

```yaml
escalations:
  - name: security-override-escalation
    # ... other config
    podSecurityOverrides:
      enabled: true
      maxAllowedScore: 150
      exemptFactors:
        - privilegedContainer
        - hostNetwork
      namespaceScope:
        patterns:
          - "kube-system"
          - "critical-*"
      requireApproval: true
      approvers:
        groups:
          - security-team
```

### Debug Session Cluster Bindings

The `debugSessionBindings` array connects DebugSessionTemplates to specific clusters with optional overrides:

```yaml
debugSessionBindings:
  - name: production-debug-access
    displayName: "Production Debug Access"
    description: "Debug sessions for production clusters"
    
    # Reference a template by name
    templateRef:
      name: standard-debug-template
    
    # Target specific clusters
    clusters:
      - prod-cluster-1
      - prod-cluster-2
    
    # Override access control
    allowed:
      groups:
        - sre-team
    approvers:
      groups:
        - senior-sre
      # Auto-approve for specific groups/clusters
      # autoApproveFor:
      #   groups:
      #     - oncall-sre
      #   clusters:
      #     - dev-*
    
    # Add scheduling constraints
    schedulingConstraints:
      nodeSelector:
        node-pool: debug-nodes
      topologySpreadConstraints:
        - maxSkew: 1
          topologyKey: topology.kubernetes.io/zone
          whenUnsatisfiable: ScheduleAnyway
    
    # Session constraints
    constraints:
      maxDuration: "2h"
      defaultDuration: "30m"
    
    # Namespace constraints
    namespaceConstraints:
      defaultNamespace: debug-workloads
      allowUserNamespace: false
    
    # Reason requirements
    requestReason:
      mandatory: true
      description: "Provide incident ticket"
    
    # Session limits
    maxActiveSessionsPerUser: 1
    maxActiveSessionsTotal: 5
```

### Debug Session Binding Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `name` | Unique binding name | Required |
| `displayName` | Human-readable name for UI | - |
| `description` | Description of this binding | - |
| `templateRef.name` | Reference to a DebugSessionTemplate | - |
| `templateSelector` | Label selector for multiple templates | - |
| `clusters` | List of target cluster names | - |
| `clusterSelector` | Label selector for clusters | - |
| `allowed.groups` | Groups allowed to use this binding | - |
| `allowed.users` | Individual users allowed | - |
| `approvers.groups` | Groups that can approve | - |
| `approvers.users` | Individual approvers | - |
| `approvers.autoApproveFor` | Auto-approve config for specific groups/clusters | - |
| `schedulingConstraints` | Node scheduling rules | - |
| `schedulingOptions` | User-selectable scheduling options | - |
| `constraints.maxDuration` | Maximum session duration | - |
| `constraints.defaultDuration` | Default session duration | - |
| `namespaceConstraints` | Namespace deployment rules | - |
| `impersonation` | ServiceAccount impersonation config | - |
| `requiredAuxiliaryResourceCategories` | Required auxiliary resources | - |
| `auxiliaryResourceOverrides` | Enable/disable auxiliary resources | - |
| `allowedPodOperations.exec` | Allow kubectl exec | `true` |
| `allowedPodOperations.attach` | Allow kubectl attach | `true` |
| `allowedPodOperations.logs` | Allow kubectl logs | `false` |
| `allowedPodOperations.portForward` | Allow kubectl port-forward | `true` |
| `requestReason.mandatory` | Require reason for requests | `false` |
| `maxActiveSessionsPerUser` | Max concurrent sessions per user | - |
| `maxActiveSessionsTotal` | Max total concurrent sessions | - |
| `priority` | UI ordering priority | - |
| `disabled` | Temporarily disable binding | `false` |
| `hidden` | Hide from UI | `false` |
| `effectiveFrom` | When binding becomes active | - |
| `expiresAt` | When binding expires | - |

### Allowed Pod Operations Example

Create a read-only binding that only allows viewing logs:

```yaml
debugSessionBindings:
  - name: logs-only-access
    templateRef:
      name: debug-template
    clusters:
      - production-cluster
    allowedPodOperations:
      exec: false       # Disable kubectl exec
      attach: false     # Disable kubectl attach
      logs: true        # Enable kubectl logs
      portForward: false # Disable port forwarding
    allowed:
      groups:
        - developers
```

### Template Selector Example

To apply a binding to multiple templates:

```yaml
debugSessionBindings:
  - name: all-dev-templates
    templateSelector:
      matchLabels:
        tier: development
    displayNamePrefix: "[DEV] "
    clusters:
      - dev-cluster
    constraints:
      maxDuration: "4h"  # More permissive for dev
```

### Scheduling Options Example

Offer users a choice of node pools:

```yaml
debugSessionBindings:
  - name: multi-pool-binding
    templateRef:
      name: flexible-template
    clusters:
      - multi-pool-cluster
    schedulingOptions:
      required: true
      options:
        - name: standard
          displayName: "Standard Nodes"
          schedulingConstraints:
            nodeSelector:
              node-type: standard
        - name: high-memory
          displayName: "High Memory Nodes"
          schedulingConstraints:
            nodeSelector:
              node-type: high-memory
```

### Deny Policies

The `denyPolicies` array defines rules that block specific actions during breakglass sessions:

```yaml
denyPolicies:
  - name: block-dangerous-ops
    appliesTo:
      clusters:
        - prod-cluster-1
        - prod-cluster-2
    rules:
      # Block namespace deletion
      - verbs:
          - delete
        apiGroups:
          - ""
        resources:
          - namespaces
      # Block secret access in kube-system
      - verbs:
          - "*"
        apiGroups:
          - ""
        resources:
          - secrets
        namespaces:
          patterns:
            - kube-system
    precedence: 50
```

### Deny Policy Parameters

| Parameter | Description | Default |
|-----------|-------------|---------|
| `name` | Unique policy name | Required |
| `appliesTo.clusters` | Clusters this policy applies to | - |
| `appliesTo.tenants` | Tenants this policy applies to | - |
| `appliesTo.sessions` | Specific sessions this policy applies to | - |
| `rules` | Array of deny rules | - |
| `rules[].verbs` | HTTP verbs to block (get, list, create, delete, etc.) | Required |
| `rules[].apiGroups` | API groups ("" for core) | Required |
| `rules[].resources` | Resource types (plural) | Required |
| `rules[].namespaces` | Namespace filter (patterns/selectorTerms) | - |
| `rules[].resourceNames` | Specific resource names | - |
| `rules[].subresources` | Subresources to match | - |
| `podSecurityRules` | Risk-based pod exec evaluation | - |
| `precedence` | Policy priority (lower wins) | `100` |

### Pod Security Rules Example

Block exec to high-risk pods based on their security configuration:

```yaml
denyPolicies:
  - name: pod-security-policy
    appliesTo:
      clusters:
        - "*"
    podSecurityRules:
      riskFactors:
        hostNetwork: 50
        hostPID: 40
        privilegedContainer: 100
        hostPathWritable: 80
        runAsRoot: 25
      thresholds:
        - maxScore: 50
          action: allow
        - maxScore: 100
          action: warn
        - maxScore: 1000
          action: deny
          reason: "Pod risk score {{.Score}} exceeds threshold"
      exemptions:
        namespaces:
          patterns:
            - kube-system
            - monitoring
      failMode: closed
```

## Examples

### Minimal Configuration

```yaml
cluster:
  clusterID: my-cluster
  tenant: my-tenant
  kubeconfigSecretRef:
    name: my-cluster-kubeconfig
    namespace: default

escalations:
  - name: basic-escalation
    allowed:
      clusters:
        - my-cluster
      groups:
        - developers
    escalatedGroup: namespace-admin
    approvers:
      groups:
        - team-leads
```

### Production Configuration

```yaml
cluster:
  clusterID: production
  tenant: platform
  environment: production
  site: eu-west
  kubeconfigSecretRef:
    name: prod-kubeconfig
    namespace: breakglass-system
  blockSelfApproval: true
  allowedApproverDomains:
    - company.com

escalations:
  - name: prod-incident-response
    allowed:
      clusters:
        - production
      groups:
        - sre-oncall
        - platform-engineers
    escalatedGroup: cluster-admin
    approvers:
      groups:
        - sre-leads
        - security-team
    maxValidFor: 4h
    retainFor: 720h  # 30 days
    approvalTimeout: 1h
    requestReason:
      mandatory: true
      description: "Incident ID and brief description required"
    approvalReason:
      mandatory: true
      description: "Approval justification"
    blockSelfApproval: true
    notificationExclusions:
      groups:
        - automation-bots
```

## Upgrading

```bash
helm upgrade my-escalation ./charts/escalation-config -f values.yaml
```

## Uninstalling

```bash
helm uninstall my-escalation
```

**Note:** This will delete the ClusterConfig and BreakglassEscalation resources. Active sessions will continue until they expire.

## Troubleshooting

### Common Issues

1. **Escalation not appearing** - Verify CRDs are installed:
   ```bash
   kubectl get crd breakglassescalations.breakglass.t-caas.telekom.com
   ```

2. **Authentication failures** - Check kubeconfig secret exists:
   ```bash
   kubectl get secret <secret-name> -n <namespace>
   ```

3. **OIDC token errors** - Verify issuer URL and client credentials

### Debugging

Check controller logs for escalation validation errors:

```bash
kubectl logs -l app=breakglass -n breakglass-system
```

## Related Documentation

- [BreakglassEscalation Reference](../docs/breakglass-escalation.md)
- [ClusterConfig Reference](../docs/cluster-config.md)
- [Identity Provider Configuration](../docs/identity-provider.md)
- [DenyPolicy Configuration](../docs/deny-policy.md)
- [Multi-IDP Guide](../docs/advanced-features.md#multi-idp-configuration-guide)
