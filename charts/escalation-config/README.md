# Escalation Config Helm Chart

Helm chart for deploying BreakglassEscalation and ClusterConfig custom resources to the breakglass system.

## Overview

This chart simplifies the configuration of privilege escalation policies by providing a declarative way to create:

- **ClusterConfig** - Defines tenant cluster connections (kubeconfig or OIDC auth)
- **BreakglassEscalation** - Defines escalation policies with allowed groups, approvers, and settings

## Prerequisites

- Kubernetes 1.24+
- Helm 3.0+
- Breakglass controller installed and running
- CRDs installed (BreakglassEscalation, ClusterConfig)

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
    key: kubeconfig  # Optional, defaults to "kubeconfig"
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
| `allowed.users` | Individual users allowed to request | - |
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
