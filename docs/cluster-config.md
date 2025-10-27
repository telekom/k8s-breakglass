# ClusterConfig Custom Resource

The `ClusterConfig` custom resource enables the breakglass hub cluster to manage and connect to tenant clusters for authorization checks and breakglass session management.

## Overview

`ClusterConfig` defines metadata and authentication details for managed tenant clusters, allowing the breakglass controller to:

- Perform Subject Access Reviews (SAR) on target clusters
- Validate breakglass session permissions
- Enable cross-cluster authorization decisions

## Resource Definition

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: <cluster-name>
spec:
  # Required: Reference to kubeconfig secret
  kubeconfigSecretRef:
    name: <secret-name>
    namespace: <secret-namespace>
    key: kubeconfig  # Optional, defaults to "kubeconfig"
  
  # Optional: Cluster identification
  clusterID: <canonical-cluster-id>  # Defaults to metadata.name
  tenant: <tenant-name>              # Can be parsed from clusterID
  environment: <env>                 # e.g., dev, staging, prod
  site: <site-name>
  location: <region>
  
  # Optional: Client configuration
  qps: 100      # Queries per second limit
  burst: 200    # Burst capacity
```

## Required Fields

### kubeconfigSecretRef

References a Kubernetes Secret containing an admin-level kubeconfig for the target cluster.

```yaml
kubeconfigSecretRef:
  name: tenant-cluster-admin      # Secret name
  namespace: default              # Secret namespace  
  key: kubeconfig                # Secret key (optional, defaults to "kubeconfig")
```

**Requirements:**

- The referenced Secret MUST exist in the specified namespace
- The kubeconfig MUST provide admin-level access to the target cluster
- The kubeconfig should be valid and accessible from the hub cluster

## Optional Fields

### Cluster Identification

```yaml
clusterID: "t-caas-prod-eu-west-1"  # Canonical cluster identifier
tenant: "my-tenant"                  # Tenant name override
environment: "prod"                  # Environment classification
site: "eu-west"                     # Site/datacenter identifier
location: "eu-west-1"               # Region/location
```

### Client Configuration

```yaml
qps: 100    # Maximum queries per second to target cluster
burst: 200  # Maximum burst capacity for API calls
```

## Status Fields

The `ClusterConfig` status provides information about connectivity and health:

```yaml
status:
  phase: "Ready"                           # Ready, Failed, Unknown
  message: "Successfully connected"        # Details about current state
  lastCheckTime: "2024-01-15T10:30:00Z"  # Last connectivity check
```

## Complete Example

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: tenant-prod-admin
  namespace: default
type: Opaque
data:
  kubeconfig: <base64-encoded-kubeconfig>
---
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: tenant-prod-cluster
spec:
  clusterID: "t-caas-prod-eu-west-1"
  tenant: "my-tenant"
  environment: "prod"
  site: "eu-west"
  location: "eu-west-1"
  kubeconfigSecretRef:
    name: tenant-prod-admin
    namespace: default
  qps: 100
  burst: 200
```

## Usage in Breakglass Sessions

When creating a `BreakglassSession`, the `cluster` field must reference an existing `ClusterConfig`:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassSession
metadata:
  name: emergency-access
spec:
  cluster: tenant-prod-cluster  # Must match ClusterConfig name
  user: user@example.com
  grantedGroup: cluster-admin
```

## Usage in Breakglass Escalations

`BreakglassEscalation` resources can reference clusters by their ClusterConfig names:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: BreakglassEscalation
metadata:
  name: prod-emergency-access
spec:
  escalatedGroup: "cluster-admin"
  allowed:
    clusters: ["tenant-prod-cluster"]  # ClusterConfig names
    groups: ["emergency-responders"]
  approvers:
    users: ["admin@example.com"]
```

## Webhook Integration

For clusters using the breakglass authorization webhook, configure the API server with:

```yaml
# authorization-config.yaml
apiVersion: apiserver.config.k8s.io/v1beta1
kind: AuthorizationConfiguration
authorizers:
  - type: Webhook
    name: breakglass
    webhook:
      timeout: 3s
      connectionInfo:
        type: KubeConfigFile
        kubeConfigFile: /etc/kubernetes/breakglass-webhook-kubeconfig.yaml
      matchConditions: 
        - expression: "'system:authenticated' in request.groups"
        - expression: "!request.user.startsWith('system:')"
```

The webhook kubeconfig should point to the breakglass service:

```yaml
# breakglass-webhook-kubeconfig.yaml
apiVersion: v1
kind: Config
clusters:
  - name: breakglass
    cluster:
      server: https://breakglass.example.com/api/breakglass/webhook/authorize/<cluster-name>
      certificate-authority-data: <ca-cert>
users:
  - name: kube-apiserver
    user:
      token: <webhook-token>
contexts:
  - name: webhook
    context:
      cluster: breakglass
      user: kube-apiserver
current-context: webhook
```

## Best Practices

### Security

- Use dedicated service accounts with minimal required permissions for kubeconfig
- Rotate kubeconfig credentials regularly
- Store secrets securely with appropriate RBAC restrictions
- Use TLS for all cluster communications

### Performance

- Set appropriate `qps` and `burst` values based on cluster size and expected load
- Monitor cluster connectivity and adjust timeouts if needed
- Use regional proximity between hub and tenant clusters when possible

### Management

- Use descriptive names that reflect cluster purpose and environment
- Include metadata fields (`tenant`, `environment`, `location`) for easier management
- Implement monitoring for `ClusterConfig` status and connectivity
- Maintain documentation of cluster relationships and dependencies

## Troubleshooting

### Common Issues

#### ClusterConfig Phase: "Failed"

- Check if the referenced Secret exists and contains valid kubeconfig
- Verify network connectivity between hub and tenant clusters
- Ensure kubeconfig provides sufficient permissions for SAR operations

#### Connection Timeouts

- Increase `qps` and `burst` values if cluster is under heavy load
- Check network latency and firewall rules
- Verify DNS resolution for cluster endpoints

#### Permission Denied

- Ensure kubeconfig contains admin-level permissions
- Check if RBAC is properly configured on target cluster
- Verify service account tokens are not expired

### Debugging Commands

```bash
# Check ClusterConfig status
kubectl get clusterconfig <name> -o yaml

# Verify referenced secret
kubectl get secret <secret-name> -n <namespace>

# Test connectivity manually
kubectl --kubeconfig=<extracted-kubeconfig> auth can-i '*' '*'
```

## Related Resources

- [BreakglassSession](./breakglass-session.md) - Session management
- [BreakglassEscalation](./breakglass-escalation.md) - Escalation policies  
- [DenyPolicy](./deny-policy.md) - Access restrictions
- [Webhook Setup](./webhook-setup.md) - Authorization webhook configuration
