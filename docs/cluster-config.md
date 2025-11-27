# ClusterConfig Custom Resource

The `ClusterConfig` custom resource enables the breakglass hub cluster to manage and connect to tenant clusters.

**Type Definition:** [`ClusterConfig`](../api/v1alpha1/cluster_config_types.go)

## Overview

`ClusterConfig` enables the breakglass controller to:

- Connect to managed tenant clusters
- Perform authorization checks (Subject Access Reviews)
- Validate breakglass session permissions

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
- `metadata.name` MUST be unique across **all namespaces**. The controller now enforces globally-unique names and will raise an error if two namespaces contain the same ClusterConfig name. Pick descriptive names that remain unique even when teams manage their own namespaces.

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

### Loopback kubeconfig rewrite

Some bootstrap kubeconfigs (especially from kind) still point to `https://127.0.0.1` or `https://localhost`. Breakglass automatically rewrites those hosts to the in-cluster DNS name `https://kubernetes.default.svc` so SubjectAccessReview calls succeed from the hub cluster. If you need to keep the original host—for example, when running through a proxy—set the environment variable:

```bash
export BREAKGLASS_DISABLE_LOOPBACK_REWRITE=true
```

The flag can be toggled per controller instance and takes effect immediately without a restart.

## Status and Conditions

The `ClusterConfig` status uses **Kubernetes conditions** to convey all state information. This provides a rich, standardized way to track cluster configuration and connectivity.

### Understanding Conditions

Each condition has:
- **Type**: The type of condition (e.g., `Ready`)
- **Status**: `True`, `False`, or `Unknown`
- **Reason**: A programmatic identifier for the state (e.g., `ConfigurationValid`, `ConnectionFailed`)
- **Message**: Human-readable explanation
- **LastTransitionTime**: When the condition last changed

### Standard Conditions

#### Ready
Indicates the ClusterConfig is fully operational with valid kubeconfig and established cluster connection.

```yaml
status:
  conditions:
  - type: Ready
    status: "True"
    reason: "ConfigurationValid"
    message: "ClusterConfig is valid and cluster connection verified"
    lastTransitionTime: "2024-01-15T10:30:00Z"
```

When `False`:
```yaml
  - type: Ready
    status: "False"
    reason: "KubeconfigValidationFailed"
    message: "Kubeconfig secret contains invalid data: invalid certificate"
    lastTransitionTime: "2024-01-15T10:30:00Z"
```

### Viewing Status

Check the status with `kubectl`:

```bash
# Quick status check
kubectl get clusterconfig
# Output columns: NAME | READY | AGE

# Detailed conditions
kubectl describe clusterconfig <name>

# View specific condition
kubectl get clusterconfig <name> -o jsonpath='{.status.conditions[?(@.type=="Ready")]}'
```

### Condition Reasons

| Reason | Status | Description |
|--------|--------|-------------|
| `ConfigurationValid` | True | All configuration is valid and verified |
| `KubeconfigValidationFailed` | False | Referenced kubeconfig secret is invalid or missing |
| `ConnectionFailed` | False | Cannot connect to target cluster |
| `AuthorizationCheckFailed` | False | Cluster connection lacks required permissions |
| `ReconciliationInProgress` | Unknown | Configuration is being validated |

### Example Status Output

```yaml
status:
  observedGeneration: 2
  conditions:
  - type: Ready
    status: "True"
    reason: "ConfigurationValid"
    message: "ClusterConfig verified and operational"
    observedGeneration: 2
    lastTransitionTime: "2024-01-15T10:30:00Z"
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

- Use admin-level credentials only for the breakglass service account
- Rotate kubeconfig credentials regularly
- Store secrets securely with appropriate RBAC
- Use TLS for all communications

### Performance

- Set appropriate `qps` and `burst` based on cluster size
- Use close network proximity between hub and tenant clusters
- Monitor connectivity

### Management

- Use descriptive names reflecting purpose and environment
- Include metadata (`tenant`, `environment`, `location`)
- Monitor `ClusterConfig` status regularly

### Cache invalidation and secret tracking

- Breakglass registers controller-runtime informers for `ClusterConfig` objects and referenced kubeconfig Secrets. Any update/delete automatically invalidates cached metadata and REST configs, so you no longer need to restart the controller after editing kubeconfigs.
- Secrets referenced by one or more ClusterConfigs are tracked. When a Secret changes, all dependent clusters are refreshed immediately.
- REST config secrets default to the `value` key; customize with `spec.kubeconfigSecretRef.key` when you store multiple kubeconfigs in one Secret.

## Troubleshooting

### Checking Cluster Status

Always check the conditions first to diagnose issues:

```bash
# Get detailed status with conditions
kubectl describe clusterconfig <name>

# Export full status
kubectl get clusterconfig <name> -o yaml
```

### Common Issues

#### Ready Condition: False (KubeconfigValidationFailed)

**Cause:** The referenced kubeconfig secret doesn't exist or contains invalid data.

**Diagnosis:**
```bash
# Check if secret exists
kubectl get secret <secret-name> -n <namespace>

# Verify secret format
kubectl get secret <secret-name> -n <namespace> -o yaml | grep kubeconfig
```

**Solution:**
- Ensure the Secret exists in the specified namespace
- Verify the kubeconfig key name (defaults to `kubeconfig`)
- Validate kubeconfig syntax with `kubectl config view`

#### Ready Condition: False (ConnectionFailed)

**Cause:** Cannot establish connection to the target cluster.

**Diagnosis:**
```bash
# Test kubeconfig connectivity
kubectl get secret <secret-name> -n <namespace> -o jsonpath='{.data.kubeconfig}' | base64 -d > /tmp/test.kubeconfig
kubectl --kubeconfig=/tmp/test.kubeconfig cluster-info
```

**Solution:**
- Verify network connectivity between hub and tenant clusters
- Check DNS resolution for cluster endpoints
- Ensure firewall rules allow API server access
- Verify kubeconfig server URL is correct

#### Ready Condition: False (AuthorizationCheckFailed)

**Cause:** Kubeconfig has insufficient permissions.

**Diagnosis:**
```bash
# Test authorization on target cluster
kubectl --kubeconfig=/tmp/test.kubeconfig auth can-i '*' '*'
```

**Solution:**
- Ensure kubeconfig provides admin or cluster-admin permissions
- Verify RBAC roles/bindings are correctly configured
- Check if service account tokens have expired

### Debugging Commands

```bash
# Show all ClusterConfigs with status
kubectl get clusterconfig -o wide

# Watch for status changes
kubectl get clusterconfig -w

# Export for analysis
kubectl get clusterconfig <name> -o json | jq '.status'

# Get only conditions
kubectl get clusterconfig <name> -o jsonpath='{.status.conditions}'

# Monitor events related to ClusterConfig
kubectl get events --field-selector involvedObject.name=<name>,involvedObject.kind=ClusterConfig
```

### Performance Tuning

If you notice slow API calls:

1. **Check QPS settings:**
   ```bash
   kubectl get clusterconfig <name> -o jsonpath='{.spec.qps}'
   ```

2. **Increase burst capacity if needed:**
   ```yaml
   spec:
     qps: 200    # Increase from default
     burst: 400  # Increase from default
   ```

3. **Monitor actual usage:**
   - Watch for API rate limiting errors in ClusterConfig conditions
   - Adjust based on workload patterns

## Related Resources

- [BreakglassSession](./breakglass-session.md) - Session management
- [BreakglassEscalation](./breakglass-escalation.md) - Escalation policies  
- [DenyPolicy](./deny-policy.md) - Access restrictions
- [Webhook Setup](./webhook-setup.md) - Authorization webhook configuration
