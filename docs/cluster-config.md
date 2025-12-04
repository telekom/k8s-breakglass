# ClusterConfig Custom Resource

The `ClusterConfig` custom resource enables the breakglass hub cluster to manage and connect to tenant clusters.

**Type Definition:** [`ClusterConfig`](../api/v1alpha1/cluster_config_types.go)

## Overview

`ClusterConfig` enables the breakglass controller to:

- Connect to managed tenant clusters
- Perform authorization checks (Subject Access Reviews)
- Validate breakglass session permissions

## Authentication Methods

ClusterConfig supports two authentication methods for connecting to managed clusters:

1. **Kubeconfig-based authentication** (traditional) - Uses a kubeconfig file stored in a Secret
2. **OIDC-based authentication** - Uses OIDC tokens obtained via client credentials flow

Only one authentication method can be configured per ClusterConfig. The method is determined by either:
- The `authType` field (explicit)
- The presence of `kubeconfigSecretRef` or `oidcAuth` fields (implicit)

## Resource Definition

### Using Kubeconfig Authentication (Default)

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: <cluster-name>
spec:
  # Optional: Explicit auth type (defaults to Kubeconfig if kubeconfigSecretRef is present)
  authType: Kubeconfig
  
  # Required for kubeconfig auth: Reference to kubeconfig secret
  kubeconfigSecretRef:
    name: <secret-name>
    namespace: <secret-namespace>
    key: value  # Optional, defaults to "value" for Cluster API compatibility
  
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

### Using OIDC Authentication

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: <cluster-name>
spec:
  # Required: Set auth type to OIDC
  authType: OIDC
  
  # Required for OIDC auth: OIDC configuration
  oidcAuth:
    # Required: OIDC issuer URL (must match cluster API server OIDC config)
    issuerURL: https://keycloak.example.com/realms/kubernetes
    
    # Required: OIDC client ID registered for the breakglass controller
    clientID: breakglass-controller
    
    # Required: Reference to secret containing client secret
    clientSecretRef:
      name: <secret-name>
      namespace: <secret-namespace>
      key: client-secret  # Optional, defaults to "client-secret"
    
    # Required: Target cluster's API server URL
    server: https://my-cluster.example.com:6443
    
    # Optional: CA certificate for the cluster API server
    caSecretRef:
      name: <ca-secret-name>
      namespace: <secret-namespace>
      key: ca.crt  # Optional, defaults to "ca.crt"
    
    # Optional: Token audience (defaults to server URL)
    audience: https://my-cluster.example.com:6443
    
    # Optional: Additional OIDC scopes to request
    scopes:
      - groups
      - email
    
    # Optional: Enable token exchange flow (RFC 8693)
    # Use this when you need to exchange a service token for a cluster-scoped token
    tokenExchange:
      enabled: true
      subjectTokenSecretRef:
        name: service-account-token
        namespace: breakglass-system
        key: token
      resource: https://my-cluster.example.com:6443
  
  # Optional: Cluster identification (same as kubeconfig auth)
  clusterID: <canonical-cluster-id>
  
  # Optional: Restrict which IdentityProviders can authenticate users for this cluster
  identityProviderRefs:
    - my-keycloak-idp
  
  # Optional: Client configuration
  qps: 100
  burst: 200
```

## Understanding OIDC in Breakglass

Breakglass uses OIDC in **two distinct ways**:

1. **User Authentication (IdentityProvider)**: Users authenticate to the Breakglass UI/API via OIDC. This is configured through `IdentityProvider` resources.

2. **Cluster Authentication (ClusterConfig.oidcAuth)**: The breakglass controller authenticates to managed clusters via OIDC client credentials. This is configured in `ClusterConfig.spec.oidcAuth`.

These are independent configurations that can use the same or different OIDC providers.

```
┌─────────────────────────────────────────────────────────────────────┐
│                         User Authentication                          │
│  User → Keycloak → Breakglass UI/API (IdentityProvider)              │
└─────────────────────────────────────────────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────┐
│                       Cluster Authentication                         │
│  Breakglass Controller → Keycloak → Target Cluster API (oidcAuth)    │
└─────────────────────────────────────────────────────────────────────┘
```

### Linking Clusters to Identity Providers

Use `identityProviderRefs` to restrict which IdentityProviders can authenticate users for a specific cluster:

```yaml
spec:
  # Only users authenticated via 'corp-keycloak' can access this cluster
  identityProviderRefs:
    - corp-keycloak
```

If `identityProviderRefs` is empty or omitted, all enabled IdentityProviders are accepted.

## Authentication Method Details

### Kubeconfig Authentication

The traditional method using a kubeconfig file stored in a Secret.

**kubeconfigSecretRef**

References a Kubernetes Secret containing an admin-level kubeconfig for the target cluster.

```yaml
kubeconfigSecretRef:
  name: tenant-cluster-admin      # Secret name
  namespace: default              # Secret namespace  
  key: value                      # Secret key (optional, defaults to "value")
```

**Requirements:**

- The referenced Secret MUST exist in the specified namespace
- The kubeconfig MUST provide admin-level access to the target cluster
- The kubeconfig should be valid and accessible from the hub cluster
- `metadata.name` MUST be unique across **all namespaces**. The controller now enforces globally-unique names and will raise an error if two namespaces contain the same ClusterConfig name. Pick descriptive names that remain unique even when teams manage their own namespaces.

### OIDC Authentication

OIDC authentication allows the breakglass controller to obtain tokens from an OIDC provider (like Keycloak) instead of using static kubeconfig credentials. This is useful when:

- You want to avoid storing long-lived credentials
- The managed cluster's API server supports OIDC authentication
- You're using a centralized identity provider

**oidcAuth Configuration**

| Field | Required | Description |
|-------|----------|-------------|
| `issuerURL` | Yes | OIDC issuer URL (must match cluster API server config) |
| `clientID` | Yes | OIDC client ID for the breakglass controller |
| `clientSecretRef` | Yes | Reference to secret containing client secret |
| `server` | Yes | URL of the target cluster's API server |
| `caSecretRef` | No | CA certificate for the cluster API server |
| `insecureSkipTLSVerify` | No | Skip TLS verification (NOT for production) |
| `audience` | No | Token audience (defaults to server) |
| `scopes` | No | Additional OIDC scopes to request |
| `tokenExchange` | No | Token exchange configuration |

**Prerequisites for OIDC:**

1. The target cluster's API server must be configured to accept OIDC tokens:
   ```yaml
   # kube-apiserver flags
   --oidc-issuer-url=https://keycloak.example.com/realms/kubernetes
   --oidc-client-id=kubernetes
   --oidc-username-claim=preferred_username
   --oidc-groups-claim=groups
   ```

2. A client must be registered in your OIDC provider for the breakglass controller
3. The client must have permissions to use the client credentials grant

### Keycloak Setup for Cluster OIDC Authentication

To use OIDC authentication with Keycloak, you need to configure a **service account client** that the breakglass controller uses to authenticate to managed clusters.

**Step 1: Create a Keycloak Client**

```
1. Go to Keycloak Admin Console → Your Realm → Clients → Create
2. Client ID: `breakglass-controller`
3. Client Protocol: `openid-connect`
4. Access Type: `confidential`
5. Service Accounts Enabled: `ON`
6. Direct Access Grants Enabled: `ON` (for client credentials flow)
```

**Step 2: Configure Client Credentials**

```
1. Go to Client → Credentials tab
2. Copy the Client Secret
3. Create a Kubernetes Secret:
```

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: oidc-client-secret
  namespace: breakglass-system
type: Opaque
stringData:
  client-secret: <your-client-secret>
```

**Step 3: Configure Token Mappers (Optional)**

If you need specific claims in the token:

```
1. Go to Client → Mappers → Add Builtin
2. Add: groups, preferred_username, email
3. Or create custom mappers for your use case
```

**Step 4: Configure the ClusterConfig**

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: my-cluster
spec:
  authType: OIDC
  oidcAuth:
    issuerURL: https://keycloak.example.com/realms/kubernetes
    clientID: breakglass-controller
    clientSecretRef:
      name: oidc-client-secret
      namespace: breakglass-system
      key: client-secret
    server: https://my-cluster-api.example.com:6443
```

### Reusing OIDC Settings from IdentityProvider

If you have an `IdentityProvider` already configured for user authentication, you can reuse its OIDC settings for cluster authentication using `oidcFromIdentityProvider`. This avoids duplicating configuration and ensures consistency.

**oidcFromIdentityProvider Configuration**

| Field | Required | Description |
|-------|----------|-------------|
| `name` | Yes | Name of the IdentityProvider resource to inherit OIDC settings from |
| `server` | Yes | URL of the target cluster's API server (cluster-specific) |
| `clientID` | No | Override the client ID (defaults to IdentityProvider's clientID) |
| `clientSecretRef` | No | Override the client secret (falls back to Keycloak service account) |
| `caSecretRef` | No | CA certificate for the cluster API server |
| `insecureSkipTLSVerify` | No | Skip TLS verification (NOT for production) |

**Example: Inheriting from IdentityProvider**

Given an IdentityProvider:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: IdentityProvider
metadata:
  name: corp-keycloak
spec:
  oidc:
    authority: https://keycloak.example.com/realms/kubernetes
    clientID: breakglass-ui
  keycloak:
    baseURL: https://keycloak.example.com
    realm: kubernetes
    clientID: breakglass-service
    clientSecretRef:
      name: keycloak-credentials
      namespace: breakglass-system
```

You can reference it in ClusterConfig:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: my-cluster
spec:
  authType: OIDC
  oidcFromIdentityProvider:
    name: corp-keycloak
    server: https://my-cluster-api.example.com:6443
    # Optional: Override client credentials for cluster auth
    # clientID: cluster-auth-client
    # clientSecretRef:
    #   name: cluster-oidc-secret
    #   namespace: breakglass-system
```

**How It Works:**

1. The controller looks up the referenced IdentityProvider
2. Inherits `issuerURL` from the IdentityProvider's `oidc.authority`
3. Uses `clientID` from:
   - `oidcFromIdentityProvider.clientID` (if specified)
   - Or falls back to IdentityProvider's `keycloak.clientID` or `oidc.clientID`
4. Uses client secret from:
   - `oidcFromIdentityProvider.clientSecretRef` (if specified)
   - Or falls back to IdentityProvider's `keycloak.clientSecretRef`
5. Combines with cluster-specific settings (`server`, `caSecretRef`)

**When to Use:**

- Use `oidcFromIdentityProvider` when:
  - You already have an IdentityProvider configured with Keycloak service account
  - You want to avoid duplicating OIDC issuer configuration
  - Multiple ClusterConfigs share the same identity provider

- Use direct `oidcAuth` when:
  - You need different OIDC settings than the IdentityProvider
  - You don't have an IdentityProvider configured
  - The cluster uses a different OIDC issuer than user authentication

**Note:** `oidcAuth` and `oidcFromIdentityProvider` are mutually exclusive. Configure one or the other, not both.

### Token Refresh and TOFU

**Automatic Token Refresh:**

The OIDC token provider automatically:
- Caches tokens until 30 seconds before expiry
- Uses refresh tokens when available
- Falls back to client credentials flow if refresh fails

**TOFU (Trust On First Use):**

If `caSecretRef` is not specified and `insecureSkipTLSVerify` is false, the controller performs TOFU:
1. Connects to the API server with TLS verification disabled (first time only)
2. Captures the server's CA certificate
3. Stores it in a Secret for future connections
4. Logs the certificate fingerprint for security auditing

**Token Exchange (RFC 8693):**

Token exchange enables the controller to exchange a subject token for a cluster-scoped token. This is useful for:
- Cross-realm authentication where tokens need to be exchanged for a different audience
- Delegation scenarios where the controller acts on behalf of a service account
- Advanced OIDC configurations that require token transformation

```yaml
tokenExchange:
  enabled: true
  # Required: Reference to secret containing the subject token to exchange
  subjectTokenSecretRef:
    name: service-account-token
    namespace: breakglass-system
    key: token
  # Optional: Token type identifiers (defaults shown)
  subjectTokenType: "urn:ietf:params:oauth:token-type:access_token"
  requestedTokenType: "urn:ietf:params:oauth:token-type:access_token"
  # Optional: Target resource for the exchanged token
  resource: "https://my-cluster.example.com:6443"
  # Optional: Actor token for delegation scenarios
  actorTokenSecretRef:
    name: controller-token
    namespace: breakglass-system
    key: token
  actorTokenType: "urn:ietf:params:oauth:token-type:access_token"
```

| Field | Required | Description |
|-------|----------|-------------|
| `enabled` | Yes | Set to `true` to enable token exchange |
| `subjectTokenSecretRef` | Yes | Reference to secret containing the subject token |
| `subjectTokenType` | No | Token type URI (default: access_token) |
| `requestedTokenType` | No | Requested token type URI (default: access_token) |
| `resource` | No | Target resource URI for the exchanged token |
| `actorTokenSecretRef` | No | Optional actor token for delegation |
| `actorTokenType` | No | Actor token type URI (default: access_token) |

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

### Identity Provider Restrictions

Use `identityProviderRefs` to restrict which IdentityProviders can authenticate users for this cluster:

```yaml
# Only users authenticated via specified IDPs can access this cluster
identityProviderRefs:
  - corp-keycloak
  - azure-ad
```

| Behavior | Configuration |
|----------|--------------|
| Accept all IDPs | Omit `identityProviderRefs` or set to `[]` |
| Restrict to specific IDPs | List IDP names in `identityProviderRefs` |

This is useful for:
- Multi-tenant environments where different clusters trust different IDPs
- Restricting production clusters to corporate-only authentication
- Compliance requirements mandating specific identity providers

**Note:** The IDP names must match the `metadata.name` of existing `IdentityProvider` resources.

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

**Kubeconfig Authentication Reasons:**

| Reason | Status | Description |
|--------|--------|-------------|
| `KubeconfigValidated` | True | Kubeconfig is valid and cluster connection verified |
| `SecretMissing` | False | Referenced kubeconfig secret doesn't exist |
| `SecretKeyMissing` | False | Secret exists but is missing the required key |
| `KubeconfigParseFailed` | False | Kubeconfig data is invalid or malformed |

**OIDC Authentication Reasons:**

| Reason | Status | Description |
|--------|--------|-------------|
| `OIDCValidated` | True | OIDC configuration is valid and token acquired |
| `OIDCConfigMissing` | False | authType=OIDC but no oidcAuth configuration |
| `OIDCDiscoveryFailed` | False | Cannot reach OIDC discovery endpoint |
| `OIDCTokenFetchFailed` | False | Failed to obtain OIDC token (client credentials) |
| `OIDCRefreshFailed` | False | Failed to refresh OIDC token |
| `OIDCCASecretMissing` | False | Referenced cluster CA secret doesn't exist |

**Common Reasons:**

| Reason | Status | Description |
|--------|--------|-------------|
| `ClusterUnreachable` | False | Cannot connect to target cluster API server |
| `TOFUFailed` | False | TOFU (Trust On First Use) certificate fetch failed |
| `ValidationFailed` | False | Generic validation failure |

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
