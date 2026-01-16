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
1. Connects to the API server using a custom TLS verification callback
2. Attempts to verify the certificate against system roots (accepts if valid)
3. If verification fails (expected for self-signed/private CAs), still captures the certificate
4. Stores the captured CA certificate in a Secret for future connections
5. Logs the certificate fingerprint for security auditing

This approach is more secure than blanket `InsecureSkipVerify` as it:
- Accepts already-trusted certificates without requiring TOFU
- Performs explicit certificate inspection before accepting untrusted certificates
- Maintains an audit trail of certificate acceptance decisions

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

### User Identifier Claim Configuration

When a spoke cluster performs OIDC authentication, it extracts the username from a specific JWT claim (configured via the cluster's API server `--oidc-username-claim` flag or `claimMappings.username.claim` in OIDC config). This username is then used in SubjectAccessReview (SAR) requests.

For the breakglass authorization webhook to correctly match sessions to SAR requests, the session's `spec.user` must contain the same identifier that the spoke cluster extracts from the JWT.

Use `userIdentifierClaim` to specify which OIDC claim the spoke cluster uses:

```yaml
spec:
  # Match the OIDC claim used by the spoke cluster's API server
  userIdentifierClaim: email  # Default: use email claim
```

| Value | Description | When to Use |
|-------|-------------|-------------|
| `email` | Uses the `email` claim from the JWT (default) | Most common for production deployments |
| `preferred_username` | Uses the `preferred_username` claim | When clusters use username-based authentication |
| `sub` | Uses the `sub` (subject) claim | When using unique subject identifiers |

**Important:** The `userIdentifierClaim` value must match the spoke cluster's OIDC username claim configuration:

```yaml
# Spoke cluster API server config example (using email):
apiServer:
  extraArgs:
    oidc-username-claim: email
    # OR for structured config:
    # authentication.oidc.claimMappings.username.claim: email
```

If not specified in ClusterConfig, `userIdentifierClaim` falls back to the global config setting (`kubernetes.userIdentifierClaim` in `config.yaml`). If not configured globally either, it defaults to `email`, which is the recommended setting for most production deployments.

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

## RBAC Requirements for OIDC Authentication

When using OIDC authentication (`authType: OIDC`) in a multi-cluster setup with authorization webhooks, the OIDC service account identity must have specific RBAC permissions on each spoke cluster. This is critical to prevent recursive webhook calls and authorization timeouts.

### Why RBAC Permissions Are Required

In a typical hub-spoke architecture:

1. Spoke clusters configure an authorization webhook pointing to the hub's breakglass manager
2. When the breakglass manager handles webhook requests, it needs to call back to spoke clusters to:
   - Fetch namespace labels for DenyPolicy evaluation
   - Deploy debug session workloads (pods, daemonsets, deployments)
   - Validate node labels for kubectl debug
   - Perform RBAC permission checks via impersonation

3. Without explicit RBAC permissions, these calls from the manager (using OIDC) would themselves trigger the authorization webhook, causing a recursive loop and timeout

4. By granting RBAC permissions, these operations are allowed directly by RBAC (which runs before the webhook), preventing recursion

### Required ClusterRoles

The OIDC identity (e.g., `breakglass-group-sync@service.local`) needs the following permissions on each spoke cluster:

#### 1. Impersonation (for RBAC checks)

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: breakglass-impersonator
rules:
# Impersonate system:auth-checker for RBAC permission checks
- apiGroups: [""]
  resources: ["users"]
  verbs: ["impersonate"]
  resourceNames: ["system:auth-checker"]
# Impersonate any group to check escalated group permissions
- apiGroups: [""]
  resources: ["groups"]
  verbs: ["impersonate"]
```

#### 2. Namespace Reader (for DenyPolicy evaluation)

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: breakglass-namespace-reader
rules:
- apiGroups: [""]
  resources: ["namespaces"]
  verbs: ["get", "list", "watch"]
```

#### 3. Workload Manager (for debug sessions)

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: breakglass-workload-manager
rules:
# Manage pods for debug sessions
- apiGroups: [""]
  resources: ["pods", "pods/exec", "pods/log", "pods/portforward"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
# Manage services and configs for debug sessions
- apiGroups: [""]
  resources: ["services", "configmaps", "secrets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
# Read nodes for kubectl debug node functionality
- apiGroups: [""]
  resources: ["nodes"]
  verbs: ["get", "list", "watch"]
# Manage workloads (daemonsets, deployments) for debug sessions
- apiGroups: ["apps"]
  resources: ["deployments", "daemonsets", "replicasets"]
  verbs: ["get", "list", "watch", "create", "update", "patch", "delete"]
# Create events for status reporting
- apiGroups: [""]
  resources: ["events"]
  verbs: ["create", "patch"]
```

### Binding the ClusterRoles

Create ClusterRoleBindings for the OIDC identity:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: breakglass-impersonator-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: breakglass-impersonator
subjects:
- kind: User
  name: "breakglass-group-sync@service.local"  # Your OIDC identity
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: breakglass-namespace-reader-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: breakglass-namespace-reader
subjects:
- kind: User
  name: "breakglass-group-sync@service.local"
  apiGroup: rbac.authorization.k8s.io
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: breakglass-workload-manager-binding
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: breakglass-workload-manager
subjects:
- kind: User
  name: "breakglass-group-sync@service.local"
  apiGroup: rbac.authorization.k8s.io
```

**Note:** Replace `breakglass-group-sync@service.local` with the actual username claim value from your OIDC tokens. This is typically the `email` or `preferred_username` claim configured in your OIDC provider.

### Webhook matchConditions Exclusion (Optional but Recommended)

For additional protection against recursive webhook calls, configure the spoke cluster's authorization webhook to skip requests from the breakglass manager's OIDC identity:

```yaml
# authorization-config.yaml
apiVersion: apiserver.config.k8s.io/v1
kind: AuthorizationConfiguration
authorizers:
  - type: RBAC
    name: rbac
  - type: Webhook
    name: breakglass
    webhook:
      timeout: 3s
      failurePolicy: NoOpinion
      connectionInfo:
        type: KubeConfigFile
        kubeConfigFile: /etc/kubernetes/breakglass-webhook.kubeconfig
      matchConditions:
        # Only call webhook for authenticated users
        - expression: "'system:authenticated' in request.groups"
        # Skip webhook for system users
        - expression: "!request.user.startsWith('system:')"
        # Skip webhook for system service accounts
        - expression: "!('system:serviceaccounts' in request.groups)"
        # Skip webhook for the breakglass manager's OIDC identity
        - expression: "request.user != 'breakglass-group-sync@service.local'"
```

This provides defense-in-depth: RBAC allows the operations directly, and the webhook exclusion ensures no recursion even if RBAC configuration is incomplete.

### Security Implications

**Permissions Granted:**

| Permission | Purpose | Security Note |
|------------|---------|---------------|
| Impersonate users/groups | RBAC permission checks | Limited to `system:auth-checker` user |
| Read namespaces | DenyPolicy evaluation | Read-only, cluster-wide |
| Manage pods | Debug session creation | Full pod lifecycle in any namespace |
| Manage deployments/daemonsets | Debug workload deployment | Full workload lifecycle |
| Read nodes | Node debug validation | Read-only |
| Manage secrets/configmaps | Debug session resources | Full access to secrets |

**Recommendations:**

1. **Restrict to specific namespaces** if possible: Use RoleBindings instead of ClusterRoleBindings if debug sessions are limited to specific namespaces
2. **Audit access**: Enable Kubernetes audit logging for the OIDC identity
3. **Rotate credentials**: Regularly rotate the OIDC client secret
4. **Monitor usage**: Set up alerts for unexpected resource creation by the OIDC identity

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

#### Ready Condition: False (OIDCDiscoveryFailed)

**Cause:** Cannot reach OIDC issuer's discovery endpoint (`.well-known/openid-configuration`).

**Diagnosis:**
```bash
# Test OIDC discovery manually
ISSUER_URL="https://keycloak.example.com/realms/kubernetes"
curl -v "${ISSUER_URL}/.well-known/openid-configuration"
```

**Solution:**
- Verify `issuerURL` is correct and accessible from the controller pod
- Check network policies allow egress to OIDC issuer
- Ensure TLS certificate is valid (or use `certificateAuthority` field)
- Verify OIDC realm/tenant name in URL

#### Ready Condition: False (OIDCTokenFetchFailed)

**Cause:** OIDC token request failed (invalid credentials, wrong scope, etc.).

**Diagnosis:**
```bash
# Check client secret exists
kubectl get secret <client-secret-name> -n <namespace>

# Verify secret data
kubectl get secret <client-secret-name> -n <namespace> -o jsonpath='{.data.client-secret}' | base64 -d

# Test token request manually
curl -X POST "${ISSUER_URL}/protocol/openid-connect/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}"
```

**Solution:**
- Verify client secret is correct and matches OIDC provider configuration
- Ensure client has correct grant types enabled (client_credentials)
- Check if client is enabled (not disabled/archived in OIDC provider)
- Verify scopes are valid for the client

#### Ready Condition: False (OIDCRefreshFailed)

**Cause:** Token refresh using refresh token failed.

**Diagnosis:**
```bash
# Check controller logs for refresh errors
kubectl logs -n breakglass-system -l app=breakglass | grep "refresh.*failed"
```

**Solution:**
- Refresh tokens expire - controller will automatically fall back to full auth
- Verify refresh token lifetime settings in OIDC provider
- If persistent, check if client_credentials flow still works (refresh is optional)
- This is usually transient and self-recovers on next token fetch

#### Ready Condition: False (TOFUFailed)

**Cause:** TOFU (Trust On First Use) CA certificate discovery failed.

**Diagnosis:**
```bash
# Test TLS connection to cluster API server
SERVER="https://api.cluster.example.com:6443"
openssl s_client -connect api.cluster.example.com:6443 -showcerts

# Check if controller can reach API server
kubectl exec -n breakglass-system -l app=breakglass -- curl -k -v ${SERVER}
```

**Solution:**
- Provide explicit `caSecretRef` instead of relying on TOFU
- Check network connectivity from controller to cluster API server
- Verify API server is serving TLS certificates
- Review TOFU logs for certificate fingerprint details

#### Ready Condition: False (ValidationFailed)

**Cause:** ClusterConfig validation failed (webhook or CRD validation).

**Diagnosis:**
```bash
# Get validation error details
kubectl get clusterconfig <name> -o jsonpath='{.status.conditions[?(@.type=="Ready")].message}'
```

**Solution:**
- Check for missing required fields (issuerURL, clientID, server for OIDC)
- Verify mutual exclusion: only use `oidcAuth` OR `oidcFromIdentityProvider`, not both
- Ensure `authType` matches the configuration (OIDC when using oidcAuth)
- Validate secret references point to existing secrets

#### Token Exchange Issues

**Cause:** Token exchange (RFC 8693) is failing.

**Diagnosis:**
```bash
# Verify subject token secret exists
kubectl get secret <subject-token-secret> -n <namespace>

# Check if OIDC provider supports token exchange
curl -X POST "${ISSUER_URL}/protocol/openid-connect/token" \
  -d "grant_type=urn:ietf:params:oauth:grant-type:token-exchange" \
  -d "client_id=${CLIENT_ID}" \
  -d "client_secret=${CLIENT_SECRET}" \
  -d "subject_token=${SUBJECT_TOKEN}" \
  -d "subject_token_type=urn:ietf:params:oauth:token-type:access_token"
```

**Solution:**
- Verify OIDC provider supports RFC 8693 token exchange
- Ensure subject token secret exists and contains valid token
- Check token types match provider expectations
- Consider using client_credentials flow if token exchange isn't required

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
