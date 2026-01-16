# Webhook Setup and Integration

This guide covers setting up the breakglass authorization webhook for real-time access control.

**Implementation:** [`webhook.go`](../pkg/webhook/)

## Overview

The breakglass authorization webhook integrates with the Kubernetes API server to:

- Intercept authorization requests for managed clusters
- Validate requests against active `BreakglassSession` resources
- Enforce `DenyPolicy` restrictions
- Provide real-time access control without modifying cluster RBAC

## Architecture

```text
┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
│   User Request  │    │  API Server     │    │ Breakglass Hub  │
│                 │────▶│  Authorization  │────▶│    Webhook      │
│ kubectl get pods│    │    Webhook      │    │   Controller    │
└─────────────────┘    └─────────────────┘    └─────────────────┘
                                │                        │
                                │                        ▼
                                │               ┌─────────────────┐
                                │               │ BreakglassSession│
                                │               │   DenyPolicy    │
                                │               │  ClusterConfig  │
                                └───────────────┤                 │
                                 ALLOW/DENY     └─────────────────┘
```

## Kubernetes API Server Configuration

### Authorization Configuration

Configure the API server with webhook authorization:

```yaml
# /etc/kubernetes/authorization-config.yaml
apiVersion: apiserver.config.k8s.io/v1beta1
kind: AuthorizationConfiguration
authorizers:
  # Node authorizer for kubelet operations (first for performance)
  - type: Node
    name: node
  
  # RBAC handles normal permissions
  - type: RBAC
    name: rbac
  
  # Breakglass webhook AFTER RBAC - grants ADDITIONAL temporary access
  # Only consulted when RBAC denies but user has valid breakglass session
  - type: Webhook
    name: breakglass
    webhook:
      # Connection settings
      timeout: 3s
      unauthorizedTTL: 30s
      authorizedTTL: 30s
      
      # Webhook endpoint configuration
      connectionInfo:
        type: KubeConfigFile
        kubeConfigFile: /etc/kubernetes/breakglass-webhook-kubeconfig.yaml
      
      # SubjectAccessReview API version
      subjectAccessReviewVersion: v1
      matchConditionSubjectAccessReviewVersion: v1
      
      # Failure handling: Use NoOpinion for resilience, Deny for strict security
      failurePolicy: Deny  # Deny on webhook failure (recommended for security)
      
      # Match conditions filter which requests go through the webhook
      # System users skip the webhook and fall through to RBAC
      matchConditions:
        - expression: "'system:authenticated' in request.groups"
        - expression: "!request.user.startsWith('system:')"
        - expression: "!('system:serviceaccounts' in request.groups)"
        # IMPORTANT: Skip the breakglass manager's OIDC identity to prevent
        # recursive webhook calls (see "Preventing Recursive Webhook Calls" below)
        - expression: "request.user != 'breakglass-group-sync@service.local'"
```

> **Important:** The last matchCondition excludes the breakglass manager's OIDC identity from webhook processing. This is critical for multi-cluster setups using OIDC authentication. See [Preventing Recursive Webhook Calls](#preventing-recursive-webhook-calls) for details.

### API Server Flags
Add the authorization configuration to your API server:

```bash
# Add to kube-apiserver command line arguments
--authorization-config=/etc/kubernetes/authorization-config.yaml
```

For **kubeadm** clusters, update the static pod manifest:

```yaml
# /etc/kubernetes/manifests/kube-apiserver.yaml
spec:
  containers:
  - name: kube-apiserver
    command:
    - kube-apiserver
    - --authorization-config=/etc/kubernetes/authorization-config.yaml
    # ... other flags
    volumeMounts:
    - name: webhook-config
      mountPath: /etc/kubernetes/authorization-config.yaml
      readOnly: true
    - name: webhook-kubeconfig
      mountPath: /etc/kubernetes/breakglass-webhook-kubeconfig.yaml
      readOnly: true
  volumes:
  - name: webhook-config
    hostPath:
      path: /etc/kubernetes/authorization-config.yaml
  - name: webhook-kubeconfig
    hostPath:
      path: /etc/kubernetes/breakglass-webhook-kubeconfig.yaml
```

## Webhook Kubeconfig

### Configuration File

Create the webhook kubeconfig file:

```yaml
# /etc/kubernetes/breakglass-webhook-kubeconfig.yaml
apiVersion: v1
kind: Config
clusters:
  - name: breakglass
    cluster:
      # Breakglass service endpoint (cluster-specific)
      server: https://breakglass.example.com/authorize/my-cluster-name
      
      # TLS configuration
      certificate-authority-data: LS0tLS1CRUdJTi... # Base64 CA cert
      # OR for development/testing (not recommended for production):
      # insecure-skip-tls-verify: true

users:
  - name: kube-apiserver
    user:
      # Authentication token
      token: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9...
      # OR use client certificates:
      # client-certificate-data: LS0tLS1CRUdJTi...
      # client-key-data: LS0tLS1CRUdJTi...

contexts:
  - name: webhook
    context:
      cluster: breakglass
      user: kube-apiserver

current-context: webhook
```

### Endpoint URL Format

The webhook endpoint is exposed by the hub server. By default the controller registers the webhook
under the API group path and also provides a legacy root path for backwards compatibility:

```text
https://breakglass.example.com/api/breakglass/webhook/authorize/{cluster-name}
https://breakglass.example.com/breakglass/webhook/authorize/{cluster-name}  # legacy
```

Where `{cluster-name}` must match:

- A `ClusterConfig` resource name in the hub cluster
- The cluster identifier used in `BreakglassSession` resources

Notes on matching behavior

- The `{cluster-name}` path segment is used by the webhook to determine which managed cluster the request targets. The webhook will match this value against the following, in order of relevance:
  - `ClusterConfig.metadata.name` (recommended canonical identifier)
  - `BreakglassSession.spec.cluster` values present on active sessions
  - Entries listed in `BreakglassEscalation.spec.allowed.clusters` for escalation-based checks

- Make sure the value you expose in the webhook URL is identical (including case) to the `ClusterConfig` name or the cluster identifier used in session/escalation objects. URL-encode any characters that are not valid in a URL path.

- If a ClusterConfig is not present for the provided `{cluster-name}`, the webhook immediately denies the request with a human-friendly message (`Cluster "foo" is not registered with Breakglass`) and emits a `cluster-missing` reason in metrics. This reduces confusion for platform users and surfaces onboarding gaps early. Create the missing ClusterConfig or update the webhook URL path to match an existing name.

### Authentication Methods

#### Bearer Token (Recommended)

```yaml
users:
  - name: kube-apiserver
    user:
      token: <secure-bearer-token>
```

Generate a secure token:

```bash
# Generate random token
openssl rand -base64 32

# Or use JWT with appropriate claims
# (implementation-specific)
```

#### Client Certificates

```yaml
users:
  - name: kube-apiserver
    user:
      client-certificate-data: <base64-client-cert>
      client-key-data: <base64-client-key>
```

## Hub Cluster Configuration

### ClusterConfig Resource

Create a `ClusterConfig` for the managed cluster:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: managed-cluster-admin
  namespace: default
type: Opaque
data:
  kubeconfig: <base64-encoded-admin-kubeconfig>
---
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: my-cluster-name  # Must match webhook URL path
spec:
  clusterID: my-cluster-name
  kubeconfigSecretRef:
    name: managed-cluster-admin
    namespace: default
```

### Service Configuration

Ensure the breakglass service is accessible from managed clusters:

```yaml
# Service exposure (example using Ingress)
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: breakglass-webhook
  annotations:
    nginx.ingress.kubernetes.io/ssl-redirect: "true"
    nginx.ingress.kubernetes.io/backend-protocol: "HTTP"
spec:
  tls:
    - hosts:
        - breakglass.example.com
      secretName: breakglass-tls
  rules:
    - host: breakglass.example.com
      http:
        paths:
          - path: /authorize
            pathType: Prefix
            backend:
              service:
                name: breakglass
                port:
                  number: 8080
```

## Webhook Behavior

### Decision Logic

The webhook evaluates requests in this order:

1. **Check DenyPolicies** → Deny if matched
2. **Check Active Sessions** → Allow if matched
3. **Pass Through** → Let RBAC decide (no opinion)

### Response Codes

- **Allowed**: Authorized by active session
- **Denied**: Blocked by policy or security rule
- **No Opinion**: No breakglass authorization applies

## Security Considerations

### Network Security

- Use HTTPS for all webhook communication
- Restrict network access between clusters
- Configure firewall rules for webhook traffic

### Authentication

- Rotate webhook tokens regularly
- Use strong credentials
- Grant minimal required permissions

### Availability

- Set appropriate failure policy (Deny for security)
- Configure reasonable timeout values (3-5s)
- Monitor webhook availability
- Consider redundancy for high availability

## Testing and Validation

### Basic Connectivity

```bash
# Test webhook endpoint
curl -k https://breakglass.example.com/authorize/my-cluster/healthz
```

### Authorization Testing

```bash
# Check permissions (uses RBAC)
kubectl --as=user@example.com auth can-i get pods

# After creating a breakglass session, re-check (may allow)
kubectl --as=user@example.com auth can-i get pods
```

## Troubleshooting

### Webhook Unreachable

```text
Error: failed to call webhook: Post "https://breakglass.example.com/authorize/my-cluster": dial tcp: connection refused
```

Check:

- Network connectivity between API server and webhook
- DNS resolution
- Firewall rules
- TLS certificates

### Authentication Failures

```text
Error: Unauthorized (401)
```

Check:

- Bearer token validity
- Client certificate validity
- Kubeconfig format

### Timeout Issues

```text
Error: context deadline exceeded
```

Check:

- Webhook timeout settings
- Network latency
- Webhook performance
- **Recursive webhook calls** (see [Preventing Recursive Webhook Calls](#preventing-recursive-webhook-calls))

### Debugging

```bash
# Check API server logs
journalctl -u kubelet | grep authorization

# Verify webhook kubeconfig
kubectl --kubeconfig=/etc/kubernetes/breakglass-webhook-kubeconfig.yaml cluster-info

# Check breakglass logs
kubectl logs -n breakglass-system deployment/breakglass-controller
```

## Preventing Recursive Webhook Calls

In multi-cluster setups where the breakglass manager uses OIDC authentication to connect to spoke clusters, **recursive webhook calls** can cause authorization timeouts. This section explains the issue and how to prevent it.

### The Problem

When the breakglass authorization webhook processes a request, it may need to call back to the spoke cluster to:

1. **Fetch namespace labels** for DenyPolicy evaluation
2. **Deploy debug session workloads** (pods, daemonsets, deployments)
3. **Perform RBAC checks** via impersonation

If the breakglass manager connects to spoke clusters using OIDC authentication, and the OIDC identity doesn't have explicit RBAC permissions, these callback requests trigger the spoke cluster's authorization webhook - which calls the breakglass manager again, creating a recursive loop:

```text
┌─────────────────────────────────────────────────────────────────────────┐
│  User kubectl command                                                    │
│         │                                                                │
│         ▼                                                                │
│  Spoke Cluster API Server                                                │
│         │                                                                │
│         ▼ (authz webhook)                                                │
│  Breakglass Manager (hub)                                                │
│         │                                                                │
│         ▼ (fetch namespace labels using OIDC)                            │
│  Spoke Cluster API Server                                                │
│         │                                                                │
│         ▼ (authz webhook - RECURSIVE!)                                   │
│  Breakglass Manager (hub) ← TIMEOUT                                      │
└─────────────────────────────────────────────────────────────────────────┘
```

### The Solution

Implement **two layers of protection**:

#### 1. Grant RBAC Permissions to the OIDC Identity

Create ClusterRoles and ClusterRoleBindings on each spoke cluster that grant the breakglass manager's OIDC identity the permissions it needs. Since RBAC runs before the webhook in the authorization chain, these operations are allowed directly without triggering the webhook.

See [RBAC Requirements for OIDC Authentication](cluster-config.md#rbac-requirements-for-oidc-authentication) for the complete list of required permissions.

#### 2. Exclude the OIDC Identity from Webhook Processing

Add a `matchCondition` to the authorization webhook configuration that skips requests from the breakglass manager's OIDC identity:

```yaml
matchConditions:
  - expression: "'system:authenticated' in request.groups"
  - expression: "!request.user.startsWith('system:')"
  - expression: "!('system:serviceaccounts' in request.groups)"
  # Exclude the breakglass manager's OIDC identity
  - expression: "request.user != 'breakglass-group-sync@service.local'"
```

Replace `breakglass-group-sync@service.local` with the actual username claim value from your OIDC tokens.

### Identifying Your OIDC Identity

The username used in the `matchCondition` must match the claim value from OIDC tokens. This is typically:

- **For Keycloak with client credentials flow:** The `email` claim set on the service account client (e.g., `breakglass-group-sync@service.local`)
- **For Azure AD:** The `preferred_username` or `email` claim

To find your OIDC identity, check the controller logs for messages like:

```text
Using cached token {"cluster": "spoke-cluster-a", "expiresAt": "..."}
```

Or decode a token manually:

```bash
# Get the access token from controller logs or OIDC provider
echo $ACCESS_TOKEN | cut -d. -f2 | base64 -d | jq '.email, .preferred_username'
```

### Symptoms of Recursive Webhook Calls

If you're experiencing this issue, you'll see:

1. **Timeout errors** in E2E tests or production:
   ```text
   context deadline exceeded (Client.Timeout exceeded while awaiting headers)
   ```

2. **Breakglass manager logs** showing namespace fetch failures:
   ```text
   Failed to fetch namespace labels for DenyPolicy evaluation
   error: "failed to get namespace default from cluster X: context canceled"
   ```

3. **Webhook requests taking ~3 seconds** (the full timeout duration) even for simple operations

## Production Deployment Checklist

- [ ] TLS certificates configured and valid
- [ ] Strong authentication tokens generated
- [ ] Network policies restrict webhook access
- [ ] Token rotation scheduled
- [ ] Webhook timeout set (3-5s)
- [ ] Failure policy set to Deny
- [ ] Monitoring configured
- [ ] Health checks working
- [ ] Connectivity tested
- [ ] Authorization flow validated
- [ ] **OIDC identity excluded from webhook matchConditions** (multi-cluster setups)
- [ ] **RBAC permissions granted to OIDC identity** (multi-cluster setups)

## Related Resources

- [ClusterConfig](./cluster-config.md) - Cluster configuration
- [BreakglassSession](./breakglass-session.md) - Session management
- [DenyPolicy](./deny-policy.md) - Access restrictions
- [API Reference](./api-reference.md) - REST API documentation
