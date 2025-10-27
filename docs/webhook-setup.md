# Webhook Setup and Integration

This guide covers setting up the breakglass authorization webhook in managed Kubernetes clusters to enable real-time access control based on active breakglass sessions.

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
  # Standard authorizers (order matters)
  - type: Node
    name: node
  - type: RBAC
    name: rbac
  
  # Breakglass webhook (evaluated after RBAC)
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
      
      # Failure handling
      failurePolicy: Deny  # Deny on webhook failure (recommended for security)
      
      # Match conditions (optimize performance)
      matchConditions:
        - expression: "'system:authenticated' in request.groups"
        - expression: "!request.user.startsWith('system:')"
        - expression: "!('system:serviceaccounts' in request.groups)"
```

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

- If a ClusterConfig is not present for the provided `{cluster-name}`, the webhook will still attempt to match active sessions and escalations by the raw cluster identifier present in the resources; however, some hub-specific checks may rely on a ClusterConfig being present.

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

### Request Processing

The webhook receives `SubjectAccessReview` requests and:

1. **Extract Request Details**: User, groups, resource, verb, namespace
2. **Find Active Sessions**: Query for active `BreakglassSession` resources
3. **Check DenyPolicies**: Evaluate any matching `DenyPolicy` resources
4. **Make Decision**: Allow, deny, or pass through to next authorizer

### Decision Logic

```pseudocode
function authorize(request):
    // Check for explicit deny policies first
    if (matchesDenyPolicy(request)):
        return DENY("Blocked by DenyPolicy")
    
    // Check for active breakglass sessions
    sessions = findActiveSessions(request.user, request.cluster)
    for session in sessions:
        if (sessionAllowsRequest(session, request)):
            return ALLOW("Authorized by BreakglassSession")
    
    // No breakglass authorization found - pass to next authorizer
    return NO_OPINION()
```

### Response Codes

- **Allowed**: Request explicitly authorized by breakglass session
- **Denied**: Request explicitly denied by policy or security violation
- **No Opinion**: No breakglass authorization applies (fallback to RBAC)

### SubjectAccessReview reason strings

When the webhook explicitly Allows or Denies a request it includes a short human-readable `status.reason` string in the `SubjectAccessReview` response. Example reasons you may see in logs or API responses:

- `Authorized by BreakglassSession` — an active session matched the requester and requested resource.
- `Allowed by Escalation` — an escalation rule permitted the action for the requester's group/identity.
- `Blocked by DenyPolicy` — an explicit deny matched the request and prevented authorization.
- `No Breakglass Authorization` — the webhook had no matching session or escalation to allow the action and returned no opinion.

These strings are intentionally concise and may be extended in future versions. Do not rely on an exact string match in production code; prefer checking the boolean `status.allowed` field and any relevant audit logs.

## Security Considerations

### Network Security

- **TLS Encryption**: Always use HTTPS for webhook communication
- **Network Isolation**: Restrict network access between clusters and hub
- **Firewall Rules**: Configure appropriate firewall rules for webhook traffic

### Authentication Security

- **Token Rotation**: Regularly rotate webhook authentication tokens
- **Strong Secrets**: Use cryptographically strong authentication credentials
- **Least Privilege**: Grant minimal required permissions to webhook tokens

### Availability and Resilience

- **Failure Policy**: Configure appropriate `failurePolicy` (Deny vs Allow)
- **Timeout Settings**: Set reasonable timeout values (3-5 seconds)
- **Monitoring**: Monitor webhook availability and response times
- **Redundancy**: Consider multiple webhook endpoints for high availability

## Testing and Validation

### Basic Connectivity Test

```bash
# Test webhook endpoint accessibility
curl -k https://breakglass.example.com/authorize/my-cluster-name/healthz

# Test with SubjectAccessReview
kubectl create -f - <<EOF
apiVersion: authorization.k8s.io/v1
kind: SubjectAccessReview
spec:
  user: test-user@example.com
  resourceAttributes:
    verb: get
    resource: pods
    namespace: default
EOF
```

### Authorization Testing

```bash
# Test without breakglass session (should use RBAC)
kubectl --as=user@example.com auth can-i get pods

# Create breakglass session through API
curl -X POST https://breakglass.example.com/api/v1/sessions \
  -H "Content-Type: application/json" \
  -d '{"cluster": "my-cluster-name", "user": "user@example.com", "requestedGroup": "cluster-admin"}'

# Test with active session (should be allowed)
kubectl --as=user@example.com auth can-i get pods
```

### Performance Testing

```bash
# Measure webhook response time
time kubectl --as=test-user@example.com auth can-i get pods

# Load testing with multiple requests
for i in {1..100}; do
  kubectl --as=user-$i@example.com auth can-i get pods &
done
wait
```

## Troubleshooting

### Common Issues

#### Webhook Unreachable

```text
Error: failed to call webhook: Post "https://breakglass.example.com/authorize/my-cluster": dial tcp: connection refused
```

**Solutions:**

- Check network connectivity between API server and webhook
- Verify DNS resolution
- Check firewall rules
- Validate TLS certificates

#### Authentication Failures

```text
Error: Unauthorized (401)
```

**Solutions:**

- Verify bearer token or client certificates
- Check token expiration
- Validate kubeconfig format

#### Timeout Issues

```text
Error: context deadline exceeded
```

**Solutions:**

- Increase webhook timeout in authorization config
- Optimize webhook performance
- Check network latency

#### Certificate Issues

```text
Error: x509: certificate signed by unknown authority
```

**Solutions:**

- Add CA certificate to webhook kubeconfig
- Use `insecure-skip-tls-verify: true` for testing only
- Ensure certificate chain is complete

### Debugging Commands

```bash
# Check API server logs
journalctl -u kubelet | grep authorization

# Test webhook directly
curl -X POST https://breakglass.example.com/authorize/my-cluster-name \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"apiVersion":"authorization.k8s.io/v1","kind":"SubjectAccessReview","spec":{"user":"test@example.com","resourceAttributes":{"verb":"get","resource":"pods"}}}'

# Validate kubeconfig
kubectl --kubeconfig=/etc/kubernetes/breakglass-webhook-kubeconfig.yaml cluster-info

# Check breakglass logs
kubectl logs -n breakglass-system deployment/breakglass-controller
```

## Production Deployment Checklist

### Security

- [ ] TLS certificates configured and valid
- [ ] Strong authentication tokens generated and stored securely
- [ ] Network policies restrict webhook access
- [ ] Regular token rotation scheduled
- [ ] Audit logging enabled

### Reliability

- [ ] Webhook timeout configured appropriately (3-5s)
- [ ] Failure policy set to `Deny` for security
- [ ] Monitoring and alerting configured
- [ ] Health check endpoints working
- [ ] Backup webhook endpoints configured

### Testing

- [ ] Basic connectivity tested
- [ ] Authorization flow validated
- [ ] Performance testing completed
- [ ] Failure scenarios tested
- [ ] Rollback procedure documented

## Related Resources

- [ClusterConfig](./cluster-config.md) - Cluster configuration
- [BreakglassSession](./breakglass-session.md) - Session management
- [DenyPolicy](./deny-policy.md) - Access restrictions
- [API Reference](./api-reference.md) - REST API documentation
