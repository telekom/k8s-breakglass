# Security Best Practices

This document covers security considerations and best practices for deploying and operating the breakglass controller.

## Rate Limiting

The breakglass API includes **built-in rate limiting** (per-IP, and for some endpoints per-user when authenticated). In production environments, you may still want additional rate limiting at the infrastructure level (ingress/API gateway) to prevent:

- **Denial of Service (DoS)** - Prevents attackers from overwhelming the API with requests
- **Brute Force Attacks** - Limits session request/approval attempts
- **Resource Exhaustion** - Prevents excessive Kubernetes resource creation

### Recommended Approaches

#### Built-in API rate limiting (default)

The API applies rate limiting in-process:

- Public API endpoints: differentiated unauthenticated (per-IP) vs authenticated (per-user) limits
- SAR webhook endpoint: much higher per-IP limits (Kubernetes calls this very frequently)

If you need to tune these limits beyond the defaults, prefer applying ingress/API-gateway limits. (The built-in defaults are defined in code under `pkg/ratelimit/`.)

> **⚠️ Security Warning: Trusted Proxies and Rate Limiter IP Spoofing**
>
> The built-in rate limiter uses Gin's `ClientIP()` function to identify clients, which reads the
> `X-Forwarded-For` header when `trustedProxies` is configured. This creates a **critical security
> consideration**:
>
> - **Without `trustedProxies`**: Rate limiting uses the direct connection IP. This is secure but may
>   rate-limit your ingress/proxy instead of individual clients.
> - **With `trustedProxies` misconfigured**: If an attacker's IP is in the trusted range, or if requests
>   bypass your trusted proxies, attackers can **spoof the `X-Forwarded-For` header** to bypass rate
>   limits entirely by sending different fake IPs with each request.
>
> **Best Practices:**
> 1. **Only add IPs/CIDRs of proxies you fully control** (your ingress controllers, load balancers).
> 2. **Never trust public or untrusted network ranges** in `trustedProxies`.
> 3. **Use network policies** to ensure the breakglass API pod only accepts traffic from your ingress.
> 4. **Consider defense in depth** - add rate limiting at the ingress layer (see below) where the real
>    client IP is known.
>
> See [configuration-reference.md](./configuration-reference.md#trustedproxies-optional) for trusted proxy
> configuration details.

#### 1. Ingress Rate Limiting (Recommended)

Configure rate limiting on your ingress controller:

**nginx-ingress:**

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: breakglass-ingress
  annotations:
    # Limit to 10 requests per second per IP
    nginx.ingress.kubernetes.io/limit-rps: "10"
    # Burst limit
    nginx.ingress.kubernetes.io/limit-burst-multiplier: "5"
    # Connections per IP
    nginx.ingress.kubernetes.io/limit-connections: "5"
spec:
  rules:
    - host: breakglass.example.com
      http:
        paths:
          - path: /api
            pathType: Prefix
            backend:
              service:
                name: breakglass
                port:
                  number: 8080
```

**Traefik:**

```yaml
apiVersion: traefik.io/v1alpha1
kind: Middleware
metadata:
  name: breakglass-ratelimit
spec:
  rateLimit:
    average: 10
    burst: 50
    period: 1s
---
apiVersion: traefik.io/v1alpha1
kind: IngressRoute
metadata:
  name: breakglass
spec:
  routes:
    - match: Host(`breakglass.example.com`) && PathPrefix(`/api`)
      kind: Rule
      middlewares:
        - name: breakglass-ratelimit
      services:
        - name: breakglass
          port: 8080
```

#### 2. Service Mesh Rate Limiting

If using Istio or similar service mesh:

```yaml
apiVersion: networking.istio.io/v1alpha3
kind: EnvoyFilter
metadata:
  name: breakglass-ratelimit
spec:
  workloadSelector:
    labels:
      app: breakglass
  configPatches:
    - applyTo: HTTP_FILTER
      match:
        context: SIDECAR_INBOUND
        listener:
          filterChain:
            filter:
              name: envoy.filters.network.http_connection_manager
              subFilter:
                name: envoy.filters.http.router
      patch:
        operation: INSERT_BEFORE
        value:
          name: envoy.filters.http.local_ratelimit
          typed_config:
            "@type": type.googleapis.com/envoy.extensions.filters.http.local_ratelimit.v3.LocalRateLimit
            stat_prefix: http_local_rate_limiter
            token_bucket:
              max_tokens: 100
              tokens_per_fill: 10
              fill_interval: 1s
```

#### 3. API Gateway Rate Limiting

## Authentication Token Handling

The API validates JWTs using an **explicit allowlist of signing algorithms** (RS/PS/ES families). This helps prevent algorithm-confusion attacks if an IdP ever misconfigures supported algorithms.

To reduce accidental credential exposure, the API middleware **strips the Authorization header** after extracting token data, so downstream logs or error handlers do not emit bearer tokens.

If using an API gateway (Kong, Ambassador, etc.), configure rate limiting there.

### Recommended Rate Limits

| Endpoint Pattern | Recommended Limit | Rationale |
|-----------------|-------------------|-----------|
| `POST /api/sessions` | 5/minute per user | Prevent session request spam |
| `PUT /api/sessions/*` | 10/minute per user | Allow reasonable approval flow |
| `GET /api/*` | 100/minute per user | Support UI refresh |
| `POST /api/debug-sessions` | 3/minute per user | Debug sessions are resource-intensive |

## Input Sanitization

The breakglass API automatically sanitizes user-provided text fields to prevent injection attacks:

### Sanitized Fields

- **Session reason** - Sanitized on creation
- **Approval/rejection reason** - Sanitized before storage
- **Debug session reason** - Sanitized on creation

### Sanitization Rules

The following patterns are stripped from text fields:

- HTML tags (`<script>`, `<iframe>`, `<svg>`, etc.)
- JavaScript handlers (`onerror=`, `onclick=`, etc.)
- Protocol handlers (`javascript:`, `data:text/html`, etc.)
- Template injection markers (`<?php`, `<%`, etc.)
- HTML comments (`<!--`, `-->`)

**Note:** Content after a dangerous pattern is also removed to prevent bypasses.

## Authentication

### OIDC Best Practices

1. **Use short-lived tokens** - Configure your IDP to issue tokens with 5-15 minute expiry
2. **Enable token refresh** - Allow token refresh for long-running sessions
3. **Validate audiences** - Ensure tokens are issued for the breakglass client
4. **Use HTTPS** - Always use TLS for OIDC communication

### Multi-Cluster OIDC Service Account

When using OIDC authentication for spoke cluster connections (via `ClusterConfig.spec.oidcAuth`), the breakglass manager's OIDC identity has elevated permissions on spoke clusters:

| Permission | Resources | Security Implication |
|------------|-----------|---------------------|
| Impersonation | users, groups | Can impersonate `system:auth-checker` for RBAC checks |
| Read | namespaces, nodes | Cluster-wide visibility |
| Full control | pods, deployments, daemonsets | Can create/delete workloads in any namespace |
| Full control | secrets, configmaps | Can read/write secrets in any namespace |

**Recommendations:**

1. **Audit the OIDC identity** - Enable Kubernetes audit logging and monitor operations by the OIDC identity
2. **Rotate credentials regularly** - Change the OIDC client secret periodically
3. **Restrict debug session namespaces** - If possible, limit `DebugSessionTemplate.targetNamespace` to specific namespaces and use RoleBindings instead of ClusterRoleBindings
4. **Monitor for abuse** - Set up alerts for unexpected resource creation by the OIDC identity
5. **Exclude from webhook** - Always add the OIDC identity to webhook matchConditions to prevent recursive calls. See [Preventing Recursive Webhook Calls](webhook-setup.md#preventing-recursive-webhook-calls)

For the complete RBAC setup, see [RBAC Requirements for OIDC Authentication](cluster-config.md#rbac-requirements-for-oidc-authentication).

### Group Membership

1. **Use group claims** - Prefer group-based authorization over user-based
2. **Minimize group scope** - Request only necessary group claims
3. **Regular audits** - Periodically review group memberships in your IDP

## Network Security

### Ingress and Reverse Proxy

When deploying behind an ingress controller, configure trusted proxies to ensure:

- Correct client IP identification for rate limiting
- HSTS header is set based on `X-Forwarded-Proto`
- Accurate logging of client addresses

```yaml
server:
  trustedProxies:
    - 10.0.0.0/8      # Kubernetes pod network
    - 172.16.0.0/12   # Private networks
```

**See [Ingress Configuration](ingress-configuration.md) for complete ingress setup.**

### TLS Configuration

```yaml
# Recommended TLS settings
server:
  tlsCertFile: /etc/breakglass/tls.crt
  tlsKeyFile: /etc/breakglass/tls.key
```

For webhook endpoints, the controller automatically generates TLS certificates. See [Webhook Setup](webhook-setup.md).

### Network Policies

Consider restricting network access:

```yaml
apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: breakglass-policy
spec:
  podSelector:
    matchLabels:
      app: breakglass
  policyTypes:
    - Ingress
    - Egress
  ingress:
    - from:
        - namespaceSelector:
            matchLabels:
              name: ingress-nginx
      ports:
        - port: 8080
  egress:
    - to:
        - namespaceSelector: {}
      ports:
        - port: 443 # HTTPS to API servers
        - port: 6443 # Kubernetes API
```

## Audit Logging

Enable audit logging to track all privilege escalation events:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: AuditConfig
metadata:
  name: default
spec:
  enabled: true
  verbosity: Detailed
```

See [Audit Configuration](audit-config.md) for details.

## Session Security

### ExtraDeployVariables Access Control

The `allowedGroups` field on ExtraDeployVariables enables fine-grained access control:

#### Variable-Level Restrictions

Restrict entire variables to specific groups:

```yaml
extraDeployVariables:
  - name: hostNetwork
    displayName: "Host Network Mode"
    inputType: boolean
    allowedGroups:  # Only these groups can set this variable
      - platform_poweruser
      - schiff-admin
```

Users not in allowed groups will receive a `403 Forbidden` error when trying to use this variable.

#### Option-Level Restrictions  

Restrict specific options within select/multiSelect variables:

```yaml
extraDeployVariables:
  - name: accessLevel
    inputType: select
    options:
      - value: "readonly"
        displayName: "Read-Only"  # Available to all
      - value: "privileged"
        displayName: "Privileged Access"
        allowedGroups:  # Only available to admins
          - schiff-admin
          - platform_emergency
```

This enables a single template to serve multiple personas with different capability levels.

#### Enforcement

- **Frontend**: Shows only options the user can select
- **API**: Validates user groups server-side and rejects unauthorized selections with clear error messages
- **Webhooks**: Admission validation ensures even direct `kubectl` creation respects group restrictions

### Duration Limits

1. **Set maximum duration** - Configure `maxValidFor` on escalations
2. **Use approval timeouts** - Set `approvalTimeout` to auto-expire pending requests
3. **Enable cleanup** - Ensure the cleanup task is running to remove expired sessions

### Approval Requirements

1. **Require approvers** - Always configure approver groups
2. **Prevent self-approval** - The system automatically prevents users from approving their own requests
3. **Multi-person approval** - Consider requiring multiple approvers for sensitive escalations

## CEL Validation Rules

Breakglass CRDs include [CEL (Common Expression Language)](https://kubernetes.io/docs/reference/using-api/cel/)
validation rules that the Kubernetes API server enforces at admission time
(requires Kubernetes 1.25+). These rules complement the Go webhook
validators and provide immediate feedback without webhook latency.

### BreakglassEscalation

| Rule | Effect |
|------|--------|
| `blockSelfApproval` requires approver groups | Prevents enabling self-approval blocking without any approver groups to approve |
| `allowedIdentityProviders` mutual exclusivity | Cannot specify both `allowedIdentityProviders` and per-role IDP lists (`allowedIdentityProvidersForRequests`/`allowedIdentityProvidersForApprovers`) |
| `sessionLimitsOverride.unlimited` conflicts | Cannot set `maxActiveSessionsPerUser`/`maxActiveSessionsTotal` when `unlimited` is true |
| `podSecurityOverrides.requireApproval` requires approvers | Cannot enable `requireApproval` without specifying who can approve |

### DenyPolicy

| Rule | Effect |
|------|--------|
| At least one rule required | A DenyPolicy must have at least one `rules` entry or `podSecurityRules` |

### IdentityProvider

| Rule | Effect |
|------|--------|
| Keycloak config required | When `groupSyncProvider` is `Keycloak`, the `keycloak` configuration block must be present |

## Related Documentation

- [Identity Provider Configuration](identity-provider.md)
- [Webhook Setup](webhook-setup.md)
- [Audit Configuration](audit-config.md)
- [Troubleshooting](troubleshooting.md)
