# Security Best Practices

This document covers security considerations and best practices for deploying and operating the breakglass controller.

## Administrative and requester trust boundaries

Ordinary users request and approve sessions through the authenticated REST API.
The API derives their identity from verified tokens and applies requester,
approver, and session policies. Kubernetes RBAC is a separate boundary:
permission to create or modify session CRs or their status is privileged
controller or automation authority. Admission validates resource fields; it
does not bind every declared requester field to the Kubernetes admission caller.
Do not grant session CR write permissions to ordinary REST users as an
alternative way to request access.

Writers of `IdentityProvider`, `ClusterConfig`, `MailProvider`, `AuditConfig`,
`DebugSessionTemplate`, `DebugPodTemplate`, bindings, and credential Secrets
control administrative policy. Selecting endpoints, service accounts, and
reviewed workload templates is intentional authority. Restrict these writes
with Kubernetes RBAC, and scope controller credentials to the resources they
need. This does not remove validation requirements or narrower constraints
promised by a policy. See [debug session authoring](debug-session-authoring.md).

Development exceptions are specific to each subsystem. Explicit SMTP or Kafka
TLS bypass options are unsafe on untrusted networks; they are not production
recommendations. The API OIDC verifier and OIDC proxy reject IDP
`insecureSkipVerify`; configure a certificate authority instead. See
[mail providers](mail-provider.md), [audit configuration](audit-config.md), and
[OIDC proxy configuration](configuration-reference.md).

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

Debug-level log statements redact sensitive data to prevent accidental exposure when verbose logging is enabled:

- JWT group memberships (`rawTokenGroups`) are omitted from all log output; only the count is logged
- Session approval tokens (the `?token=` query parameter) are redacted in request-path logs by recording only their length (`tokenLen`), and token metadata authorization helpers receive a redacted session name before emitting downstream authorization logs. Token metadata validation also requires the caller to be the requester, an authorized approver, or a historical approver before returning session state.
- OIDC group names from the token claims are logged as `[REDACTED]` in the enriched request logger

### Issuer Validation (SEC-003)

Before routing a JWT to a JWKS endpoint, the middleware validates the `iss` claim extracted from the unverified token:

- Must be a well-formed HTTPS URL (non-HTTPS schemes like `http://`, `file://`, or `javascript:` are rejected)
- Must not exceed 512 characters
- Must have a non-empty host component
- Must not include query strings, URL fragments, or userinfo (for example, `https://idp.example.com?x=1`, `https://idp.example.com/#foo`, and `https://user@idp.example.com` are all rejected)

This prevents an attacker from using a crafted issuer to trigger SSRF-like JWKS fetches to arbitrary endpoints.

### JWKS Fetch Rate Limiting (SEC-004)

The system enforces a per-issuer cooldown (`10s` minimum interval) on the initial JWKS client load. This reduces repeated startup or misconfiguration-related fetches for the same issuer and limits tight retry loops against the OIDC provider.

Subsequent JWKS refreshes (including those triggered by unknown `kid` values) are handled by the underlying JWKS client library and are not subject to this additional cooldown. You should still configure network-level and IdP-side protections (for example, rate limits) for JWKS endpoints.

These protections are in addition to the existing LRU cache for JWKS key sets.

### OIDC Proxy Egress Controls

The API exposes an **unauthenticated** OIDC proxy at `GET|POST /api/oidc/authority/*proxyPath`. It exists so the browser can fetch discovery and JWKS documents through the server origin instead of having to trust the IdP certificate directly. Because it is unauthenticated and performs server-side outbound requests, it is an SSRF-sensitive boundary and is defended in depth:

- **Path allowlist** — only well-known OIDC endpoints are proxied; absolute URLs, `..`, backslashes, and encoded traversal are rejected.
- **Authority allowlist** — the target authority must match a configured `IdentityProvider` authority by **exact string equality**. An attacker-supplied `X-OIDC-Authority` header for an unknown host is rejected with `403`.
- **Host pinning** — the resolved target URL is rejected if its scheme or host differs from the selected authority.
- **No redirect following** — the HTTP client refuses upstream `30x` responses. Only the *first* hop is validated against the authority allowlist, so following a redirect would let a trusted-but-redirecting IdP steer a server-side request to an arbitrary host. The `30x` status is relayed to the caller, but `Location` and `Set-Cookie` are stripped by the response-header allowlist.
- **Response size cap** — the relayed body is capped at 1 MiB. Real discovery documents are a few KiB and even a large JWKS stays well under 256 KiB, so this leaves ample headroom while removing an unbounded-copy DoS vector. A truncated response is logged at `Error` level and counted as `response_too_large`. A body of *exactly* 1 MiB is relayed in full and reported as a success: hitting the limit is only treated as truncation if the upstream body actually continues past it.
- **No credential relay** — `Authorization` and `Cookie` are never forwarded upstream.

**Always configure an `https://` authority.** A plaintext `http://` authority gives the outbound first hop no CA policy and no server identity check, so DNS or on-path control of the authority hostname becomes a full SSRF primitive with *no redirect involved* — the redirect refusal cannot help. The `IdentityProvider` CRD enforces `^https://.+` for `spec.oidc.authority` and `spec.keycloak.baseURL`; only legacy file-based configuration can reach the plaintext path, and doing so logs a loud `oidc_proxy_insecure_http_authority` warning and reports `breakglass_oidc_proxy_tls_mode{mode="http"} 1`.

> `server.allowOIDCProxyRedirects: true` restores redirect following for a non-conforming IdP. This re-enables the SSRF path described above and logs a warning at startup. Leave it unset unless you have verified the redirect targets are trusted.

### Audience Validation (SEC-005)

Every `IdentityProvider` CRD must set `spec.oidc.expectedAudience`. The middleware validates the JWT `aud` claim against that value. This prevents token reuse from other services that share the same OIDC provider — a common cross-service token confusion attack.

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: IdentityProvider
spec:
  oidc:
    clientID: "breakglass-ui"
    expectedAudience: "breakglass-ui"
```

This requires a matching audience protocol mapper in your identity provider (e.g., Keycloak) that adds the expected value to the `aud` claim in issued tokens. Existing `IdentityProvider` resources created before this requirement must be updated with `spec.oidc.expectedAudience` before applying the new CRD or rolling out the new controller.

### Token Storage in the Browser

The browser frontend uses `sessionStorage` through `oidc-client-ts` by default.
Development builds may explicitly opt into persistent `localStorage` storage;
that mode is warned about because browser scripts can read it. Production builds
always use `sessionStorage`, reset a stale persistent preference, and purge or
ignore legacy localStorage OIDC artifacts, including IDP name hints used for
reauthentication. Access tokens remain readable by same-origin JavaScript and
are explicitly attached as Bearer tokens to API requests. Session storage limits
persistence and prevents other origins from reading it; it does not protect
tokens from compromised same-origin scripts. Browser-local cached runtime
configuration is bootstrap state, not the server's issuer authorization policy.

CSP restricts script sources and reduces injection opportunities, but cannot
guarantee that every XSS payload is blocked. Keep access tokens short-lived
(for example, 5–15 minutes), constrain their audience, and avoid logging token
objects or authenticated HTTP request configurations. Bearer authentication
avoids the automatic cookie credential attachment that enables conventional
cookie-based CSRF; it does not remove XSS or other request-forgery risks.

An `httpOnly` cookie design would require a server-side session or
Backend-for-Frontend layer with its own CSRF protection. That is a different
architecture, not a configuration switch in this SPA. The development mock API
uses synthetic records and does not exercise production authentication; see
[the frontend development guide](../frontend/README.md).

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
2. **Disable UI refresh tokens** - Do not issue `offline_access` or refresh tokens for breakglass UI sessions; use short access-token lifetimes and require explicit re-authentication instead
3. **Validate audiences** - Ensure tokens are issued for the breakglass client
4. **Use HTTPS** - Always use TLS for OIDC communication
5. **Keep `hardenedIDPHints` enabled** (default) - Prevents disclosure of configured identity provider names and URLs in webhook error messages. See [Configuration Reference](configuration-reference.md#hardenedidphints-optional) for details.

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

Restrict network access to the breakglass pods. The SAR authorization webhook (`/breakglass/webhook/authorize/:cluster_name`) is intentionally unauthenticated — see [SAR Authorization Webhook](#sar-authorization-webhook-design-decision) below for details. Use a NetworkPolicy to ensure only the Kubernetes API server can reach the webhook port.

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
              kubernetes.io/metadata.name: ingress-nginx
      ports:
        - port: 8080
    # Allow Kubernetes API server to reach the SAR webhook (served by Gin API)
    - from:
        - ipBlock:
            cidr: <API_SERVER_CIDR>  # Replace with your API server IP range
      ports:
        - port: 8080  # SAR webhook via Gin API port
  egress:
    - to:
        - namespaceSelector: {}
      ports:
        - port: 443 # HTTPS to API servers
        - port: 6443 # Kubernetes API
```

### SAR Authorization Webhook (Design Decision)

The SAR handler accepts Kubernetes
[SubjectAccessReview](https://kubernetes.io/docs/reference/access-authn-authz/authorization/#checking-api-access)
requests without authenticating the HTTP caller. It is exposed on the shared
Gin API listener (default port 8080) at both
`/breakglass/webhook/authorize/:cluster_name` and
`/api/breakglass/webhook/authorize/:cluster_name`. The admission webhook listener
on port 9443 is separate. Rate limiting reduces abuse but does not authenticate
SAR callers.

The SAR body contains asserted user and group identities. Only the API server
or another explicitly trusted caller should reach these routes. A direct call
returns an authorization decision, not Kubernetes permissions or credentials,
but can disclose decisions and affect activity tracking, counters, and logs.
The [Kubernetes webhook protocol](https://kubernetes.io/docs/reference/access-authn-authz/webhook/) can use transport authentication; the built-in
Gin handler does not validate a configured kubeconfig bearer token or client
certificate. A validating gateway or proxy must provide that protection when
required; see [webhook setup](webhook-setup.md#transport-authentication).

Restrict direct pod access with NetworkPolicy and protect **both route aliases**
at any ingress or gateway. Allowing ingress-controller pods through a
NetworkPolicy does not authenticate public callers of `/api/*`. Deny public
routing to the SAR paths or require authentication at a trusted gateway.
Kubernetes audit logs cover requests processed by the API server; use service
and gateway logging to observe direct HTTP calls as well.

### Build Info Endpoint

The `/api/debug/buildinfo` endpoint exposes only the application version and build date. Infrastructure details (Go version, OS/architecture, commit hash) are omitted from the public response to prevent reconnaissance.

If full build metadata is needed for debugging, check the controller logs at startup (which include version, commit, and build date) or inspect the compiled binary's `-ldflags` values.

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
- **Webhooks**: Validate resource shape and configured values. Direct CR writes are privileged; admission must not be treated as authenticating the declared requester or replacing REST group authorization.

### Duration Limits

1. **Set maximum duration** - Configure `maxValidFor` on escalations
2. **Use approval timeouts** - Set `approvalTimeout` to auto-expire pending requests
3. **Enable cleanup** - Ensure the cleanup task is running to remove expired sessions

### Approval Requirements

1. **Require approvers** - Always configure approver groups
2. **Prevent self-approval** - The system automatically prevents users from approving their own requests
3. **Multi-person approval** - Consider requiring multiple approvers for sensitive escalations

### Approver Group Verification and the Unverified-Groups Fallback

Approval authorization normally resolves the approver's groups **on the target spoke cluster** (via `SelfSubjectReview` under impersonation), not from the caller's JWT. Cluster-verified groups are strictly stronger evidence than JWT claims.

When that spoke-side lookup fails (spoke unreachable, credentials expired, RBAC changed), breakglass does **not** hard-fail. This is deliberate and reflects an asymmetric failure model: a wrong *deny* locks operators out of production during exactly the kind of incident breakglass exists to resolve, which is generally worse than a wrong *allow* that is fully attributed and alertable. Instead the lookup failure is treated as "**no verified groups**" and the decision falls through to the pre-existing, explicitly scoped request-context (JWT-claim) group fallback:

- If the caller would have been authorized on verified groups anyway, the outcome is unchanged.
- If the caller has no matching group in either source, they are denied as before.
- If the JWT-claim groups are **load-bearing** for an allow, the approval is granted but recorded as based on unverified evidence.

Every lookup failure is observable, so the fallback is never silent:

| Signal | Meaning |
|---|---|
| `breakglass_approval_group_lookup_failures_total{cluster}` | A spoke-side approver group lookup failed. At least one approval lost its verified basis. |
| `breakglass_approval_unverified_group_decisions_total{cluster}` | An approval was **granted** on unverified JWT-claim groups. Security-relevant subset of the above. |
| `session.approval_unverified_groups` audit event | Per-decision record (severity `warning`, classified as sensitive) with approver, cluster, matched group, and identity provider. |
| `Error`-level log | The underlying lookup error with cluster context, emitted on every failure. |

**Recommendations:**

1. **Alert on `breakglass_approval_unverified_group_decisions_total`** — any non-zero rate means approvals are being granted on weaker evidence and warrants review of both the approvals and the spoke connectivity.
2. **Alert on `breakglass_approval_group_lookup_failures_total`** as an availability signal — it is the leading indicator for the above.
3. **Review the `session.approval_unverified_groups` audit trail** after any spoke outage.
4. **Keep spoke credentials healthy** — the fallback is a safety net for incidents, not a supported steady state.

## Cross-Site Request Forgery (CSRF) Protection

The breakglass frontend is **not vulnerable to CSRF** because it uses **OIDC Bearer token authentication** rather than cookie-based sessions:

- All API requests include an `Authorization: Bearer <token>` header injected by the HTTP client interceptor (`frontend/src/services/httpClient.ts`).
- OIDC access tokens default to browser `sessionStorage` via `oidc-client-ts`, **not** cookies; development-only persistent `localStorage` is an explicit opt-in and production always uses session storage.
- The browser never automatically attaches credentials to cross-origin requests, so a malicious site cannot forge authenticated API calls.

This architecture inherently mitigates CSRF because:

1. **No ambient credentials** — Unlike session cookies, Bearer tokens must be explicitly attached to each request by JavaScript code.
2. **Same-origin policy** — A cross-origin page cannot read `sessionStorage` of the breakglass domain.
3. **No `withCredentials`** — The axios client does not set `withCredentials: true`, so cookies (if any existed) would not be sent cross-origin.

> **If you add cookie-based session state in the future**, you must implement CSRF protection (e.g., `SameSite=Strict` cookies, double-submit token pattern, or the `Synchronizer Token Pattern`).

## Related Documentation

- [Identity Provider Configuration](identity-provider.md)
- [Webhook Setup](webhook-setup.md)
- [Audit Configuration](audit-config.md)
- [Troubleshooting](troubleshooting.md)
