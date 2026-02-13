# Configuration Reference

Complete reference for the breakglass configuration file (`config.yaml`).

**Default Path**: `./config.yaml`  
**Environment Override**: `BREAKGLASS_CONFIG_PATH=/path/to/config.yaml`

## Overview

The breakglass configuration file controls:

- Server and TLS settings
- Frontend UI behavior
- Kubernetes cluster settings

**Note:** The following are **NOT** configured in config.yaml:

- **OIDC/IDP authentication** - Configured via **IdentityProvider CRDs**. See [Identity Provider documentation](identity-provider.md).
- **Email notifications** - Configured via **MailProvider CRDs**. See [Mail Provider documentation](mail-provider.md).

## Configuration File Format

```yaml
server:
  listenAddress: :8080

frontend:
  baseURL: https://breakglass.example.com
  brandingName: "Das SCHIFF Breakglass"  # optional
  uiFlavour: "oss"  # optional

kubernetes:
  context: ""
  oidcPrefixes:
    - "oidc:"
```

**Notes:**

- Email configuration has been moved to **MailProvider CRDs** - see [Mail Provider documentation](mail-provider.md)
- OIDC/IDP configuration has been moved to **IdentityProvider CRDs** - see [Identity Provider documentation](identity-provider.md)

## Section Reference

### `server`

HTTP server configuration.

#### `listenAddress`

The address and port the HTTP server binds to.

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Default** | `:8080` |
| **Example** | `:8080`, `0.0.0.0:8080`, `127.0.0.1:3000` |

```yaml
server:
  listenAddress: :8080
```

#### `tlsCertFile` (Optional)

Path to TLS certificate file for HTTPS.

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Default** | `` (HTTP only) |
| **Example** | `/etc/breakglass/tls.crt`, `/var/secrets/cert.pem` |

```yaml
server:
  tlsCertFile: /etc/breakglass/tls.crt
  tlsKeyFile: /etc/breakglass/tls.key
```

**Note**: Both `tlsCertFile` and `tlsKeyFile` must be set for HTTPS to work.

#### `tlsKeyFile` (Optional)

Path to TLS private key file for HTTPS.

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Default** | `` (HTTP only) |
| **Example** | `/etc/breakglass/tls.key`, `/var/secrets/key.pem` |

---

#### `allowedOrigins`

Explicit list of browser origins allowed to make credentialed API requests (CORS).

| Property | Value |
|----------|-------|
| **Type** | `[]string` |
| **Default** | Empty (no origins allowed). When `BREAKGLASS_ALLOW_DEFAULT_ORIGINS=true` is set **and** no custom origins are configured, falls back to local development origins: `https://localhost:8443`, `http://localhost:28081`, `http://localhost:28080`, `http://localhost:5173` |
| **Example** | `https://breakglass.example.com`, `https://admin.example.net` |

```yaml
server:
  allowedOrigins:
    - https://breakglass.example.com
    - https://admin.example.net
```

**Notes:**

- These origins must include scheme + host (and optional port); paths are ignored.
- Requests whose `Origin` header is not on this list are rejected before hitting any handler—even if the CORS middleware is bypassed.
- When left empty, the server falls back to a safe set of localhost origins plus the configured `frontend.baseURL` for developer convenience.
- **Important:** If you specify custom `allowedOrigins`, the frontend base URL is *not* auto-included. Add the UI origin explicitly whenever you override this list.

**Operational Guidance - CORS Origins:**

| Scenario | Recommended Configuration |
|----------|---------------------------|
| Single domain deployment | Add only `https://breakglass.yourdomain.com` |
| Multi-region with CDN | Add each CDN endpoint origin (e.g., `https://breakglass-us.example.com`, `https://breakglass-eu.example.com`) |
| Development + Production | Use separate config files; never include `localhost` origins in production |
| Behind reverse proxy | Use the external-facing origin, not internal service names |

**Security Best Practices:**

1. **Never use wildcard origins** (`*`) - Breakglass explicitly rejects wildcard CORS.
2. **Audit origins regularly** - Remove stale or decommissioned frontend URLs.
3. **Use HTTPS only** in production - HTTP origins should only appear in development configs.
4. **Match exactly** - `https://breakglass.example.com` and `https://breakglass.example.com:443` are treated as different origins.

**Troubleshooting CORS Issues:**

```bash
# Check if origin is allowed (look for blocked_request_origin in logs)
kubectl logs -l app=breakglass-controller | grep blocked_request_origin

# Verify CORS headers in response
curl -v -H "Origin: https://breakglass.example.com" https://api.breakglass.example.com/api/config
```

---

#### `trustedProxies` (Optional)

List of CIDR ranges or IP addresses of trusted reverse proxies for `X-Forwarded-For` header processing.

| Property | Value |
|----------|-------|
| **Type** | `[]string` |
| **Default** | `[]` (trust no proxies - safe default) |
| **Example** | `["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"]` |

```yaml
server:
  trustedProxies:
    - 10.0.0.0/8      # Private networks
    - 172.16.0.0/12   # Private networks
    - 127.0.0.1       # Loopback
```

**Notes:**

- When set, Gin uses `X-Forwarded-For` headers from these proxies to determine client IP.
- When empty (default), the server uses the direct connection IP for rate limiting and logging.
- **Security Warning:** Only trust proxies you control. Untrusted proxies can spoof client IPs.

> **⚠️ Important:** Misconfiguring trusted proxies can allow attackers to bypass rate limiting by
> spoofing the `X-Forwarded-For` header. See [Security Best Practices: Rate Limiting](./security-best-practices.md#rate-limiting)
> for detailed guidance and best practices.

**Operational Guidance - Trusted Proxies:**

| Deployment | Recommended Configuration |
|------------|---------------------------|
| Direct (no proxy) | Leave empty `[]` |
| Kubernetes Ingress (NGINX) | Add pod network CIDR (e.g., `10.244.0.0/16`) |
| Cloud Load Balancer | Add LB IP ranges (check cloud provider docs) |
| Multiple proxy layers | Add all proxy layer CIDRs |

---

#### `hardenedIDPHints` (Optional)

Controls whether identity provider names are exposed in authorization error messages.

| Property | Value |
|----------|-------|
| **Type** | `bool` |
| **Default** | `false` |
| **Secure Setting** | `true` |

```yaml
server:
  hardenedIDPHints: true
```

**Behavior:**

- `false` (default): When authentication fails due to an unknown token issuer, the error message lists available identity providers to help users identify which IDP to use.
  - Example: `"Your token issuer 'https://wrong.issuer.com' is not configured. Available providers: keycloak, azure-ad"`

- `true` (hardened): Error messages do not expose configured identity provider names, preventing reconnaissance attacks.
  - Example: `"Your token issuer is not configured for this cluster"`

**Security Considerations:**

- In high-security environments, set `hardenedIDPHints: true` to prevent attackers from discovering which identity providers are configured.
- In user-friendly environments (e.g., internal platforms), leave as `false` to help users troubleshoot authentication issues.

---

### `frontend`

Frontend UI configuration.

#### `baseURL`

Base URL of the breakglass frontend (for redirects and links).

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Required** | Yes |
| **Example** | `https://breakglass.example.com`, `http://localhost:5173` |

```yaml
frontend:
  baseURL: https://breakglass.example.com
```

Used for:

- OIDC redirect URIs
- Links in email notifications
- Frontend JavaScript API calls
- **Webhook authorization messages** - When access is denied, the webhook response includes a link to this URL so users can request access via the UI

**Important**: This URL must be resolvable by users' browsers. In production deployments, always set this to the externally accessible URL of your breakglass frontend. Using `localhost` URLs in production will result in confusing error messages for users.

#### `brandingName` (Optional)

Custom product name displayed in UI header and page title.

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Default** | `` (neutral placeholder) |
| **Example** | `Das SCHIFF Breakglass`, `Platform Breakglass` |

```yaml
frontend:
  brandingName: "Das SCHIFF Breakglass"
```

When set, displayed in:

- Page title (`<title>`)
- Header/navbar
- Email subjects
- Notifications

#### `uiFlavour` (Optional)

UI theme/appearance at runtime.

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Default** | `oss` |
| **Valid Values** | `oss`, `telekom`, `neutral` |
| **Example** | `telekom` |

```yaml
frontend:
  uiFlavour: "telekom"
```

**Options:**

- `oss` - OSS neutral theme (default, suitable for all organizations)
- `telekom` - Deutsche Telekom branded theme
- `neutral` - Neutral theme (equivalent to `oss`)

**Note**: This controls the Scale UI components appearance (colors, styles). The actual theme must be built into the container image.

---

### `mail` (DEPRECATED - REMOVED)

⚠️ **DEPRECATED**: The `mail` configuration section has been **removed** in favor of **MailProvider CRDs**.

**Migration Required**: Email configuration is now managed via Kubernetes Custom Resources. This provides:

- Multiple SMTP provider support
- Per-escalation provider selection
- Dynamic reconfiguration without restarts
- Secret-based credential management
- Built-in health checking and status reporting
- Provider-specific metrics

**New Approach**: Create a **MailProvider** resource:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: MailProvider
metadata:
  name: production-smtp
spec:
  displayName: "Production SMTP"
  default: true
  smtp:
    host: smtp.example.com
    port: 587
    username: breakglass@example.com
    passwordRef:
      name: smtp-credentials
      namespace: breakglass-system
      key: password
  sender:
    address: noreply@example.com
    name: "Breakglass System"
  retry:
    count: 3
    initialBackoffMs: 100
    queueSize: 1000
```

See [Mail Provider Documentation](./mail-provider.md) for complete configuration options, validation rules, and examples.

---

### `kubernetes`

Kubernetes cluster access configuration.

#### `context` (Optional)

kubectl context to use for cluster access.

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Default** | `` (current context) |
| **Example** | `kubernetes-admin@kubernetes` |

```yaml
kubernetes:
  context: ""
```

If empty, uses the current context from `~/.kube/config`.

#### `oidcPrefixes`

List of prefixes to strip from OIDC user group names for cluster matching.

| Property | Value |
|----------|-------|
| **Type** | `[]string` |
| **Default** | `["oidc:", "keycloak:"]` |
| **Example** | `["oidc:", "keycloak:", "adfs/"]` |

```yaml
kubernetes:
  oidcPrefixes:
    - "oidc:"
    - "keycloak:"
```

**Purpose**: Normalizes group names across different OIDC providers.

**Example**:

- OIDC provider returns: `oidc:site-reliability-engineers`
- After prefix stripping: `site-reliability-engineers`
- Matched against: BreakglassEscalation `allowed.groups: ["site-reliability-engineers"]`

#### `clusterConfigCheckInterval` (Optional)

Interval for checking ClusterConfig resource validity.

| Property | Value |
|----------|-------|
| **Type** | `duration string` |
| **Default** | `10m` |
| **Example** | `5m`, `30m`, `1h` |

```yaml
kubernetes:
  clusterConfigCheckInterval: "10m"
```

Valid formats: `30s`, `5m`, `1h`

**Note**: Can also be set via CLI flag `--cluster-config-check-interval` (takes precedence).

#### `userIdentifierClaim` (Optional)

Specifies which OIDC claim to use as the user identifier for session matching. This is a global default that can be overridden per-cluster in ClusterConfig.

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Default** | `email` |
| **Valid Values** | `email`, `preferred_username`, `sub` |

```yaml
kubernetes:
  userIdentifierClaim: "email"
```

**Purpose**: Controls which JWT claim is used to identify users when creating sessions. This value is stored in `spec.user` of BreakglassSession and must match the claim configured in spoke clusters' OIDC `claimMappings.username.claim`.

**Priority**: ClusterConfig setting > Global config > Default (email)

**Example**:

If your spoke clusters are configured with OIDC like:
```yaml
# kube-apiserver OIDC flags on spoke cluster
--oidc-username-claim=preferred_username
```

Then set:
```yaml
kubernetes:
  userIdentifierClaim: "preferred_username"
```

This ensures that when the spoke cluster sends SubjectAccessReview requests to the hub, the username in the SAR matches the user identifier stored in the session.

---

## Complete Example

```yaml
# Server configuration
server:
  listenAddress: :8080
  tlsCertFile: /etc/breakglass/tls.crt
  tlsKeyFile: /etc/breakglass/tls.key

# Frontend UI configuration
frontend:
  baseURL: https://breakglass.example.com
  brandingName: "Das SCHIFF Breakglass"
  uiFlavour: "telekom"

# Kubernetes cluster settings
kubernetes:
  context: ""
  clusterConfigCheckInterval: "10m"
  userIdentifierClaim: "email"  # Which OIDC claim to use for user matching
  oidcPrefixes:
    - "oidc:"
    - "keycloak:"
```

**Notes:**

- **OIDC/IDP configuration** (authority, clientID, JWKS, etc.) is now managed via **IdentityProvider CRDs**. See [Identity Provider documentation](identity-provider.md).
- **Email notifications** are now managed via **MailProvider CRDs**. See [Mail Provider documentation](mail-provider.md).

## Environment Variables

Some settings can be overridden via environment variables:

| Setting | Environment Variable | Priority |
|---------|----------------------|----------|
| Config file path | `BREAKGLASS_CONFIG_PATH` | 1 (highest) |
| Disable email | `BREAKGLASS_DISABLE_EMAIL` | 1 (highest) |
| Enable default CORS origins | `BREAKGLASS_ALLOW_DEFAULT_ORIGINS` | 1 (highest) |

```bash
# Use custom config file
export BREAKGLASS_CONFIG_PATH=/etc/breakglass/production.yaml
breakglass-controller

# Disable email notifications
export BREAKGLASS_DISABLE_EMAIL=true
breakglass-controller

# Enable default localhost CORS origins (useful for local development)
# When set to "true" and no custom origins are configured, falls back to
# http://localhost:5173, http://localhost:28080, http://localhost:28081,
# and https://localhost:8443 as the CORS allow-list.
# Has no effect when custom origins are explicitly configured.
export BREAKGLASS_ALLOW_DEFAULT_ORIGINS=true
breakglass-controller
```

## Configuration Loading

Breakglass loads configuration in this order:

1. **Read config file** from `--config-path` (or `BREAKGLASS_CONFIG_PATH`)
2. **Apply environment variable overrides** (for specific settings)
3. **Apply CLI flag overrides** (for flags)
4. **Use defaults** for unset values

**Priority** (highest to lowest):

1. CLI flags
2. Environment variables
3. Config file
4. Default values

## Validation

Breakglass validates configuration on startup:

- **REQUIRED**: `frontend.baseURL`
- **REQUIRED**: `mail.host` (unless `--disable-email` flag set)
- **REQUIRED**: At least one IdentityProvider CRD must exist in the cluster

**If validation fails**: Controller exits with error message.

```text
Fatal error: IdentityProvider validation failed: no IdentityProvider resources found
```

## Secrets and Sensitive Data

For sensitive data in configuration files:

1. **Use Kubernetes Secrets** to store the config file
2. **Mount as volume** in pod
3. **Reference via `--config-path` flag**

**Example:**

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: breakglass-config
  namespace: breakglass-system
type: Opaque
data:
  config.yaml: |
    YXV0aG9yaXphdGlvbnNlcnZlcjoKICB... # Base64 encoded
---
apiVersion: apps/v1
kind: Deployment
metadata:
  name: breakglass-controller
spec:
  template:
    spec:
      containers:
      - name: controller
        args:
          - --config-path=/etc/breakglass/config.yaml
        volumeMounts:
        - name: config
          mountPath: /etc/breakglass
          readOnly: true
      volumes:
      - name: config
        secret:
          secretName: breakglass-config
```

## Timeouts and Rate Limiting

### HTTP Server Timeouts

The breakglass API server applies sensible defaults for HTTP timeouts. These are not configurable via config.yaml but can be tuned via environment variables or by modifying the deployment.

| Timeout | Default | Purpose |
|---------|---------|---------|
| Read Timeout | 30s | Maximum time to read request body |
| Write Timeout | 30s | Maximum time to write response |
| Idle Timeout | 120s | Keep-alive connection timeout |
| Shutdown Timeout | 30s | Grace period for in-flight requests during shutdown |

**Operational Guidance - Timeouts:**

```yaml
# Kubernetes deployment with custom timeouts
apiVersion: apps/v1
kind: Deployment
spec:
  template:
    spec:
      containers:
      - name: controller
        # Configure terminationGracePeriodSeconds to allow graceful shutdown
        # Should be >= server shutdown timeout (30s) + buffer
        terminationGracePeriodSeconds: 45
        livenessProbe:
          httpGet:
            path: /healthz
            port: 8081
          timeoutSeconds: 5
          periodSeconds: 10
        readinessProbe:
          httpGet:
            path: /readyz
            port: 8081
          timeoutSeconds: 5
          periodSeconds: 5
```

### Rate Limiting

Breakglass implements multi-tier rate limiting to protect against DoS attacks while allowing legitimate traffic. See [Rate Limiting](./rate-limiting.md) for the full reference including architecture, debugging guidance, and tuning options.

| Tier | Limit | Burst | Scope | Applied To |
|------|-------|-------|-------|------------|
| Public (unauthenticated) | 20 req/s | 50 | Per IP | All requests (before auth) |
| Authenticated (unauthenticated path) | 10 req/s | 20 | Per IP | Public API endpoints without valid JWT |
| Authenticated (with valid JWT) | 50 req/s | 100 | Per user | Public API endpoints with valid JWT |
| SAR Webhook | 1000 req/s | 5000 | Per IP | SubjectAccessReview from spoke clusters |

> **Note:** Rate limit headers (`X-RateLimit-*`, `Retry-After`) are **not currently emitted** by the server. Clients receive a `429 Too Many Requests` JSON response when rate limited.

**Operational Guidance - Rate Limiting:**

1. **Static asset exclusions:** Requests to `/assets/` and `/favicon` paths bypass the public rate limiter.

2. **Dual-layer limiting:** Requests to authentication-optional endpoints (e.g., `/api/config`) hit the global per-IP limiter first, then the authenticated limiter. Authenticated users get significantly higher limits (50 req/s vs 10 req/s).

3. **IP-based vs User-based limiting:**
   - Unauthenticated requests are limited by source IP
   - On auth-required endpoints, authenticated requests are limited by the JWT `email` claim; if `email` is missing, the rate limiter falls back to per-IP tracking
   - On auth-optional endpoints (e.g., `/api/config`), the middleware extracts user identity from the JWT `email` claim with fallback to `sub` (subject)
   - Behind proxies, ensure `trustedProxies` is configured correctly for accurate IP detection

4. **Rate limits are currently hardcoded.** For custom limits, modify `pkg/ratelimit/ratelimit.go` and rebuild. The `DefaultAPIConfig()`, `DefaultAuthenticatedAPIConfig()`, and `DefaultSARConfig()` functions define the default values.

5. **Memory management:** Rate limiter entries are automatically cleaned up. Unused per-IP entries expire after 5 minutes; per-user entries expire after 10 minutes. Cleanup runs every 60 seconds.

### Approver Resolution Limits

When a `BreakglassSession` is created, the controller resolves all potential approvers from configured `BreakglassEscalation` resources. To prevent resource exhaustion from extremely large groups (e.g., misconfigured LDAP groups containing thousands of members), the controller enforces hard limits on approver resolution:

| Limit | Value | Purpose |
|-------|-------|---------|
| MaxApproverGroupMembers | 1,000 | Maximum members resolved per individual approver group |
| MaxTotalApprovers | 5,000 | Maximum total approvers across all matched escalations |

**Behavior when limits are exceeded:**

1. **Per-group limit (MaxApproverGroupMembers):** If a single approver group contains more than 1,000 members, only the first 1,000 are added. A warning is logged:
   ```
   Approver group has too many members, truncating
   ```

2. **Total limit (MaxTotalApprovers):** If the total approvers would exceed 5,000, resolution stops early. Groups are skipped entirely when no capacity remains. Warnings are logged:
   ```
   No remaining capacity for approvers, skipping group
   ```
   Or when truncating to fit:
   ```
   Truncating members to fit within total approvers limit
   ```
   And when the limit is reached:
   ```
   Maximum total approvers limit reached, stopping escalation processing
   ```

3. **Matched escalation preserved:** Even when limits cause truncation, the matched `BreakglassEscalation` is still recorded. This ensures escalation matching logic works correctly regardless of approver count limits.

**Operational Guidance - Approver Limits:**

1. **Monitor warning logs:** Watch for truncation warnings in controller logs:
   ```bash
   kubectl logs -n breakglass-system -l app=breakglass-manager | grep -i "truncat\|too many members\|no remaining capacity"
   ```

2. **Check approver counts:** Sessions with truncated approvers will still work correctly, but some potential approvers may not be notified.

3. **Review large groups:** If warnings appear frequently, review your `BreakglassEscalation` configurations. Consider:
   - Using more specific/smaller approver groups
   - Breaking large escalations into multiple targeted ones
   - Ensuring LDAP/AD groups are scoped appropriately

4. **These limits are hardcoded:** Currently, these values cannot be configured. They are designed to handle worst-case scenarios while allowing legitimate large deployments. If you need different limits, modify the constants in `pkg/breakglass/session_controller.go` and rebuild.

## Troubleshooting

### "Configuration file not found"

```text
Error loading config: open config.yaml: no such file or directory
```

**Solutions**:

1. Check file exists: `ls -la config.yaml`
2. Use absolute path: `--config-path=/etc/breakglass/config.yaml`
3. Set environment variable: `export BREAKGLASS_CONFIG_PATH=/etc/breakglass/config.yaml`

### "Required field missing"

```text
Fatal error: missing required configuration field 'frontend.identityProviderName'
```

**Solutions**:

1. Add missing field to config.yaml
2. Verify IdentityProvider Kubernetes resource exists
3. Check field name spelling (case-sensitive)

### "OIDC provider unreachable"

```text
Error validating OIDC configuration: context deadline exceeded
```

**Solutions**:

1. Verify `authorizationserver.url` is correct and reachable
2. Check network connectivity to OIDC provider
3. Verify TLS certificates if using HTTPS

### "Email sending fails"

```text
Error sending email: connection refused
```

**Solutions**:

1. Verify SMTP server `host` and `port` are correct
2. Check firewall allows outbound SMTP
3. Test with `telnet host port`
4. For development, set `insecureSkipVerify: true` (development only!)

---

## Related Documentation

- [Installation Guide](./installation.md) - Step-by-step setup
- [CLI Flags Reference](./cli-flags-reference.md) - Controller flags
- [Identity Provider](./identity-provider.md) - IdentityProvider configuration
- [BreakglassEscalation](./breakglass-escalation.md) - Escalation policies
- [Advanced Features](./advanced-features.md) - Domain restrictions, request reasons
