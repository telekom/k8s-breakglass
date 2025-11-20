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

**Important**: This URL must be resolvable by users' browsers.

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

```bash
# Use custom config file
export BREAKGLASS_CONFIG_PATH=/etc/breakglass/production.yaml
breakglass-controller

# Disable email notifications
export BREAKGLASS_DISABLE_EMAIL=true
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

```
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

## Troubleshooting

### "Configuration file not found"

```
Error loading config: open config.yaml: no such file or directory
```

**Solutions**:
1. Check file exists: `ls -la config.yaml`
2. Use absolute path: `--config-path=/etc/breakglass/config.yaml`
3. Set environment variable: `export BREAKGLASS_CONFIG_PATH=/etc/breakglass/config.yaml`

### "Required field missing"

```
Fatal error: missing required configuration field 'frontend.identityProviderName'
```

**Solutions**:
1. Add missing field to config.yaml
2. Verify IdentityProvider Kubernetes resource exists
3. Check field name spelling (case-sensitive)

### "OIDC provider unreachable"

```
Error validating OIDC configuration: context deadline exceeded
```

**Solutions**:
1. Verify `authorizationserver.url` is correct and reachable
2. Check network connectivity to OIDC provider
3. Verify TLS certificates if using HTTPS

### "Email sending fails"

```
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
