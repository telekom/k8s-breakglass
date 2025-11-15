# Configuration Reference

Complete reference for the breakglass configuration file (`config.yaml`).

**Default Path**: `./config.yaml`  
**Environment Override**: `BREAKGLASS_CONFIG_PATH=/path/to/config.yaml`

## Overview

The breakglass configuration file controls:
- Server and TLS settings
- OIDC authentication
- Frontend UI behavior
- Email notifications
- Kubernetes cluster settings

## Configuration File Format

```yaml
server:
  listenAddress: :8080

authorizationserver:
  url: https://keycloak.example.com/realms/master
  jwksEndpoint: "protocol/openid-connect/certs"

frontend:
  identityProviderName: "production-idp"
  baseURL: https://breakglass.example.com

mail:
  host: smtp.example.com
  port: 587
  senderAddress: breakglass@example.com

kubernetes:
  context: ""
  oidcPrefixes:
    - "oidc:"
```

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

### `authorizationserver`

OIDC authentication provider configuration.

#### `url`

Base URL of the OIDC provider.

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Required** | Yes |
| **Example** | `https://keycloak.example.com/realms/master` |

```yaml
authorizationserver:
  url: https://keycloak.example.com/realms/master
```

#### `jwksEndpoint`

Relative path to the JWKS (JSON Web Key Set) endpoint.

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Required** | Yes |
| **Example** | `protocol/openid-connect/certs` (Keycloak), `oauth/discovery/keys` (other providers) |

```yaml
authorizationserver:
  url: https://keycloak.example.com/realms/master
  jwksEndpoint: "protocol/openid-connect/certs"
```

The full JWKS URL will be: `{url}/{jwksEndpoint}`

**For common OIDC providers:**

| Provider | URL | JWKS Endpoint |
|----------|-----|---------------|
| Keycloak | `https://keycloak.example.com/realms/master` | `protocol/openid-connect/certs` |
| Azure AD | `https://login.microsoftonline.com/{tenant}/v2.0` | `.well-known/openid-configuration` |
| Okta | `https://yourorgname.okta.com/oauth2/default` | `v1/keys` |
| Google | `https://accounts.google.com` | `.well-known/openid-configuration` |

---

### `frontend`

Frontend UI and authentication configuration.

#### `identityProviderName` (REQUIRED)

Name of the IdentityProvider Kubernetes resource to use.

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Required** | Yes |
| **Example** | `production-idp` |

```yaml
frontend:
  identityProviderName: "production-idp"
```

This must reference an existing IdentityProvider CR:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: IdentityProvider
metadata:
  name: production-idp
spec:
  primary: true
  oidc:
    authority: "https://keycloak.example.com/realms/master"
    clientID: "breakglass-ui"
```

**Important**: Breakglass will fail to start if the referenced IdentityProvider doesn't exist.

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

### `mail`

Email notification configuration.

#### `host`

SMTP server hostname.

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Required** | Yes (unless emails disabled) |
| **Example** | `smtp.gmail.com`, `mail.example.com`, `127.0.0.1` |

```yaml
mail:
  host: smtp.example.com
```

#### `port`

SMTP server port.

| Property | Value |
|----------|-------|
| **Type** | `int` |
| **Required** | Yes (unless emails disabled) |
| **Default** | `587` (typical for SMTP with TLS) |
| **Example** | `587`, `25`, `465` |

```yaml
mail:
  host: smtp.example.com
  port: 587
```

**Common ports:**
- `25` - SMTP (unencrypted, rarely used)
- `587` - SMTP with STARTTLS (recommended)
- `465` - SMTP with TLS (implicit)

#### `insecureSkipVerify` (Optional)

Skip TLS certificate verification (for testing only).

| Property | Value |
|----------|-------|
| **Type** | `bool` |
| **Default** | `false` |
| **Example** | `true` |

```yaml
mail:
  insecureSkipVerify: true  # Only for development/testing!
```

⚠️ **Security Warning**: Only use in development. Never enable in production.

#### `username` (Optional)

SMTP authentication username.

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Default** | `` (no authentication) |
| **Example** | `breakglass@example.com`, `smtp-user` |

```yaml
mail:
  username: breakglass@example.com
```

#### `password` (Optional)

SMTP authentication password.

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Default** | `` (no authentication) |
| **Example** | `secure-password-123` |

```yaml
mail:
  password: secure-password-123
```

#### `senderAddress` (Optional)

Email address for the "From" header.

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Default** | `` (generated) |
| **Example** | `noreply@example.com`, `breakglass@example.com` |

```yaml
mail:
  senderAddress: noreply@example.com
```

If not set, generated from `senderName` and hostname.

#### `senderName` (Optional)

Display name for the "From" header.

| Property | Value |
|----------|-------|
| **Type** | `string` |
| **Default** | `Das SCHIFF Breakglass` (if `brandingName` set) |
| **Example** | `Das SCHIFF Breakglass` |

```yaml
mail:
  senderName: "Das SCHIFF Breakglass"
```

Example email header: `Das SCHIFF Breakglass <noreply@example.com>`

#### `retryCount` (Optional)

Number of retry attempts for failed emails.

| Property | Value |
|----------|-------|
| **Type** | `int` |
| **Default** | `3` |
| **Example** | `1`, `3`, `5` |

```yaml
mail:
  retryCount: 3
```

Total send attempts = 1 + retryCount

#### `retryBackoffMs` (Optional)

Initial backoff duration in milliseconds for exponential backoff.

| Property | Value |
|----------|-------|
| **Type** | `int` |
| **Default** | `100` |
| **Example** | `100`, `500`, `1000` |

```yaml
mail:
  retryBackoffMs: 100
```

Backoff sequence: 100ms, 200ms, 400ms, ...

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

# OIDC authentication provider
authorizationserver:
  url: https://keycloak.example.com/realms/master
  jwksEndpoint: "protocol/openid-connect/certs"

# Frontend UI configuration
frontend:
  identityProviderName: "production-idp"  # REQUIRED
  baseURL: https://breakglass.example.com
  brandingName: "Das SCHIFF Breakglass"
  uiFlavour: "telekom"

# Email notification settings
mail:
  host: smtp.example.com
  port: 587
  username: breakglass@example.com
  password: "secure-password"
  insecureSkipVerify: false
  senderAddress: noreply@example.com
  senderName: "Das SCHIFF Breakglass"
  retryCount: 3
  retryBackoffMs: 100

# Kubernetes cluster settings
kubernetes:
  context: ""
  clusterConfigCheckInterval: "10m"
  oidcPrefixes:
    - "oidc:"
    - "keycloak:"
```

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

- **REQUIRED**: `authorizationserver.url`
- **REQUIRED**: `authorizationserver.jwksEndpoint`
- **REQUIRED**: `frontend.identityProviderName` (must exist as Kubernetes resource)
- **REQUIRED**: `frontend.baseURL`
- **REQUIRED**: `mail.host` (unless `--disable-email` flag set)

**If validation fails**: Controller exits with error message.

```
Fatal error: missing required configuration field 'frontend.identityProviderName'
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
