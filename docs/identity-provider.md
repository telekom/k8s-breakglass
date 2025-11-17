# IdentityProvider Configuration

## Overview

The `IdentityProvider` is a **mandatory cluster-scoped Kubernetes custom resource** that configures user authentication and optional group synchronization for the Breakglass system.

**Key Features:**
- **Cluster-Scoped**: Single global identity provider configuration per cluster
- **OIDC-Based**: All providers use OpenID Connect (OIDC) for user authentication
- **Extensible**: Optional group synchronization providers (currently Keycloak)
- **Cross-Namespace Secrets**: Can reference secrets from any namespace
- **High Availability**: Multiple providers can be configured with primary/fallback selection

## Requirements

IdentityProvider is **MANDATORY** for Breakglass operation. The system will not start without at least one enabled IdentityProvider resource.

## OIDC Configuration

The OIDC configuration defines how users authenticate with the system. This is required for all providers.

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: IdentityProvider
metadata:
  name: production-idp
spec:
  primary: true
  oidc:
    authority: "https://auth.example.com"
    clientID: "breakglass-ui"
    # Optional: CA certificate for TLS validation
    certificateAuthority: |
      -----BEGIN CERTIFICATE-----
      ...
      -----END CERTIFICATE-----
```

### OIDC Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `authority` | string | ✅ Yes | OIDC provider authority endpoint (e.g., `https://auth.example.com`) |
| `clientID` | string | ✅ Yes | OIDC client ID for the Breakglass UI |
| `jwksEndpoint` | string | ❌ No | JWKS endpoint for key sets. Defaults to `{authority}/.well-known/openid-configuration` |
| `insecureSkipVerify` | boolean | ❌ No | Skip TLS verification (NOT for production). Default: `false` |
| `certificateAuthority` | string | ❌ No | PEM-encoded CA certificate for TLS validation |

## Group Synchronization (Optional)

You can optionally configure group synchronization using Keycloak. This allows the system to fetch user group memberships from Keycloak for advanced authorization.

### Keycloak Group Sync

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: IdentityProvider
metadata:
  name: production-idp
spec:
  primary: true
  oidc:
    authority: "https://auth.example.com"
    clientID: "breakglass-ui"
  
  # Enable Keycloak group synchronization
  groupSyncProvider: Keycloak
  keycloak:
    baseURL: "https://keycloak.example.com"
    realm: "master"
    clientID: "breakglass-admin"
    clientSecretRef:
      name: keycloak-client-secret
      namespace: default
      key: clientSecret
    
    # Optional performance tuning
    cacheTTL: "10m"
    requestTimeout: "10s"
```

### Keycloak Credentials

The Keycloak client secret must be stored in a Kubernetes Secret:

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: keycloak-client-secret
  namespace: default
type: Opaque
data:
  clientSecret: <base64-encoded-secret>
```

### Keycloak Service Account Requirements

The Keycloak service account (client) used for group synchronization should have **minimal permissions**:
- ✅ `view-users`
- ✅ `view-groups`
- ❌ **NOT** admin permissions
- ❌ **NOT** write permissions

### Keycloak Fields

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `baseURL` | string | ✅ Yes | Keycloak server URL (e.g., `https://keycloak.example.com`) |
| `realm` | string | ✅ Yes | Keycloak realm name |
| `clientID` | string | ✅ Yes | Service account client ID (view-users/view-groups only) |
| `clientSecretRef` | SecretKeyReference | ✅ Yes | Reference to secret containing client secret |
| `cacheTTL` | string | ❌ No | Cache duration (default: `10m`). Format: `5m`, `1h`, etc. |
| `requestTimeout` | string | ❌ No | API request timeout (default: `10s`). Format: `10s`, `5m`, etc. |
| `insecureSkipVerify` | boolean | ❌ No | Skip TLS verification (NOT for production). Default: `false` |
| `certificateAuthority` | string | ❌ No | PEM-encoded CA certificate for TLS validation |

## Cross-Namespace Secrets

IdentityProvider is cluster-scoped, meaning it can reference secrets in any namespace. Specify the namespace in `SecretKeyReference`:

```yaml
keycloak:
  baseURL: "https://keycloak.example.com"
  realm: "master"
  clientID: "breakglass-admin"
  clientSecretRef:
    name: keycloak-secret
    namespace: secrets  # Secret is in 'secrets' namespace
    key: adminSecret
```

## Primary and Fallback Providers

You can configure multiple IdentityProviders for redundancy:

```yaml
---
# Primary provider
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: IdentityProvider
metadata:
  name: prod-primary
spec:
  primary: true
  oidc:
    authority: "https://auth-primary.example.com"
    clientID: "breakglass-ui"

---
# Fallback provider
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: IdentityProvider
metadata:
  name: prod-fallback
spec:
  primary: false
  oidc:
    authority: "https://auth-secondary.example.com"
    clientID: "breakglass-ui"
```

**Load Priority:**
1. Primary provider (if enabled and not disabled)
2. First enabled non-primary provider
3. Error if none available

## Disabling Providers Temporarily

You can temporarily disable a provider without deleting it:

```yaml
spec:
  disabled: true
```

## Configuration via config.yaml

The Frontend config in `config.yaml` now references the IdentityProvider by name:

```yaml
frontend:
  identityProviderName: "production-idp"  # REQUIRED - name of the IdentityProvider CR
  baseURL: "https://breakglass.example.com"
  brandingName: "Das SCHIFF Breakglass"
```

**Note:** Individual OIDC fields (`oidcAuthority`, `oidcClientID`) are no longer supported. All identity configuration must be in the IdentityProvider CRD.

## RBAC Permissions

The Breakglass controller requires the following permissions for IdentityProvider:

```yaml
- apiGroups:
  - breakglass.t-caas.telekom.com
  resources:
  - identityproviders
  verbs:
  - get
  - list
  - watch
- apiGroups:
  - breakglass.t-caas.telekom.com
  resources:
  - identityproviders/status
  verbs:
  - get
  - patch
  - update
- apiGroups:
  - ""
  resources:
  - secrets
  verbs:
  - get
```

## Migration from Old Configuration

### Before (Deprecated)

```yaml
authorizationServer:
  url: "https://auth.example.com"
  jwksEndpoint: "https://auth.example.com/.well-known/openid-configuration"

frontend:
  oidcAuthority: "https://auth.example.com"
  oidcClientID: "breakglass-ui"

keycloak:
  baseURL: "https://keycloak.example.com"
  realm: "master"
  clientID: "breakglass-admin"
  clientSecret: "secret"
```

### After (Current)

```yaml
# config.yaml - minimal, just reference the CRD
frontend:
  identityProviderName: "production-idp"
  baseURL: "https://breakglass.example.com"
```

```yaml
# IdentityProvider CRD
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: IdentityProvider
metadata:
  name: production-idp
spec:
  primary: true
  oidc:
    authority: "https://auth.example.com"
    clientID: "breakglass-ui"
  groupSyncProvider: Keycloak
  keycloak:
    baseURL: "https://keycloak.example.com"
    realm: "master"
    clientID: "breakglass-admin"
    clientSecretRef:
      name: keycloak-secret
      namespace: default
      key: clientSecret
```

## Status and Monitoring

The IdentityProvider status shows validation and connectivity information:

```yaml
status:
  phase: "Ready"
  message: "Provider is accessible and configured correctly"
  lastValidation: "2024-11-11T12:00:00Z"
  connected: true
  configHash: "sha256:abc123..."
```

**Phase Values:**
- `Ready` - Provider is operational
- `Validating` - Provider configuration is being validated
- `Error` - Provider encountered an error

## Troubleshooting

### No IdentityProvider Found

```
Error: no IdentityProvider resources found; IdentityProvider is MANDATORY for operation
```

**Solution:** Create at least one IdentityProvider resource:
```bash
kubectl apply -f identity-provider.yaml
```

### All Providers Disabled

```
Error: no enabled IdentityProvider resources found; at least one enabled provider is required
```

**Solution:** Enable at least one provider by setting `disabled: false` or removing the field:
```yaml
spec:
  disabled: false
```

### Keycloak Secret Not Found

```
Error: failed to load Keycloak client secret: failed to get secret keycloak-secret/default
```

**Solution:** Ensure the secret exists in the specified namespace:
```bash
kubectl get secret keycloak-secret -n default
```

### TLS Certificate Validation Failed

```
Error: x509: certificate signed by unknown authority
```

**Solution:** Add the CA certificate to the IdentityProvider:
```yaml
oidc:
  certificateAuthority: |
    -----BEGIN CERTIFICATE-----
    ...
    -----END CERTIFICATE-----
```

Or temporarily allow insecure connections (NOT for production):
```yaml
oidc:
  insecureSkipVerify: true
```

## Multi-IDP Support (New in v0.2.0)

Breakglass now supports **multiple identity providers** allowing users to authenticate with different OIDC providers. This enables:

- **Flexible Authentication**: Users can choose their preferred identity provider
- **Gradual Migration**: Transition users from one provider to another
- **Multi-Tenant Support**: Different escalations can require different IDPs
- **Backward Compatible**: Single-IDP mode continues to work unchanged

### Multi-IDP Architecture

In multi-IDP mode:

1. **IdentityProvider CRs**: Multiple IdentityProvider resources, each with a unique issuer URL
2. **JWT Validation**: Each user token is validated against the issuer's JWKS endpoint
3. **Per-Escalation Control**: Optional `allowedIdentityProviders` field in BreakglassEscalation restricts which IDPs can access each escalation
4. **Frontend Support**: UI automatically detects multiple IDPs and provides a selection screen

### Enabling Multi-IDP

Create multiple IdentityProvider resources with different issuers:

```yaml
---
# Corporate OIDC Provider
apiVersion: breakglass.telekom.de/v1alpha1
kind: IdentityProvider
metadata:
  name: corporate-oidc
spec:
  issuer: "https://auth.corp.example.com"
  clientID: "breakglass-prod"
  clientSecret:
    secretRef:
      name: corporate-secret
      namespace: breakglass
  disabled: false

---
# External Keycloak Instance
apiVersion: breakglass.telekom.de/v1alpha1
kind: IdentityProvider
metadata:
  name: external-keycloak
spec:
  issuer: "https://keycloak.external.example.com/realms/breakglass"
  clientID: "breakglass-external"
  clientSecret:
    secretRef:
      name: keycloak-secret
      namespace: breakglass
  disabled: false
```

### Per-Escalation IDP Restrictions

Optionally restrict escalations to specific IDPs:

```yaml
apiVersion: breakglass.telekom.de/v1alpha1
kind: BreakglassEscalation
metadata:
  name: prod-access
spec:
  escalatedGroup: prod-admins
  allowedIdentityProviders:
    - corporate-oidc  # Only corporate IDP can use this escalation
  approvers:
    groups:
      - senior-ops

---
# Escalation accessible by any IDP (or empty list = all IDPs)
apiVersion: breakglass.telekom.de/v1alpha1
kind: BreakglassEscalation
metadata:
  name: dev-access
spec:
  escalatedGroup: dev-admins
  allowedIdentityProviders: []  # Empty = all IDPs allowed
  approvers:
    groups:
      - dev-leads
```

### Frontend IDP Selection

When multiple IDPs are available, the frontend displays:

- **IDP Selection Screen**: Users select their identity provider before login
- **Single IDP Mode**: If only one IDP is configured, the selection screen is skipped
- **IDP Status**: Disabled IDPs are shown as unavailable

### JWKS Caching

For performance, Breakglass caches JWT Key Sets (JWKS) from each provider:

- **Cache Duration**: 24 hours per key (or discovery document TTL)
- **Automatic Refresh**: Expired keys are fetched on-demand
- **Per-Issuer Caching**: Each issuer maintains independent cache

### Migration Path: Single → Multi-IDP

If you currently have a single IdentityProvider and want to add another:

1. **Existing Single IDP** (continues working):

   ```yaml
   apiVersion: breakglass.telekom.de/v1alpha1
   kind: IdentityProvider
   metadata:
     name: primary-idp
   spec:
     issuer: "https://existing.example.com"
     # ... existing configuration
   ```

2. **Add New IDP** (users can now choose):

   ```yaml
   apiVersion: breakglass.telekom.de/v1alpha1
   kind: IdentityProvider
   metadata:
     name: new-idp
   spec:
     issuer: "https://new.example.com"
     # ... new provider configuration
   ```

3. **No escalation changes needed** - all escalations accessible by both IDPs by default

4. **Optionally restrict** - add `allowedIdentityProviders` to specific escalations

### Multi-IDP Best Practices

1. **Unique Issuer URLs**: Each IdentityProvider must have a unique `issuer` field
2. **Naming Convention**: Use descriptive names (e.g., `corporate-oidc`, `external-keycloak`)
3. **Secret Management**: Store credentials in separate secrets per provider
4. **Test Coverage**: Verify each IDP with test escalations before production
5. **Documentation**: Document which IDPs are used for which purposes
6. **Monitoring**: Track successful/failed logins per IDP

### Troubleshooting Multi-IDP

**"Unknown issuer" error**:

- Verify JWT token's `iss` claim matches an IdentityProvider's `issuer` field
- Check JWKS endpoint accessibility from pod

**IDP selection screen not appearing**:

- System detects multi-IDP only if 2+ enabled IdentityProviders exist
- Verify both providers are `disabled: false`

**Escalation restricted but user still gets "Access Denied"**:

- User's IDP must be in `allowedIdentityProviders` list
- Check escalation configuration with: `kubectl get breakglassescalation -o yaml`

## Examples

See `/config/samples/` for complete examples:

- `breakglass_v1alpha1_identityprovider_oidc.yaml` - OIDC-only configuration
- `breakglass_v1alpha1_identityprovider_keycloak.yaml` - OIDC with Keycloak group sync
- `breakglass_v1alpha1_breakglass_escalation_multiidp.yaml` - Multi-IDP escalation configuration

## See Also

- [Installation Guide](installation.md) - How to deploy Breakglass
- [API Reference](api-reference.md) - Full API documentation
- [Advanced Features](advanced-features.md) - Group synchronization and RBAC
