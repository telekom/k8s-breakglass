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
| `authority` | string | ✅ Yes | OIDC provider authority endpoint (e.g., `https://auth.example.com`). The frontend redirects users to this endpoint for authentication. |
| `clientID` | string | ✅ Yes | OIDC client ID for the Breakglass UI (frontend). Configured in your OIDC provider. |
| `jwksEndpoint` | string | ❌ No | JWKS endpoint for key sets. Defaults to `{authority}/.well-known/openid-configuration` |
| `insecureSkipVerify` | boolean | ❌ No | Skip TLS verification (NOT for production). Default: `false` |
| `certificateAuthority` | string | ❌ No | PEM-encoded CA certificate for TLS validation |

### Issuer Field (Critical for Multi-IDP)

**Required for multi-IDP mode. Optional but recommended for single-IDP setups.**

```yaml
spec:
  issuer: "https://auth.example.com"
```

The `issuer` field is the OIDC issuer URL that **must exactly match** the `iss` claim in JWT tokens issued by your OIDC provider. This field is critical because:

- **JWT Validation**: The system uses the issuer to validate that tokens come from the expected provider
- **Multi-IDP Identification**: When multiple IdentityProviders are configured, the issuer identifies which provider authenticated a user
- **SAR Webhook Matching**: The authorization webhook uses the token's issuer claim to match against configured IdentityProviders and provide helpful error messages with IDP hints
- **Unique Per Provider**: Each IdentityProvider must have a **unique issuer URL**

**Examples:**
- Generic OIDC: `https://auth.example.com` (usually same as authority)
- Keycloak: `https://keycloak.example.com/realms/master`
- Azure AD: `https://login.microsoftonline.com/{tenant-id}/v2.0`
- Auth0: `https://your-domain.auth0.com/`

**Multi-IDP Configuration Best Practice:**

```yaml
---
# Provider 1: Corporate OIDC
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: IdentityProvider
metadata:
  name: corp-oidc
spec:
  oidc:
    authority: "https://auth-corp.example.com"
    clientID: "breakglass-ui"
  issuer: "https://auth-corp.example.com"  # ← Unique issuer
  displayName: "Corporate OIDC"

---
# Provider 2: Keycloak Instance
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: IdentityProvider
metadata:
  name: keycloak-idp
spec:
  oidc:
    authority: "https://keycloak.example.com"
    clientID: "breakglass-ui"
  issuer: "https://keycloak.example.com/realms/master"  # ← Different issuer
  displayName: "Keycloak Provider"
```

When a user authenticates, their JWT token will contain one of these issuer URLs in the `iss` claim. The system uses this to verify the user's identity provider and provide appropriate access decisions.

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

When `groupSyncProvider: Keycloak` is set, the `keycloak` section configures how the backend fetches group/user information from Keycloak.

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `baseURL` | string | ✅ Yes | Keycloak server URL (e.g., `https://keycloak.example.com`) |
| `realm` | string | ✅ Yes | Keycloak realm name where users/groups are stored |
| `clientID` | string | ✅ Yes | Service account client ID for API queries (should have view-users/view-groups permissions only) |
| `clientSecretRef` | SecretKeyReference | ✅ Yes | Reference to secret containing admin client secret |
| `cacheTTL` | string | ❌ No | Cache duration for group memberships (default: `10m`). Format: `5m`, `1h`, etc. |
| `requestTimeout` | string | ❌ No | API request timeout (default: `10s`). Format: `10s`, `5m`, etc. |
| `insecureSkipVerify` | boolean | ❌ No | Skip TLS verification (NOT for production). Default: `false` |
| `certificateAuthority` | string | ❌ No | PEM-encoded CA certificate for TLS validation |

**Important:** The Keycloak `clientID` in this section is the **admin/service account** client used for API queries (to fetch user groups). This is different from the OIDC `clientID` which is the user-facing client in the `oidc` section above.

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

## Integration with ClusterConfig

IdentityProviders can be linked to specific clusters using `ClusterConfig.spec.identityProviderRefs`:

```yaml
# ClusterConfig restricting access to specific IDPs
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: production-cluster
spec:
  identityProviderRefs:
    - prod-primary      # Only users from these IDPs
    - prod-fallback     # can access this cluster
  # ... other config
```

**Behavior:**
- If `identityProviderRefs` is empty/omitted → All enabled IDPs are accepted
- If `identityProviderRefs` has values → Only users authenticated via listed IDPs can access

**Use Cases:**
- Restrict production clusters to corporate IDP only
- Allow different tenants to use different IDPs
- Enforce compliance requirements for specific clusters

See [ClusterConfig](./cluster-config.md#identity-provider-restrictions) for more details.

## Configuration Integration

The IdentityProvider CRD is the **sole source** of OIDC/IDP configuration. No additional config.yaml settings are required.

**Legacy config.yaml fields removed:**
- `authorizationserver.url` - Now in `spec.oidc.authority`
- `authorizationserver.jwksEndpoint` - Auto-discovered from authority
- `frontend.identityProviderName` - No longer needed, all IDPs auto-discovered
- `frontend.oidcAuthority` - Now in `spec.oidc.authority`
- `frontend.oidcClientID` - Now in `spec.oidc.clientID`

The system automatically discovers and uses all enabled IdentityProvider CRDs in the cluster.

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

## Migration from Legacy Configuration

**Note:** As of this version, migration is complete. The following legacy fields have been **removed** from config.yaml:

### Removed (No Longer Supported)

```yaml
# These fields are NO LONGER supported in config.yaml:
authorizationServer:
  url: "https://auth.example.com"
  jwksEndpoint: "https://auth.example.com/.well-known/openid-configuration"

frontend:
  oidcAuthority: "https://auth.example.com"
  oidcClientID: "breakglass-ui"
  identityProviderName: "production-idp"  # REMOVED

keycloak:
  baseURL: "https://keycloak.example.com"
  realm: "master"
  clientID: "breakglass-admin"
  clientSecret: "secret"
```

### Current (CRD-Only)

```yaml
# config.yaml - No IDP configuration needed
frontend:
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

## SubjectAccessReview (SAR) Webhook and Issuer Matching

The Breakglass authorization system includes a webhook that intercepts Kubernetes SubjectAccessReview (SAR) requests. This webhook:

1. **Extracts the user's JWT token** from the Kubernetes authentication context
2. **Validates the token** using the configured IdentityProvider's JWKS endpoint
3. **Matches the token's issuer claim** (`iss`) against configured IdentityProviders to determine which provider authenticated the user
4. **Makes authorization decisions** and provides helpful error messages when access is denied

### How Issuer Matching Works

When a user makes a request to the Kubernetes API:

```
User Request
    ↓
JWT Token (contains iss claim)
    ↓
SAR Webhook receives request
    ↓
Extracts and validates JWT token
    ↓
Reads token.iss claim (e.g., "https://keycloak.example.com/realms/master")
    ↓
Searches for IdentityProvider with matching issuer
    ↓
Uses that provider's OIDC config to validate the token
    ↓
Makes authorization decision
```

### Issuer Claim Importance

Each JWT token contains an `iss` (issuer) claim. This claim identifies which OIDC provider created the token. The Breakglass system uses this to:

- **Identify the provider**: Know which IdentityProvider to use for validation
- **Validate the token**: Use the correct JWKS endpoint for verification
- **Multi-IDP support**: Enable users to authenticate with different providers
- **Audit and logging**: Track which provider issued each authorization request

**Example JWT header and payload:**

```json
{
  "header": {
    "alg": "RS256",
    "kid": "key-id-123"
  },
  "payload": {
    "iss": "https://auth.example.com",  // ← Must match IdentityProvider.spec.issuer
    "sub": "user@example.com",
    "aud": "kubernetes",
    "iat": 1699000000,
    "exp": 1699003600
  }
}
```

### Multi-IDP Issuer Resolution

In multi-IDP mode, when a request arrives:

```
Request with JWT token
    ↓
Extract iss claim: "https://auth.example.com"
    ↓
Search all IdentityProviders for matching issuer
    ↓
Found: IdentityProvider "corporate-oidc" (issuer: "https://auth.example.com")
    ↓
Use "corporate-oidc" OIDC config to validate token
    ↓
Success! Token is valid from this provider
```

If the issuer doesn't match any configured IdentityProvider:

```
Request with JWT token
    ↓
Extract iss claim: "https://unknown-provider.com"
    ↓
Search all IdentityProviders for matching issuer
    ↓
NOT FOUND - No IdentityProvider has this issuer
    ↓
Return error: "Token issued by unknown-provider.com, please authenticate using one of the configured identity providers"
```

### Error Messages with IDP Hints

When access is denied, users see helpful error messages that include the identity provider information:

**Example: Token from unknown issuer**
```
Error: User token issued by https://unknown-auth.example.com, 
       please authenticate using one of these identity providers:
       - Corporate OIDC (issuer: https://auth.example.com)
       - Backup OIDC (issuer: https://backup-auth.example.com)
```

This helps users understand which provider authenticated their token and, if necessary, which provider they should use instead.

### Troubleshooting Issuer Mismatches

**Symptom:** User gets "unknown issuer" error despite having a valid token

**Possible causes:**
1. The IdentityProvider's `issuer` field doesn't match the token's `iss` claim
2. The token was issued by a different OIDC provider than expected
3. The issuer URL has trailing slashes or protocol differences (e.g., `http://` vs `https://`)

**Solution:**
1. Check your OIDC provider's configuration for its issuer URL
2. Update the IdentityProvider's `issuer` field to match exactly
3. Verify no trailing slashes or protocol mismatches:
   - ✅ `https://auth.example.com`
   - ❌ `https://auth.example.com/` (trailing slash)
   - ❌ `http://auth.example.com` (different protocol)

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
