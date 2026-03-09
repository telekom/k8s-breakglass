# Proposal: Extended OIDC Auth Modes for ClusterConfig

**Status:** Accepted  
**Date:** 2026-03-02  
**Author:** AI-assisted  

## Summary

Extend `OIDCFromIdentityProviderConfig` (and `OIDCAuthConfig`) with three new capabilities:

1. **Offline Refresh Token auth** — admin stores an offline refresh token in a K8s Secret; breakglass exchanges it for fresh access tokens using the IDP's existing client. No new OIDC client registration needed.
2. **Token Exchange via IDP reference** — reuse the IDP's Keycloak service account for RFC 8693 token exchange. Currently `TokenExchangeConfig` only exists on `OIDCAuthConfig`, not on `OIDCFromIdentityProviderConfig`.
3. **Full field parity** — add `audience` and `scopes` fields to `OIDCFromIdentityProviderConfig`, matching `OIDCAuthConfig`.

Additionally, a configurable **fallback policy** controls what happens when the primary auth flow (refresh token) fails.

## Motivation

Today, `OIDCFromIdentityProviderConfig` only supports client-credentials flow:

```yaml
oidcFromIdentityProvider:
  name: my-idp
  server: https://k8s-api.example.com
  clientSecretRef:
    name: my-secret
    namespace: breakglass-system
```

This requires registering a dedicated OIDC client with its own secret for every cluster. Many deployments already have a Keycloak client configured for breakglass user auth — reusing it via offline refresh tokens or token exchange avoids client proliferation and simplifies operations.

## Design

### New CRD Fields

#### `FallbackPolicy` Enum

```go
// +kubebuilder:validation:Enum=None;Auto;Warn
type FallbackPolicy string

const (
    // FallbackPolicyNone disables fallback — if the primary auth flow
    // (refresh token) fails, the cluster becomes unreachable and a
    // RefreshTokenExpired condition is set.
    FallbackPolicyNone FallbackPolicy = "None"

    // FallbackPolicyAuto silently falls back to the IDP's Keycloak
    // service account client_credentials flow when the refresh token
    // expires or is revoked. No degraded condition is set.
    FallbackPolicyAuto FallbackPolicy = "Auto"

    // FallbackPolicyWarn falls back to client_credentials but also
    // sets a DegradedAuth condition and emits a Kubernetes event
    // to alert operators.
    FallbackPolicyWarn FallbackPolicy = "Warn"
)
```

**Default: `None`** — strict by design. Admin must explicitly opt in to fallback.

#### `OIDCFromIdentityProviderConfig` Extensions

```yaml
oidcFromIdentityProvider:
  name: my-idp                      # existing
  server: https://k8s-api.example.com # existing
  # --- NEW FIELDS ---
  refreshTokenSecretRef:             # Offline refresh token from K8s Secret
    name: my-refresh-token
    namespace: breakglass-system
    key: refresh-token               # User-specified key (required)
  tokenExchange:                     # RFC 8693 token exchange config
    enabled: true
    subjectTokenSecretRef:
      name: subject-token
      namespace: breakglass-system
      key: token
  audience: "https://k8s-api.example.com"
  scopes:
    - openid
    - groups
  fallbackPolicy: Warn              # None (default) | Auto | Warn
```

#### `OIDCAuthConfig` Extensions

The direct `oidcAuth` mode also gets `RefreshTokenSecretRef` and `FallbackPolicy` for parity:

```yaml
oidcAuth:
  issuerURL: https://keycloak.example.com/realms/myrealm
  clientID: breakglass-cluster
  server: https://k8s-api.example.com
  refreshTokenSecretRef:
    name: my-refresh-token
    namespace: breakglass-system
    key: refresh-token
  fallbackPolicy: Auto
```

### Mutual Exclusivity Rules

| On `OIDCFromIdentityProviderConfig` | Rule |
|------|------|
| `refreshTokenSecretRef` + `clientSecretRef` | **Mutually exclusive** — error at admission time |
| `fallbackPolicy` without `refreshTokenSecretRef` | **Invalid** — pointless without a primary flow that can expire |
| `tokenExchange.enabled` without `subjectTokenSecretRef` | **Invalid** |

On `OIDCAuthConfig`, `refreshTokenSecretRef` and `clientSecretRef` **can coexist** (enables explicit fallback without relying on IDP Keycloak config).

### Token Acquisition Flow

Updated `getToken()` flow in `OIDCTokenProvider`:

```
1. Check cache (valid if >30s until expiry)
   ↓ (cache miss)
2. Try refresh with cached refresh token (from previous token response)
   ↓ (no cached RT or refresh fails)
3. If RefreshTokenSecretRef set → read offline RT from K8s Secret → refresh
   ↓ (refresh succeeds → cache token, done)
   ↓ (refresh fails with invalid_grant → ErrRefreshTokenExpired)
4. Evaluate FallbackPolicy:
   ├─ None → return ErrRefreshTokenExpired (checker sets condition)
   ├─ Auto → silently try client_credentials via IDP Keycloak SA
   └─ Warn → try client_credentials + return ErrDegradedAuth marker
5. If no RefreshTokenSecretRef:
   ├─ TokenExchange.Enabled → tokenExchangeFromSecret()
   └─ else → clientCredentialsFlow()
6. Cache token (including refresh token if returned)
```

### Fallback Mechanism

When `FallbackPolicy` is `Auto` or `Warn`, the fallback path uses the **IDP's Keycloak service account credentials** (from `IdentityProvider.Spec.Keycloak.ClientID` + `ClientSecretRef`). This requires:

1. The referenced `IdentityProvider` must have Keycloak config (`spec.keycloak` section)
2. The Keycloak service account must have permissions to obtain tokens valid for the target cluster

If the IDP has no Keycloak config, the fallback is a **runtime error** caught by the ClusterConfig checker (not webhook — IDP is fetched at runtime).

### ClusterConfig Conditions

Two new condition types:

| Condition | When Set | Meaning |
|-----------|----------|---------|
| `RefreshTokenExpired` | Refresh token is invalid/revoked and `FallbackPolicy=None` | Cluster is **unreachable** until the Secret is updated |
| `DegradedAuth` | Refresh token expired but fallback succeeded with `FallbackPolicy=Warn` | Cluster is reachable but using **fallback credentials** |

### Secret Watching

Extend the existing Secret informer-based cache invalidation to track OIDC-related secrets:

- **Currently tracked**: kubeconfig secrets only
- **Newly tracked**: `RefreshTokenSecretRef`, `ClientSecretRef`, `SubjectTokenSecretRef`, `CASecretRef`

When any tracked OIDC secret changes, all clusters referencing it are evicted from cache, triggering fresh token acquisition on next request.

New maps on `ClientProvider`:
- `clusterToOIDCSecrets map[string][]string` — cluster → set of OIDC secret keys
- `oidcSecretToClusters map[string]map[string]struct{}` — reverse index

### Admission Warnings

| Trigger | Warning Message |
|---------|-----------------|
| `RefreshTokenSecretRef` set | "Offline refresh tokens don't expire unless explicitly revoked; ensure your IDP is configured for offline access" |
| `FallbackPolicy = None` (default) with `RefreshTokenSecretRef` | "No fallback configured — cluster will become unreachable if the refresh token expires or is revoked" |

## Deployment Modes Summary

After this change, `ClusterConfig` supports **5 cluster auth modes**:

| # | Mode | Config | When to Use |
|---|------|--------|-------------|
| 1 | **Kubeconfig** | `authType: Kubeconfig` + `kubeconfigSecretRef` | Static credentials, mTLS via embedded client certs |
| 2 | **Client Credentials (direct)** | `authType: OIDC` + `oidcAuth` + `clientSecretRef` | Dedicated OIDC client per cluster |
| 3 | **Client Credentials (via IDP)** | `authType: OIDC` + `oidcFromIdentityProvider` + `clientSecretRef` | Reuse IDP config but with cluster-specific client |
| 4 | **Offline Refresh Token** | `authType: OIDC` + `oidcFromIdentityProvider` + `refreshTokenSecretRef` | **NEW** — Reuse existing IDP client, no new OIDC registration |
| 5 | **Token Exchange** | `authType: OIDC` + `oidcAuth.tokenExchange` or `oidcFromIdentityProvider.tokenExchange` | **NEW on IDP ref** — RFC 8693 delegation |

## File Changes

### CRD Types
- `api/v1alpha1/cluster_config_types.go` — `FallbackPolicy` enum, extend `OIDCFromIdentityProviderConfig` and `OIDCAuthConfig`

### Validation
- `api/v1alpha1/validation_helpers.go` — new validation rules
- `api/v1alpha1/validation_helpers_test.go` — new test cases
- `api/v1alpha1/cluster_config_types.go` — admission warnings

### Runtime
- `pkg/cluster/oidc.go` — `refreshTokenFromSecret()`, modified `getToken()`, `resolveOIDCFromIdentityProvider()` extensions, typed errors
- `pkg/cluster/oidc_test.go` — new test cases
- `pkg/cluster/oidc_additional_test.go` — new test cases

### Secret Watching
- `pkg/cluster/cache.go` — OIDC secret tracking maps, `InvalidateOIDCSecret()`, `IsOIDCSecretTracked()`
- `pkg/cluster/watchers.go` — extended Secret handler
- `pkg/cluster/cache_test.go` — new test cases

### Checker
- `pkg/breakglass/clusterconfig/checker.go` — `RefreshTokenSecretRef` + `TokenExchange` validation branches, condition handling
- `pkg/breakglass/clusterconfig/checker_test.go` — new test cases
- `pkg/breakglass/clusterconfig/oidc_test.go` — new test cases

### E2E
- `e2e/helpers/builders.go` — new builder methods
- `e2e/helpers/auth.go` — `ObtainOfflineRefreshToken()` helper
- `e2e/tests/oidc_from_idp_tests.sh` — new test script (OI-001 through OI-008)
- `e2e/api/cluster_config_oidc_from_idp_test.go` — Go E2E tests
- `e2e/tests/comprehensive_tests.sh` — include new script

### Auto-Generated (via `make generate && make manifests`)
- `api/v1alpha1/zz_generated.deepcopy.go`
- `api/v1alpha1/applyconfiguration/api/v1alpha1/oidcfromidentityproviderconfig.go`
- `api/v1alpha1/applyconfiguration/api/v1alpha1/clusterconfigspec.go`
- `config/crd/bases/breakglass.t-caas.telekom.com_clusterconfigs.yaml`
- `charts/escalation-config/crds/` (Helm CRD sync)

### Documentation
- `docs/cluster-config.md` — new "OIDC via IdentityProvider Reference" section
- `CHANGELOG.md` — unreleased entries

## Security Considerations

1. **Offline refresh tokens are long-lived** — they don't expire unless explicitly revoked at the IDP. Exposure of the K8s Secret containing one grants persistent cluster access.
2. **Fallback to service account** — `FallbackPolicy: Auto` silently uses IDP service account credentials, which may have broader permissions than the original user's refresh token. Default `None` prevents this.
3. **Secret rotation** — the Secret watcher ensures new tokens are picked up immediately on Secret update, enabling zero-downtime rotation.
4. **Token exchange delegation** — actor tokens in `TokenExchangeConfig` enable delegation scenarios but require careful RBAC review at the IDP level.

## Testing Strategy

| Layer | Coverage |
|-------|----------|
| **Unit tests** | Validation rules, `getToken()` flow branches, `resolveOIDCFromIdentityProvider()`, Secret tracking, fallback policy evaluation |
| **Checker tests** | Runtime validation with mock IDP, condition setting, event emission |
| **E2E shell tests** | Full Keycloak + Kind cluster tests for each auth mode and fallback scenario |
| **E2E Go tests** | API-level tests using helpers framework |
| **Fuzz tests** | Existing fuzz coverage applies to URL/identifier validation used by new fields |

## Out of Scope

- **Device code flow** — already fully implemented in bgctl; not applicable for server-side cluster auth
- **mTLS client certificate auth** — already works via kubeconfig path (embed `client-certificate-data`/`client-key-data` in kubeconfig Secret)
- **New deployment patterns** — these are auth *configuration* modes within existing deployment patterns
