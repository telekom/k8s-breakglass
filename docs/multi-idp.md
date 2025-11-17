# Multi-IDP Support - Implementation Guide

## Overview

Breakglass now supports multiple Identity Providers (IDPs) in a single cluster, enabling:

1. **Multiple Authentication Sources** - Users can authenticate via different OIDC providers
2. **IDP-Based Access Control** - Clusters and escalations can be restricted to specific IDPs
3. **Session Auditing** - Each session records which IDP authenticated the user
4. **Gradual Migration** - Existing single-IDP deployments continue working unchanged

## Phase 1: CRD Changes (COMPLETED ✅)

### What Changed

Four CRD types were extended with multi-IDP fields:

#### 1. IdentityProviderSpec
- **Added `Issuer` field** (string, optional)
  - The OIDC issuer URL (must match the `iss` claim in JWT tokens)
  - Used to identify which provider authenticated a user
  - Example: `https://auth.example.com`

- **Deprecated `Primary` field** (but kept for backward compatibility)
  - Old single-IDP deployments can still set Primary=true
  - In multi-IDP mode, use ClusterConfig.IdentityProviderRefs instead

#### 2. ClusterConfigSpec
- **Added `IdentityProviderRefs` field** ([]string, optional)
  - Names of IdentityProvider CRs this cluster accepts
  - If empty/unset → accepts all enabled IDPs (backward compatible)
  - Example: `["platform-idp", "tenant-idp"]`

#### 3. BreakglassEscalationSpec
- **Added `AllowedIdentityProviders` field** ([]string, optional)
  - Names of IdentityProvider CRs this escalation accepts
  - If empty/unset → inherits from ClusterConfig (backward compatible)
  - Enables isolation between different provider contexts

#### 4. BreakglassSessionSpec
- **Added `IdentityProviderName` field** (string, optional)
  - Name of the IdentityProvider CR that authenticated the user
  - Set during session creation
  - Used for auditing and webhook validation

- **Added `IdentityProviderIssuer` field** (string, optional)
  - The OIDC issuer URL (from JWT `iss` claim)
  - Set during session creation
  - Used by webhook to validate consistent IDP usage

### Backward Compatibility

✅ **Fully backward compatible** - Existing deployments work without changes:

```yaml
# Old single-IDP setup still works
apiVersion: breakglass.telekom.de/v1alpha1
kind: IdentityProvider
metadata:
  name: my-idp
spec:
  oidc:
    authority: https://auth.example.com
    clientID: my-client
  primary: true  # Still supported for backward compatibility
```

After upgrade, sessions will have `identityProviderName` and `identityProviderIssuer` populated automatically.

## Phase 2: Configuration Loading (COMPLETED ✅)

### New Loader Methods

File: `pkg/config/identity_provider_loader.go`

#### LoadAllIdentityProviders(ctx)
Returns all enabled IDPs as a map of `name → config`.

```go
idps, err := loader.LoadAllIdentityProviders(ctx)
// idps["idp-1"] = &IdentityProviderConfig{Name: "idp-1", Issuer: "https://..."}
```

#### LoadIdentityProviderByIssuer(ctx, issuer)
Finds an IDP by JWT issuer URL - essential for multi-IDP support.

```go
// Extract issuer from JWT iss claim
issuer := claims["iss"].(string) // e.g., "https://auth.tenant.com"

// Find which provider authenticated this user
idp, err := loader.LoadIdentityProviderByIssuer(ctx, issuer)
// idp.Name = "tenant-idp"
```

#### ValidateIdentityProviderRefs(ctx, refs)
Validates that referenced IDPs exist and are enabled.

```go
// Used during admission webhook validation
err := loader.ValidateIdentityProviderRefs(ctx, []string{"idp-1", "idp-2"})
// Returns error if any ref is invalid, disabled, or doesn't exist
```

#### GetIDPNameByIssuer(ctx, issuer)
Convenience method to get IDP name from issuer.

```go
name, err := loader.GetIDPNameByIssuer(ctx, "https://auth.example.com")
// name = "my-idp"
```

### IdentityProviderConfig Changes

Extended with `Name` and `Issuer` fields:

```go
type IdentityProviderConfig struct {
    Name      string  // e.g., "tenant-idp"
    Issuer    string  // e.g., "https://auth.tenant.com"
    Type      string  // "OIDC"
    Authority string  // OIDC authority URL
    ClientID  string  // OIDC client ID
    // ... other fields
}
```

## Phase 3: Webhook Validation (COMPLETED ✅)

Webhook validation ensures data consistency before resources are created or updated. All multi-IDP fields now have comprehensive validation rules.

### Validation Rules by Resource Type

#### IdentityProvider Validation

**File:** `api/v1alpha1/identity_provider_types.go`

```go
func (idp *IdentityProvider) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error)
```

**Rules:**
1. **Issuer must be valid URL** - If set, must parse as valid URL
2. **Issuer must be unique** - No two IdentityProviders can have the same issuer
3. **Existing validations preserved** - OIDC config and Keycloak config still validated as before

**Example Errors:**
```
# Issuer validation error
ClusterConfig.breakglass.telekom.de "idp-1" is invalid:
  spec.issuer: Invalid value: ":invalid": issuer must be a valid URL

# Issuer uniqueness error
ClusterConfig.breakglass.telekom.de "idp-2" is invalid:
  spec.issuer: Duplicate value: "issuer must be unique cluster-wide; conflicting IdentityProvider=idp-1"
```

#### ClusterConfig Validation

**File:** `api/v1alpha1/cluster_config_types.go`

```go
func (cc *ClusterConfig) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error)
```

**Rules:**
1. **Referenced IDPs must exist** - Each IDP name in `identityProviderRefs` must correspond to an existing IdentityProvider CR
2. **Referenced IDPs must be enabled** - Referenced IDPs cannot have `disabled: true`
3. **Empty list is valid** - If `identityProviderRefs` is empty/unset, cluster accepts all enabled IDPs (backward compatible)

**Example:**
```yaml
spec:
  identityProviderRefs:
    - platform-idp  # ✅ Valid - exists and enabled
    - tenant-idp    # ✅ Valid - exists and enabled
    # ✖ Invalid would be: non-existent-idp
```

**Example Error:**
```
ClusterConfig.breakglass.telekom.de "prod-cluster" is invalid:
  spec.identityProviderRefs[0]: Not found: "non-existent-idp"
```

#### BreakglassEscalation Validation

**File:** `api/v1alpha1/breakglass_escalation_types.go`

```go
func (be *BreakglassEscalation) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error)
```

**Rules:**
1. **AllowedIdentityProviders must exist and be enabled** - Same validation as ClusterConfig
2. **Empty list is valid** - If `allowedIdentityProviders` is empty, escalation inherits filtering from the cluster config (backward compatible)
3. **Existing validations preserved** - `escalatedGroup` still required, cluster-wide name uniqueness still enforced

**Semantics:**
- Empty `allowedIdentityProviders` → Escalation uses cluster's IDP list
- Specified `allowedIdentityProviders` → Escalation only available via those IDPs
- Enables IDP-specific escalations for isolation/security

**Example:**
```yaml
spec:
  allowedIdentityProviders: []   # ✅ Valid - inherit from cluster
  allowedIdentityProviders:
    - platform-idp               # ✅ Valid - restrict to platform-idp
```

#### BreakglassSession Validation

**File:** `api/v1alpha1/breakglass_session_types.go`

```go
func (bs *BreakglassSession) ValidateCreate(ctx context.Context, obj runtime.Object) (admission.Warnings, error)
```

**Rules:**
1. **IdentityProviderName if set must reference valid IDP** - If populated, must match existing enabled IdentityProvider
2. **IdentityProviderIssuer if set must match IDP** - If both name and issuer are set, issuer must match that IDP's issuer
3. **Both fields are optional** - During session creation (will be populated during authentication), can be empty
4. **Existing validations preserved** - cluster, user, grantedGroup required; scheduledStartTime must be in future

**Typical Flow:**
1. User creates session (both fields often empty initially)
2. Authentication handler populates both fields based on JWT
3. Webhook validates they match

**Example:**
```yaml
spec:
  identityProviderName: tenant-idp          # ✅ Valid - exists and enabled
  identityProviderIssuer: https://auth.tenant.com  # ✅ Valid - matches tenant-idp issuer
```

**Example Errors:**
```
# Non-existent IDP
BreakglassSession.breakglass.telekom.de "session-1" is invalid:
  spec.identityProviderName: Not found: "non-existent-idp"

# Issuer mismatch
BreakglassSession.breakglass.telekom.de "session-1" is invalid:
  spec.identityProviderIssuer: Invalid value: "https://other.com":
    issuer does not match IdentityProvider tenant-idp (expected https://auth.tenant.com)
```

### Helper Functions

File: `api/v1alpha1/validation_helpers.go`

#### ensureClusterWideUniqueIssuer()
Validates issuer uniqueness across all IdentityProvider CRs.

```go
func ensureClusterWideUniqueIssuer(
    ctx context.Context,
    issuer string,
    currentName string,
    path *field.Path,
) field.ErrorList
```

#### validateIdentityProviderRefs()
Validates that IDP references exist and are enabled.

```go
func validateIdentityProviderRefs(
    ctx context.Context,
    refs []string,
    path *field.Path,
) field.ErrorList
```

#### validateIdentityProviderFields()
Validates session IDP tracking fields for consistency.

```go
func validateIdentityProviderFields(
    ctx context.Context,
    idpName string,
    idpIssuer string,
    namePath *field.Path,
    issuerPath *field.Path,
) field.ErrorList
```

### Test Coverage

**Validation Tests:** `api/v1alpha1/multi_idp_validation_test.go`

Tests cover:
- ✅ Issuer uniqueness validation
- ✅ Issuer URL format validation  
- ✅ IdentityProviderRefs validation (existing, non-existing, disabled)
- ✅ AllowedIdentityProviders validation
- ✅ Session IDP field validation
- ✅ Issuer mismatch detection
- ✅ Backward compatibility (empty refs is valid)
- ✅ Helper function unit tests

Run validation tests:
```bash
go test -v ./api/v1alpha1/... -run "Validation"
```

## Phase 4: API Authentication (IN PROGRESS)

Next phase will extend `pkg/api/auth.go` to:
- Support multiple OIDC providers
- Extract issuer from JWT tokens
- Validate tokens against the correct provider's JWKS
- Record IDP details in sessions

## Usage Examples

### Example 1: Basic Multi-IDP Cluster

```yaml
# Two identity providers
---
apiVersion: breakglass.telekom.de/v1alpha1
kind: IdentityProvider
metadata:
  name: platform-idp
spec:
  oidc:
    authority: https://auth.platform.com
    clientID: platform-client
  issuer: https://auth.platform.com
  displayName: Platform IDP
---
apiVersion: breakglass.telekom.de/v1alpha1
kind: IdentityProvider
metadata:
  name: tenant-idp
spec:
  oidc:
    authority: https://auth.tenant.com
    clientID: tenant-client
  issuer: https://auth.tenant.com
  displayName: Tenant IDP

# Cluster accepts both IDPs
---
apiVersion: breakglass.telekom.de/v1alpha1
kind: ClusterConfig
metadata:
  name: prod-cluster
spec:
  clusterID: prod-cluster
  tenant: platform
  kubeconfigSecretRef:
    name: kubeconfig
    namespace: default
  # Accept both providers
  identityProviderRefs:
    - platform-idp
    - tenant-idp
```

### Example 2: IDP-Specific Escalations

```yaml
# Escalation accessible from platform-idp only
---
apiVersion: breakglass.telekom.de/v1alpha1
kind: BreakglassEscalation
metadata:
  name: admin-access
  namespace: default
spec:
  allowed:
    clusters:
      - prod-cluster
  escalatedGroup: admin
  allowedIdentityProviders:  # Restrict to platform-idp
    - platform-idp
```

### Example 3: Session with IDP Tracking

After a user creates a session, it will include IDP details:

```yaml
apiVersion: breakglass.telekom.de/v1alpha1
kind: BreakglassSession
metadata:
  name: user-session-123
  namespace: default
spec:
  cluster: prod-cluster
  user: user@platform.com
  grantedGroup: admin
  identityProviderName: platform-idp          # Which IDP authenticated
  identityProviderIssuer: https://auth.platform.com  # JWT issuer URL
```

## Testing

All changes include comprehensive unit tests:

### CRD Tests
- `api/v1alpha1/multi_idp_test.go` - Verifies field presence and backward compatibility

### Loader Tests
- `pkg/config/multi_idp_loader_test.go` - Tests all new loader methods

Run tests:
```bash
# Test CRD changes
go test -v ./api/v1alpha1/... -run "TestIdentityProvider|TestClusterConfig|TestBackwardCompatibility"

# Test loader changes
go test -v ./pkg/config/... -run "TestLoadAll|TestLoadBy|TestValidate|TestGetID"

# Build verification
go build -o /tmp/breakglass ./cmd
```

## Upcoming Phases

### Phase 4: API Authentication (pkg/api/auth.go)
- Multi-OIDC provider support
- JWT issuer extraction
- Dynamic JWKS loading per provider

### Phase 5: Session Creation (pkg/api/api.go)
- Record IDP details when creating sessions
- Validate IDP restrictions from cluster/escalation
- Add IDP-based filtering

### Phase 6: Webhook Authorization (pkg/webhook/auth.go)
- Validate session IDP matches request issuer
- Prevent IDP switching mid-session

### Phase 7: Frontend Config Endpoint
- Expose multiple IDPs to frontend
- Show login button per IDP

### Phase 8: Frontend UI Updates
- IDP selection in login flow
- Escalation filtering by IDP
- Session IDP display

## Migration Guide

### For Existing Single-IDP Deployments

**No action required!** Existing deployments continue working:

1. **Before upgrade**: One IdentityProvider with Primary=true
2. **After upgrade**: Same IdentityProvider works unchanged
3. **Optional enhancement**: Add Issuer field when ready to adopt multi-IDP

### To Adopt Multi-IDP

1. Add `issuer` field to existing IdentityProvider (or create with it)
2. Create additional IdentityProviders with unique issuers
3. Update ClusterConfig to specify IdentityProviderRefs (optional - defaults to all)
4. Update BreakglassEscalation with AllowedIdentityProviders if needed
5. Redeploy - new sessions will track IDP automatically

## Configuration Best Practices

### 1. Unique Issuers
Ensure each IdentityProvider has a unique issuer URL:
```yaml
# ❌ Bad - ambiguous
spec:
  issuer: https://auth.example.com  # Used by two IDPs?
  
# ✅ Good - clear identity
spec:
  issuer: https://auth.platform.example.com
  issuer: https://auth.tenant.example.com
```

### 2. Descriptive Names
Use clear names for IDP references:
```yaml
# ❌ Unclear
identityProviderRefs:
  - idp1
  - idp2

# ✅ Clear
identityProviderRefs:
  - platform-idp
  - tenant-idp
```

### 3. Cluster Restrictions
Restrict clusters to specific IDPs for tenant isolation:
```yaml
# Tenant cluster only accepts tenant IDP
spec:
  identityProviderRefs:
    - tenant-idp
```

### 4. Escalation Inheritance
Leave AllowedIdentityProviders empty to inherit from cluster:
```yaml
# ❌ Redundant - unnecessarily repeats cluster config
spec:
  allowedIdentityProviders:
    - platform-idp
    - tenant-idp

# ✅ Clean - inherits from cluster
spec:
  # allowedIdentityProviders not set
```

## Troubleshooting

### Q: Session created with empty IdentityProviderName
**A**: Phases 2-3 not yet complete. Once API authentication is updated (Phase 3+), IDP details will be populated.

### Q: "No enabled IdentityProvider found for issuer"
**A**: The JWT issuer doesn't match any configured IdentityProvider.issuer. Check:
1. IdentityProvider.spec.issuer matches your OIDC provider's issuer URL
2. JWT token is from a configured OIDC provider
3. Provider is not disabled (spec.disabled=true)

### Q: Escalation not available for user
**A**: User's IDP may not be allowed. Check:
1. User's IDP is in ClusterConfig.identityProviderRefs (or field is empty)
2. User's IDP is in BreakglassEscalation.allowedIdentityProviders (if set)
3. Both IDP lists intersect

## Implementation Status

| Phase | Component | Status |
|-------|-----------|--------|
| 1 | CRD Changes | ✅ Complete |
| 2 | Config Loading | ✅ Complete |
| 3 | API Authentication | 🔄 In Progress |
| 4 | Session Creation | ⏳ Planned |
| 5 | Webhook Authorization | ⏳ Planned |
| 6 | Frontend Config | ⏳ Planned |
| 7 | Frontend UI | ⏳ Planned |

## Files Modified

### Phase 1: CRD Changes
- `api/v1alpha1/identity_provider_types.go` - Added Issuer field
- `api/v1alpha1/cluster_config_types.go` - Added IdentityProviderRefs
- `api/v1alpha1/breakglass_escalation_types.go` - Added AllowedIdentityProviders
- `api/v1alpha1/breakglass_session_types.go` - Added IdentityProviderName, IdentityProviderIssuer
- `api/v1alpha1/multi_idp_test.go` - CRD tests

### Phase 2: Config Loading  
- `pkg/config/config.go` - Added Name, Issuer to IdentityProviderConfig
- `pkg/config/identity_provider_loader.go` - Added new loader methods
- `pkg/config/multi_idp_loader_test.go` - Loader tests

## Next Steps

1. Continue with Phase 3 - API Authentication
2. Add webhook validation for IDP restrictions
3. Update frontend to support multiple IDPs
4. Create comprehensive integration tests
5. Update deployment documentation
