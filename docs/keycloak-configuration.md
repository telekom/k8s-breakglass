# Keycloak Configuration Guide

This guide documents how the breakglass controller integrates with [Keycloak](https://www.keycloak.org/) for OIDC authentication and group synchronization. It covers every operating mode, all OAuth 2.0 token flows, required realm/client/user configuration, GoCloak API interactions, and Kubernetes API server OIDC setup.

**Audience**: Platform engineers configuring Keycloak for breakglass, and developers implementing similar OIDC flows in other applications.

> **Keycloak version**: This guide is written for Keycloak 26.x. All Admin REST API endpoints and client settings reference the [Keycloak 26.0 Server Administration Guide](https://www.keycloak.org/docs/latest/server_admin/).

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Realm Configuration](#realm-configuration)
- [Client Configuration](#client-configuration)
  - [1. breakglass-ui (Frontend / Public)](#1-breakglass-ui-frontend--public)
  - [2. kubernetes (API Server / Public)](#2-kubernetes-api-server--public)
  - [3. breakglass-group-sync (Service Account / Confidential)](#3-breakglass-group-sync-service-account--confidential)
  - [4. breakglass-e2e-oidc (E2E Testing / Confidential)](#4-breakglass-e2e-oidc-e2e-testing--confidential)
- [Protocol Mappers](#protocol-mappers)
- [Users, Groups, and Roles](#users-groups-and-roles)
  - [Service Account Users](#service-account-users)
  - [Required Realm Roles](#required-realm-roles)
  - [Required Client Roles](#required-client-roles)
  - [Groups](#groups)
- [Kubernetes API Server OIDC Configuration](#kubernetes-api-server-oidc-configuration)
- [Operating Modes](#operating-modes)
  - [Choosing an Operating Mode](#choosing-an-operating-mode)
  - [Mode 1: Kubeconfig (No OIDC)](#mode-1-kubeconfig-no-oidc)
  - [Mode 2: Client Credentials Flow (Direct OIDC)](#mode-2-client-credentials-flow-direct-oidc)
  - [Mode 3: Client Credentials via IdentityProvider](#mode-3-client-credentials-via-identityprovider)
  - [Mode 4: Offline Refresh Token Flow](#mode-4-offline-refresh-token-flow)
  - [Mode 5: Token Exchange Flow (RFC 8693)](#mode-5-token-exchange-flow-rfc-8693)
- [Token Acquisition Flow (Internal)](#token-acquisition-flow-internal)
- [Fallback Policy](#fallback-policy)
- [GoCloak API Interactions (Group Sync)](#gocloak-api-interactions-group-sync)
- [IdentityProvider Custom Resource](#identityprovider-custom-resource)
- [ClusterConfig Conditions](#clusterconfig-conditions)
- [TLS and TOFU (Trust On First Use)](#tls-and-tofu-trust-on-first-use)
- [Checker Validation Flow](#checker-validation-flow)
- [Obtaining Offline Refresh Tokens](#obtaining-offline-refresh-tokens)
- [Post-Setup Verification](#post-setup-verification)
- [Troubleshooting](#troubleshooting)
- [Production Considerations](#production-considerations)
- [Reference Links](#reference-links)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────┐
│                  Keycloak Server                    │
│  ┌─────────────┐ ┌──────────────┐ ┌──────────────┐ │
│  │breakglass-ui│ │  kubernetes  │ │ group-sync   │ │
│  │  (public)   │ │  (public)    │ │(confidential)│ │
│  └──────┬──────┘ └──────┬───────┘ └──────┬───────┘ │
│         │               │               │          │
│  ┌──────┴───────────────┴───────────────┴────────┐ │
│  │        Realm: breakglass-e2e                   │ │
│  │   Users · Groups · Roles · Protocol Mappers    │ │
│  └────────────────────────────────────────────────┘ │
└────────────┬────────────────────────┬───────────────┘
             │                        │
    OIDC tokens (JWT)        Admin REST API
             │                   (GoCloak)
             ▼                        ▼
┌────────────────────┐  ┌──────────────────────────┐
│  Kubernetes API    │  │  Breakglass Controller   │
│  Server            │  │  ┌────────────────────┐  │
│  (OIDC configured) │  │  │OIDCTokenProvider   │  │
│                    │  │  │ - client_credentials│  │
│  AuthenticationCfg │  │  │ - refresh_token     │  │
│  - issuer          │  │  │ - token_exchange    │  │
│  - audiences       │  │  └────────────────────┘  │
│  - claimMappings   │  │  ┌────────────────────┐  │
│                    │◄─┤  │KeycloakGroupMember │  │
│                    │  │  │Resolver (GoCloak)  │  │
│                    │  │  │ - GetToken          │  │
│                    │  │  │ - GetGroups         │  │
│                    │  │  │ - GetGroupMembers   │  │
│                    │  │  │ - GetGroup          │  │
│                    │  │  └────────────────────┘  │
└────────────────────┘  └──────────────────────────┘
```

The breakglass controller uses Keycloak in two independent capacities:

1. **OIDC Token Provider** ([`pkg/cluster/oidc.go`](../pkg/cluster/oidc.go)): Acquires tokens to authenticate against target Kubernetes clusters. Supports client credentials, refresh token, and token exchange flows.

2. **Group Membership Resolver** ([`pkg/breakglass/escalation/escalation_status_updater.go`](../pkg/breakglass/escalation/escalation_status_updater.go)): Queries the Keycloak Admin REST API to resolve group memberships for escalation status updates. Uses the [GoCloak](https://github.com/Nerzal/gocloak) library (v13).

---

## Realm Configuration

Create a Keycloak realm with the following settings:

| Setting | Value | Notes |
|---------|-------|-------|
| **Realm name** | `breakglass-e2e` (or your chosen name) | Must match the OIDC issuer URL path segment |
| **Enabled** | `true` | |
| **Access Token Lifespan** | `300` seconds (5 min) | Default; overridable per client |
| **SSO Session Idle Timeout** | `1800` seconds (30 min) | Default |
| **SSO Session Max Lifespan** | `36000` seconds (10 hr) | Default |
| **Offline Session Idle Timeout** | `2592000` seconds (30 days) | For offline refresh tokens |
| **Offline Session Max Lifespan** | Disabled | Keep offline tokens valid indefinitely unless revoked |

> **Upstream reference**: [Keycloak Realm Settings — Sessions](https://www.keycloak.org/docs/latest/server_admin/#_timeouts)

### Realm Creation

**Via Admin Console**:
1. Log in to `https://keycloak.example.com/admin`
2. Click the realm dropdown → **Create Realm**
3. Enter the realm name and click **Create**

**Via CLI** (`kcadm.sh`):
```bash
/opt/keycloak/bin/kcadm.sh config credentials \
  --server http://localhost:8080 \
  --realm master --user admin --password admin

/opt/keycloak/bin/kcadm.sh create realms \
  -s realm=breakglass-e2e \
  -s enabled=true
```

**Via Realm Import** (recommended for reproducibility):
```bash
# Mount the realm JSON and start Keycloak with --import-realm
docker run -e KEYCLOAK_ADMIN=admin \
  -e KEYCLOAK_ADMIN_PASSWORD=admin \
  -v ./breakglass-e2e-realm.json:/opt/keycloak/data/import/realm.json \
  quay.io/keycloak/keycloak:26.5.0 start-dev --import-realm
```

The E2E realm JSON is at [`config/dev/resources/breakglass-e2e-realm.json`](../config/dev/resources/breakglass-e2e-realm.json).

> **Important**: Keycloak realm import is asynchronous. The pod becomes `Ready` before the import finishes. The E2E setup script polls for the realm and clients before proceeding (see `assign_keycloak_service_account_roles()` in [`e2e/kind-setup-single.sh`](../e2e/kind-setup-single.sh)).

---

## Client Configuration

Four Keycloak clients are required for a full breakglass deployment. Each serves a distinct purpose:

### 1. breakglass-ui (Frontend / Public)

**Purpose**: OIDC client for the breakglass web UI. Users authenticate via browser-based Authorization Code flow.

| Setting | Value |
|---------|-------|
| **Client ID** | `breakglass-ui` |
| **Client Type** | Public (`publicClient: true`) |
| **Standard Flow** | Enabled (Authorization Code) |
| **Direct Access Grants** | Enabled (Resource Owner Password Credentials — for E2E tests) |
| **Service Accounts** | Disabled |
| **Redirect URIs** | `http://localhost:28081/*`, `*` (restrict in production) |
| **Web Origins** | `http://localhost:28081`, `*` (restrict in production) |
| **Access Token Lifespan** | `300` seconds (5 min) |
| **Client Session Idle** | `300` seconds (5 min) |
| **Client Session Max** | `3600` seconds (1 hr) |

**Keycloak Admin Console path**: Clients → Create client → OpenID Connect

**Required Protocol Mappers** (configured on this client):

| Mapper Name | Type | Config |
|-------------|------|--------|
| `groups` | `oidc-group-membership-mapper` | `claim.name=groups`, `full.path=false`, all token claims enabled |
| `username` | `oidc-usermodel-property-mapper` | `user.attribute=username`, `claim.name=preferred_username`, `jsonType.label=String` |
| `audience-kubernetes` | `oidc-audience-mapper` | `included.custom.audience=kubernetes` — adds `kubernetes` to the token's `aud` claim |

> **Why `audience-kubernetes`?** The Kubernetes API server validates that the token's audience (`aud`) claim contains `kubernetes`. Without this mapper, tokens from `breakglass-ui` would only contain `breakglass-ui` as audience and would be rejected by the API server.

> **Upstream reference**: [Keycloak Protocol Mappers](https://www.keycloak.org/docs/latest/server_admin/#_protocol-mappers)

### 2. kubernetes (API Server / Public)

**Purpose**: OIDC client representing the Kubernetes API server. Tokens issued to this client are used for `kubectl` authentication and by the breakglass controller when using client_credentials flow.

| Setting | Value |
|---------|-------|
| **Client ID** | `kubernetes` |
| **Client Type** | Public (`publicClient: true`) |
| **Enabled** | `true` |
| **Standard Flow** | Enabled |
| **Direct Access Grants** | Enabled |
| **Service Accounts** | Disabled |
| **Redirect URIs** | `urn:ietf:wg:oauth:2.0:oob`, `http://localhost:18000`, `http://localhost:8000` |
| **Web Origins** | `*` |
| **Use Refresh Tokens** | `true` |

**Required Protocol Mappers**:

| Mapper Name | Type | Config |
|-------------|------|--------|
| `groups` | `oidc-group-membership-mapper` | `claim.name=groups`, `full.path=false`, `multivalued=true` |
| `Client Host` | `oidc-usersessionmodel-note-mapper` | `user.session.note=clientHost`, `claim.name=clientHost` |
| `Client ID` | `oidc-usersessionmodel-note-mapper` | `user.session.note=clientId`, `claim.name=clientId` |
| `Client IP Address` | `oidc-usersessionmodel-note-mapper` | `user.session.note=clientAddress`, `claim.name=clientAddress` |
| `kubernetes-audience` | `oidc-audience-mapper` | `included.client.audience=kubernetes` — ensures `aud` contains `kubernetes` |

> **Upstream reference**: [Keycloak OIDC Clients](https://www.keycloak.org/docs/latest/server_admin/#_oidc_clients)

### 3. breakglass-group-sync (Service Account / Confidential)

**Purpose**: Confidential service account client used by the breakglass controller for two purposes:
1. **Group sync**: Queries the Keycloak Admin REST API to resolve group memberships
2. **Token exchange / Fallback**: Acts as the client for token exchange (RFC 8693) and as fallback credentials when refresh tokens expire

| Setting | Value |
|---------|-------|
| **Client ID** | `breakglass-group-sync` |
| **Client Type** | Confidential (`publicClient: false`) |
| **Client Secret** | `breakglass-group-sync-secret` (change in production!) |
| **Client Authenticator** | `client-secret` |
| **Service Accounts** | Enabled (`serviceAccountsEnabled: true`) |
| **Standard Flow** | Disabled |
| **Direct Access Grants** | Disabled |
| **Access Token Lifespan** | `300` seconds (5 min) |
| **Token Exchange Standard** | **Enabled** (`token.exchange.standard.enabled: true`) |

**Required Protocol Mappers**:

| Mapper Name | Type | Config |
|-------------|------|--------|
| `kubernetes-audience` | `oidc-audience-mapper` | `included.custom.audience=kubernetes` |

**Required Service Account Roles** (assigned post-import via `kcadm.sh`):

| Client | Role | Purpose |
|--------|------|---------|
| `realm-management` | `view-users` | Read user details (email, username) |
| `realm-management` | `query-users` | Search for users |
| `realm-management` | `query-groups` | Search for groups |
| `realm-management` | `view-realm` | Read realm configuration |

> **Why are roles assigned post-import?** Keycloak's realm import does not reliably persist service account → client role mappings. The E2E setup script uses `kcadm.sh` inside the Keycloak pod to assign these roles after import (see [`e2e/kind-setup-single.sh`](../e2e/kind-setup-single.sh)).

**Assigning roles via `kcadm.sh`**:

> **Security Warning**: Never use example secrets or admin passwords in production. Replace all placeholder credentials with securely generated values.

```bash
# Authenticate
/opt/keycloak/bin/kcadm.sh config credentials \
  --server http://localhost:8080 \
  --realm master --user admin --password admin

REALM=breakglass-e2e
CLIENT_ID=breakglass-group-sync

# Get the service account user ID
SA_USER_ID=$(kcadm.sh get users -r "$REALM" \
  -q username=service-account-$CLIENT_ID \
  --fields id --format csv --noquotes)

# Get the realm-management client UUID
RM_CLIENT_UUID=$(kcadm.sh get clients -r "$REALM" \
  -q clientId=realm-management \
  --fields id --format csv --noquotes)

# Get and assign role IDs
for ROLE in view-users query-users query-groups view-realm; do
  ROLE_ID=$(kcadm.sh get "clients/$RM_CLIENT_UUID/roles/$ROLE" -r "$REALM" \
    --fields id --format csv --noquotes)
  kcadm.sh create "users/$SA_USER_ID/role-mappings/clients/$RM_CLIENT_UUID" \
    -r "$REALM" \
    -b "[{\"id\":\"$ROLE_ID\",\"name\":\"$ROLE\"}]"
done
```

> **Side effect**: Enabling `token.exchange.standard.enabled` allows this client to act as the exchange client in RFC 8693 flows. See [Mode 5: Token Exchange Flow](#mode-5-token-exchange-flow-rfc-8693).

> **Upstream reference**: [Keycloak Service Account Roles](https://www.keycloak.org/docs/latest/server_admin/#_service_accounts), [Token Exchange](https://www.keycloak.org/docs/latest/securing_apps/#_token-exchange)

### 4. breakglass-e2e-oidc (E2E Testing / Confidential)

**Purpose**: Confidential client used exclusively for E2E tests that exercise OIDC auth modes. Not needed in production.

| Setting | Value |
|---------|-------|
| **Client ID** | `breakglass-e2e-oidc` |
| **Client Type** | Confidential (`publicClient: false`) |
| **Client Secret** | `breakglass-e2e-oidc-secret` |
| **Client Authenticator** | `client-secret` |
| **Service Accounts** | Disabled |
| **Standard Flow** | Enabled |
| **Direct Access Grants** | Enabled |
| **Access Token Lifespan** | `300` seconds (5 min) |
| **Token Exchange Standard** | **Enabled** (`token.exchange.standard.enabled: true`) |
| **Redirect URIs** | `*` |
| **Web Origins** | `*` |

**Required Protocol Mappers**:

| Mapper Name | Type | Config |
|-------------|------|--------|
| `groups` | `oidc-group-membership-mapper` | `claim.name=groups`, `full.path=false` |
| `kubernetes-audience` | `oidc-audience-mapper` | `included.custom.audience=kubernetes` |

---

## Protocol Mappers

Protocol mappers control which claims appear in the OIDC tokens. The breakglass controller and API server rely on specific claims:

| Claim | Mapper Type | Required By | Notes |
|-------|------------|-------------|-------|
| `groups` | `oidc-group-membership-mapper` | API server, controller | Must use `full.path=false` (flat group names, not `/parent/child` paths) |
| `preferred_username` | `oidc-usermodel-property-mapper` | UI, audit logs | Maps `user.attribute=username` to `preferred_username` claim |
| `email` | (built-in scope) | Controller, API server | Used as `userIdentifierClaim` for matching users to sessions |
| `aud` (audience) | `oidc-audience-mapper` | API server | Must include `kubernetes` in `aud` array for API server to accept the token |
| `clientHost` | `oidc-usersessionmodel-note-mapper` | Audit | Client host for audit trail |
| `clientId` | `oidc-usersessionmodel-note-mapper` | Audit | Client ID for audit trail |
| `clientAddress` | `oidc-usersessionmodel-note-mapper` | Audit | Client IP for audit trail |

> **Critical**: If the `groups` mapper uses `full.path=true`, group names will be `/parent/child` format which won't match the flat group names used in `BreakglassEscalation` resources. Always use `full.path=false`.

> **Upstream reference**: [Keycloak Protocol Mapper Types](https://www.keycloak.org/docs/latest/server_admin/#_protocol-mappers)

---

## Users, Groups, and Roles

### Service Account Users

When `serviceAccountsEnabled: true` is set on a client, Keycloak automatically creates a service account user named `service-account-<clientId>`.

For `breakglass-group-sync`:
- **Username**: `service-account-breakglass-group-sync`
- **Email**: `breakglass-group-sync@service.local` (auto-generated)
- **Service Account Client ID**: `breakglass-group-sync`

### Required Realm Roles

All human users require these realm roles:

| Role | Purpose |
|------|---------|
| `offline_access` | Allows obtaining offline refresh tokens (for Mode 4). Without this role, `grant_type=refresh_token` with an offline token will fail with `invalid_grant`. |
| `uma_authorization` | Standard UMA role; assigned by default in most Keycloak configurations |

The `offline_access` role is configured as a **default optional client scope**:
```json
{
  "defaultOptionalClientScopes": ["offline_access"]
}
```

This means clients must explicitly request `scope=offline_access` to receive an offline refresh token.

> **Upstream reference**: [Keycloak Offline Access](https://www.keycloak.org/docs/latest/server_admin/#_offline-access)

### Required Client Roles

The `breakglass-group-sync` service account requires roles on the `realm-management` internal client:

| Client Role | Admin REST API Permission |
|-------------|---------------------------|
| `view-users` | `GET /admin/realms/{realm}/groups/{id}/members` |
| `query-users` | `GET /admin/realms/{realm}/users?search=...` |
| `query-groups` | `GET /admin/realms/{realm}/groups?search=...` |
| `manage-users` | Required by some admin API endpoints |
| `view-realm` | `GET /admin/realms/{realm}` |

Without these roles, the GoCloak API calls will return `403 Forbidden`.

> **Upstream reference**: [Keycloak Admin REST API Roles](https://www.keycloak.org/docs/latest/server_admin/#_admin_permissions)

### Groups

Create groups matching the `escalatedGroup` values in your `BreakglassEscalation` resources. Example group structure:

```
breakglass-users        # Default group for all breakglass users
breakglass-approvers    # Users who can approve sessions
dev                     # Developer group
ops                     # Operations group
approver                # Approver group
senior-ops              # Senior operations (higher privilege)
emergency-response      # Emergency access group
```

Groups appear as flat names in the `groups` claim of OIDC tokens (with `full.path=false`).

The E2E realm includes 53 users and 75+ groups for comprehensive test coverage. Production deployments typically use far fewer.

---

## Kubernetes API Server OIDC Configuration

The target Kubernetes cluster's API server must be configured to accept OIDC tokens from Keycloak. There are two approaches:

### Option A: Structured Authentication Configuration (Kubernetes 1.30+)

Create an `AuthenticationConfiguration` file and pass it via `--authentication-config`:

```yaml
apiVersion: apiserver.config.k8s.io/v1   # v1beta1 for K8s <1.34
kind: AuthenticationConfiguration
jwt:
  - issuer:
      url: https://keycloak.example.com/realms/breakglass-e2e
      certificateAuthority: |
        -----BEGIN CERTIFICATE-----
        <Keycloak TLS CA certificate PEM>
        -----END CERTIFICATE-----
      audiences:
        - kubernetes
    claimMappings:
      username:
        claim: email
        prefix: ""
      groups:
        claim: groups
        prefix: "oidc:"
```

Then in the kube-apiserver manifest:
```yaml
spec:
  containers:
  - command:
    - kube-apiserver
    - --authentication-config=/etc/kubernetes/authentication-config.yaml
    # ... other flags
    volumeMounts:
    - name: authentication-config
      mountPath: /etc/kubernetes/authentication-config.yaml
      readOnly: true
  volumes:
  - name: authentication-config
    hostPath:
      path: /etc/kubernetes/authentication-config.yaml
```

### Option B: Legacy OIDC Flags (Kubernetes <1.30)

```yaml
spec:
  containers:
  - command:
    - kube-apiserver
    - --oidc-issuer-url=https://keycloak.example.com/realms/breakglass-e2e
    - --oidc-client-id=kubernetes
    - --oidc-username-claim=email
    - --oidc-username-prefix=""
    - --oidc-groups-claim=groups
    - --oidc-groups-prefix=oidc:
    - --oidc-ca-file=/etc/kubernetes/keycloak-ca.crt
```

### Critical Configuration Notes

1. **`issuer.url`** must match the `issuerURL` in your `ClusterConfig` or `IdentityProvider` exactly (including trailing `/realms/<name>`)
2. **`audiences`** must include `kubernetes` — this is why all Keycloak clients need the `audience-kubernetes` protocol mapper
3. **`claimMappings.username.claim`** must match the `userIdentifierClaim` in your `ClusterConfig` (default: `email`)
4. **`claimMappings.groups.prefix`** adds a prefix to all group names. If set to `oidc:`, a group `dev` becomes `oidc:dev` in RBAC. Your `BreakglassEscalation.spec.escalatedGroup` must use the unprefixed name (the controller handles prefix matching)
5. **`certificateAuthority`** must trust the Keycloak server's TLS certificate. If using self-signed certs, include the CA here.

> **Upstream reference**: [Kubernetes OIDC Authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#openid-connect-tokens), [Structured Authentication Configuration](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#using-authentication-configuration)

---

## Operating Modes

The breakglass controller supports five authentication modes for connecting to target clusters. Each mode determines how the controller acquires tokens to perform SubjectAccessReview (SAR) checks.

### Choosing an Operating Mode

| Criterion | Mode 1: Kubeconfig | Mode 2: Direct CC | Mode 3: IDP CC | Mode 4: Refresh Token | Mode 5: Token Exchange |
|-----------|--------------------|--------------------|----------------|------------------------|------------------------|
| **Keycloak required for cluster auth?** | No | Yes | Yes | Yes | Yes |
| **Extra OIDC client needed?** | No | Yes (confidential SA) | No (reuses IDP) | No (reuses existing) | Yes (confidential) |
| **Credential rotation** | Manual kubeconfig | Automatic (token refresh) | Automatic | Manual (token rotation) | Automatic |
| **Identity preserved?** | SA identity only | SA identity only | SA identity only | User identity | Delegated identity |
| **Offline access?** | N/A | N/A | N/A | Yes (long-lived) | Depends on subject token |
| **Complexity** | Low | Medium | Medium | Medium-High | High |
| **Best for** | Simple / non-OIDC clusters | Dedicated SA per cluster | Many clusters, one IDP | Existing client reuse, user identity | Cross-realm delegation |

> **Recommendation**: Start with **Mode 1** (Kubeconfig) for simple setups. Use **Mode 3** (IDP-based) for multi-cluster deployments with shared Keycloak. Use **Mode 4** (Refresh Token) when you need to preserve user identity. Use **Mode 5** (Token Exchange) only for cross-realm or delegation scenarios.

> **Mutual exclusivity**: If both `oidcAuth` and `oidcFromIdentityProvider` are set on a `ClusterConfig`, `oidcFromIdentityProvider` takes precedence.

### Mode 1: Kubeconfig (No OIDC)

The simplest mode — uses a static kubeconfig stored in a Kubernetes Secret. No Keycloak interaction for cluster auth (Keycloak is still used for user auth and group sync).

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: my-cluster
  namespace: breakglass-system
spec:
  authType: Kubeconfig
  kubeconfigSecretRef:
    name: my-cluster-kubeconfig
    namespace: breakglass-system
    key: value   # default key name
```

**Keycloak requirements**: None for cluster auth. Keycloak is still required for the IdentityProvider (user authentication).

**Side effects**: None. Token is read from the kubeconfig file.

### Mode 2: Client Credentials Flow (Direct OIDC)

The controller uses OAuth 2.0 [client credentials grant](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4) to acquire a service account token directly.

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: oidc-cluster
  namespace: breakglass-system
spec:
  authType: OIDC
  oidcAuth:
    issuerURL: https://keycloak.example.com/realms/breakglass-e2e
    clientID: breakglass-group-sync
    clientSecretRef:
      name: oidc-client-secret
      namespace: breakglass-system
      key: value
    server: https://api.target-cluster.example.com:6443
    audience: kubernetes       # optional, defaults to server URL
    scopes:                    # optional, only openid is auto-included
      - groups
      - email
    certificateAuthority: |    # PEM-encoded CA cert for the OIDC issuer
      -----BEGIN CERTIFICATE-----
      <Keycloak TLS CA certificate PEM>
      -----END CERTIFICATE-----
    insecureSkipTLSVerify: false
    allowTOFU: true            # auto-discover cluster CA on first connect
```

**Keycloak requirements**:
- Confidential client with `serviceAccountsEnabled: true`
- Client secret stored in a Kubernetes Secret
- `kubernetes-audience` protocol mapper on the client

**Token endpoint HTTP request** (constructed by `clientCredentialsFlow()` in [`pkg/cluster/oidc.go`](../pkg/cluster/oidc.go)):

```http
POST /realms/breakglass-e2e/protocol/openid-connect/token HTTP/1.1
Host: keycloak.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials
&client_id=breakglass-group-sync
&client_secret=<secret>
&audience=kubernetes
&scope=openid+groups+email
```

> **Note**: Only the `openid` scope is auto-included. The `groups` and `email` scopes shown above are only included if explicitly listed in `spec.oidcAuth.scopes`.

**Response**:
```json
{
  "access_token": "eyJhbG...",
  "token_type": "Bearer",
  "expires_in": 300,
  "scope": "openid email groups"
}
```

**Side effects**:
- Creates a Keycloak user session for the service account
- Token is cached in memory with 30-second refresh buffer (`TokenRefreshBuffer`)
- If `allowTOFU: true` and no CA is configured, the controller will connect to the cluster API server, capture its TLS certificate, and cache it (TOFU)

> **Upstream reference**: [OAuth 2.0 Client Credentials Grant](https://datatracker.ietf.org/doc/html/rfc6749#section-4.4), [Keycloak Service Accounts](https://www.keycloak.org/docs/latest/server_admin/#_service_accounts)

### Mode 3: Client Credentials via IdentityProvider

Same flow as Mode 2, but the OIDC configuration is inherited from an `IdentityProvider` CR, reducing duplication when the same Keycloak instance serves multiple clusters.

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: IdentityProvider
metadata:
  name: corporate-idp
spec:
  oidc:
    authority: https://keycloak.example.com/realms/breakglass-e2e
    clientID: breakglass-ui
  issuer: https://keycloak.example.com/realms/breakglass-e2e
  groupSyncProvider: Keycloak
  keycloak:
    baseURL: https://keycloak.example.com
    realm: breakglass-e2e
    clientID: breakglass-group-sync
    clientSecretRef:
      name: group-sync-secret
      namespace: breakglass-system
      key: value
    cacheTTL: 10m
---
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: oidc-cluster-via-idp
  namespace: breakglass-system
spec:
  authType: OIDC
  oidcFromIdentityProvider:
    name: corporate-idp         # References the IdentityProvider above
    server: https://api.target-cluster.example.com:6443
    # clientID and clientSecretRef are inherited from IDP's keycloak section
    # unless explicitly overridden here
```

**Resolution logic** (in `resolveOIDCFromIdentityProvider()` in [`pkg/cluster/oidc.go`](../pkg/cluster/oidc.go)):

1. Fetch the referenced `IdentityProvider` CR
2. Check if the IdentityProvider is enabled (`.spec.disabled` must be `false`)
3. Build `OIDCAuthConfig` by merging:
   - `issuerURL` ← `idp.Spec.OIDC.Authority`
   - `clientID` ← `ref.ClientID` (override) OR `idp.Spec.OIDC.ClientID` (fallback)
   - `server` ← `ref.Server`
   - `clientSecretRef` ← `ref.ClientSecretRef` (override) OR `idp.Spec.Keycloak.ClientSecretRef` (fallback)
4. If no `clientSecretRef` is specified and the IDP has Keycloak configured, the Keycloak SA credentials are used automatically

**Side effects**: Same as Mode 2, plus:
- The IdentityProvider must exist and be in `Ready` condition
- If the IDP is disabled, the ClusterConfig check fails

### Mode 4: Offline Refresh Token Flow

The controller uses a pre-obtained [offline refresh token](https://www.keycloak.org/docs/latest/server_admin/#_offline-access) to acquire fresh access tokens. This avoids registering a new OIDC client — the token was issued to the user's existing OIDC client.

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: refresh-token-cluster
  namespace: breakglass-system
spec:
  authType: OIDC
  oidcAuth:
    issuerURL: https://keycloak.example.com/realms/breakglass-e2e
    clientID: breakglass-e2e-oidc   # The client that issued the refresh token
    server: https://api.target-cluster.example.com:6443
    refreshTokenSecretRef:
      name: offline-token-secret
      namespace: breakglass-system
      key: token
    fallbackPolicy: Warn            # None | Auto | Warn
    # clientSecretRef is only needed for confidential clients
    clientSecretRef:
      name: oidc-client-secret
      namespace: breakglass-system
      key: value
```

Or via IdentityProvider:
```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: refresh-token-via-idp
  namespace: breakglass-system
spec:
  authType: OIDC
  oidcFromIdentityProvider:
    name: corporate-idp
    server: https://api.target-cluster.example.com:6443
    refreshTokenSecretRef:
      name: offline-token-secret
      namespace: breakglass-system
      key: token
    fallbackPolicy: Warn
```

**Token endpoint HTTP request** (constructed by `refreshToken()` in [`pkg/cluster/oidc.go`](../pkg/cluster/oidc.go)):

```http
POST /realms/breakglass-e2e/protocol/openid-connect/token HTTP/1.1
Host: keycloak.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=refresh_token
&client_id=breakglass-e2e-oidc
&refresh_token=<offline_refresh_token>
&client_secret=<secret>           # only for confidential clients
```

**Response**:
```json
{
  "access_token": "eyJhbG...",
  "token_type": "Bearer",
  "expires_in": 300,
  "refresh_token": "eyJhb...",
  "scope": "openid email groups offline_access"
}
```

**Keycloak requirements**:
- The user must have the `offline_access` realm role
- The client must have `offline_access` in its optional client scopes
- The refresh token must have been obtained with `scope=offline_access`

> **Note — Secret key defaults**: The `SecretKeyReference.key` field defaults to `"value"` per the CRD schema, but the `refreshTokenSecretRef` and `subjectTokenSecretRef` code paths default to `"token"` at runtime if no key is specified. This is a runtime override — always set the `key` field explicitly to avoid confusion.

**Side effects**:
- **Refresh token rotation**: Some Keycloak configurations rotate the refresh token on each use. The controller handles both — if a new refresh token is returned, it's cached; if not, the original is reused.
- **Token expiry detection**: If the refresh token is expired/revoked, Keycloak returns `{"error": "invalid_grant"}`. The controller detects this via `isInvalidGrantError()` which checks for: `invalid_grant`, `Token is not active`, `Session not active`, `Refresh token expired`.
- **Fallback behavior**: Controlled by `fallbackPolicy` — see [Fallback Policy](#fallback-policy).

> **Upstream reference**: [OAuth 2.0 Refresh Token Grant](https://datatracker.ietf.org/doc/html/rfc6749#section-6), [Keycloak Offline Access](https://www.keycloak.org/docs/latest/server_admin/#_offline-access)

### Mode 5: Token Exchange Flow (RFC 8693)

The controller exchanges a subject token (stored in a Kubernetes Secret) for a cluster-scoped access token using [RFC 8693 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693).

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: token-exchange-cluster
  namespace: breakglass-system
spec:
  authType: OIDC
  oidcAuth:
    issuerURL: https://keycloak.example.com/realms/breakglass-e2e
    clientID: breakglass-group-sync
    clientSecretRef:
      name: group-sync-secret
      namespace: breakglass-system
      key: value
    server: https://api.target-cluster.example.com:6443
    audience: kubernetes
    tokenExchange:
      enabled: true
      subjectTokenSecretRef:
        name: subject-token-secret
        namespace: breakglass-system
        key: token
      subjectTokenType: urn:ietf:params:oauth:token-type:access_token   # default
      requestedTokenType: urn:ietf:params:oauth:token-type:access_token # default
      resource: https://api.target-cluster.example.com:6443             # optional
      # Actor token (optional, for delegation)
      actorTokenSecretRef:
        name: actor-token-secret
        namespace: breakglass-system
        key: token
      actorTokenType: urn:ietf:params:oauth:token-type:access_token     # default
```

**Token endpoint HTTP request** (constructed by `tokenExchangeFromSecret()` → `tokenExchangeWithActorToken()` in [`pkg/cluster/oidc.go`](../pkg/cluster/oidc.go)):

```http
POST /realms/breakglass-e2e/protocol/openid-connect/token HTTP/1.1
Host: keycloak.example.com
Content-Type: application/x-www-form-urlencoded

grant_type=urn:ietf:params:oauth:grant-type:token-exchange
&client_id=breakglass-group-sync
&client_secret=<secret>
&subject_token=<subject_access_token>
&subject_token_type=urn:ietf:params:oauth:token-type:access_token
&requested_token_type=urn:ietf:params:oauth:token-type:access_token
&audience=kubernetes
&resource=https://api.target-cluster.example.com:6443
&scope=groups+email
# Optional actor token (delegation):
&actor_token=<actor_access_token>
&actor_token_type=urn:ietf:params:oauth:token-type:access_token
```

**Response**:
```json
{
  "access_token": "eyJhbG...",
  "token_type": "Bearer",
  "expires_in": 300
}
```

**Keycloak requirements**:
- The exchanging client must have `token.exchange.standard.enabled: true` in its attributes
- The client must be confidential with a client secret
- The subject token must be a valid access token from the same realm
- Fine-grained token exchange permissions may need to be configured in Keycloak's authorization services

> **Note**: Unlike the client credentials flow, the token exchange flow does **not** auto-prepend `openid` to the scope. Scopes from `spec.oidcAuth.scopes` are passed through directly.

> **Upstream reference**: [RFC 8693 OAuth Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693), [Keycloak Token Exchange](https://www.keycloak.org/docs/latest/securing_apps/#_token-exchange)

---

## Token Acquisition Flow (Internal)

The `OIDCTokenProvider.getToken()` method follows a strict priority order when acquiring tokens. This is the complete decision tree:

```
getToken(clusterName, oidcConfig, namespace)
│
├── 1. Check in-memory cache
│   └── Valid & not expired (with 30s buffer)? → Return cached token
│
├── 2. Refresh from cached refresh token
│   └── Cache has a refresh token? → POST grant_type=refresh_token
│       ├── Success? → Cache & return
│       └── Fail? → Continue to step 3
│
├── 3. Refresh from K8s Secret (offline token)
│   └── refreshTokenSecretRef configured?
│       ├── Read token from Secret → POST grant_type=refresh_token
│       │   ├── Success? → Cache & return
│       │   └── Fail? → evaluateFallback()
│       │       ├── fallbackPolicy=None → Return ErrRefreshTokenExpired (hard fail)
│       │       ├── fallbackPolicy=Auto → client_credentials (silent fallback)
│       │       └── fallbackPolicy=Warn → client_credentials + ErrDegradedAuth
│       └── Not configured? → Continue to step 4
│
├── 4a. Token Exchange (if enabled)
│   └── tokenExchange.enabled? → Read subject token from Secret
│       → POST grant_type=urn:ietf:params:oauth:grant-type:token-exchange
│       → Cache & return
│
└── 4b. Client Credentials (default)
    └── clientSecretRef configured?
        → POST grant_type=client_credentials
        → Cache & return
```

**Token caching**: Tokens are cached in memory keyed by `"{namespace}/{clusterName}"`. The cache is not persisted — a controller restart re-acquires all tokens. The refresh buffer (`TokenRefreshBuffer = 30s`) triggers proactive refresh before expiry.

**Token injection**: Tokens are injected into HTTP requests via `WrapTransport` on the `rest.Config`. The `tokenInjectorRoundTripper` calls `getToken()` on every request, which returns the cached token or refreshes transparently.

---

## Fallback Policy

The `fallbackPolicy` field controls what happens when the primary auth flow (refresh token) fails:

| Policy | Behavior | Condition Set | Use Case |
|--------|----------|--------------|----------|
| `None` (default) | Hard fail. Cluster becomes unreachable. | `RefreshTokenExpired=True`, `Ready=False` | Production: explicit operator action required |
| `Auto` | Silent fallback to `client_credentials` using IDP Keycloak SA credentials. | None | Low-ops environments where availability > audit trail |
| `Warn` | Fallback to `client_credentials` + emit warning. | `DegradedAuth=True` | Production: maintain availability while alerting operators |

**Fallback credential resolution** (in `applyFallbackCredentials()`):
1. If the `OIDCAuthConfig` already has a `clientSecretRef` → use it directly
2. Otherwise, check the `fallbackCreds` map (populated during `resolveOIDCFromIdentityProvider()`)
3. If found, deep-copy the OIDC config and swap in the IDP's Keycloak SA `clientID` + `clientSecretRef`
4. If no fallback credentials are available → fail with `ErrRefreshTokenExpired`

> **Important**: When using `oidcFromIdentityProvider` with `refreshTokenSecretRef`, the controller stores the IDP's Keycloak SA credentials in `fallbackCreds` at resolution time. The primary refresh token flow uses the original `clientID` (not the Keycloak SA), because the refresh token was issued to that specific client.

---

## GoCloak API Interactions (Group Sync)

The `KeycloakGroupMemberResolver` (in [`pkg/breakglass/escalation/escalation_status_updater.go`](../pkg/breakglass/escalation/escalation_status_updater.go)) uses the [GoCloak v13](https://github.com/Nerzal/gocloak) library to query the Keycloak Admin REST API for group membership data.

### API Call 1: GetToken (Authentication)

```go
token, err := k.gocloak.GetToken(ctx, k.cfg.Realm, gocloak.TokenOptions{
    ClientID:     &k.cfg.ClientID,
    ClientSecret: &k.cfg.ClientSecret,
    GrantType:    gocloak.StringP("client_credentials"),
})
```

**HTTP equivalent**:
```http
POST /realms/{realm}/protocol/openid-connect/token HTTP/1.1
Content-Type: application/x-www-form-urlencoded

grant_type=client_credentials&client_id={clientID}&client_secret={clientSecret}
```

**Required Keycloak config**: Service account enabled, client secret configured.

**Token caching**: The resolver caches the token for 5 minutes (`tokenTime.Add(5*time.Minute)`), independent of the `OIDCTokenProvider` cache.

**Error handling**: Logs `clientID`, `baseURL`, `realm`, `endpoint`, and `grantType` on failure.

### API Call 2: GetGroups (Search)

```go
params := gocloak.GetGroupsParams{Search: gocloak.StringP(group)}
groups, err := k.gocloak.GetGroups(ctx, token, k.cfg.Realm, params)
```

**HTTP equivalent**:
```http
GET /admin/realms/{realm}/groups?search={groupName} HTTP/1.1
Authorization: Bearer {token}
```

**Required Keycloak role**: `query-groups` on `realm-management`

**Behavior**: Returns groups whose name contains the search string. The resolver then does a case-insensitive exact match (`strings.EqualFold`) on `group.Name` to find the specific group.

**Side effect**: If no matching group is found, caches an empty member list to avoid repeated queries.

### API Call 3: GetGroupMembers (Direct Members)

```go
params2 := gocloak.GetGroupsParams{}
members, err := k.gocloak.GetGroupMembers(ctx, token, k.cfg.Realm, *groupID, params2)
```

**HTTP equivalent**:
```http
GET /admin/realms/{realm}/groups/{groupId}/members HTTP/1.1
Authorization: Bearer {token}
```

**Required Keycloak role**: `view-users` on `realm-management`

**Behavior**: Returns all direct members of the group. For each member, the resolver extracts the identifier in priority order:
1. `m.Email` if non-empty
2. `m.Username` if non-empty (fallback)

### API Call 4: GetGroup (Subgroup Detail)

```go
groupDetail, err := k.gocloak.GetGroup(ctx, token, k.cfg.Realm, *groupID)
```

**HTTP equivalent**:
```http
GET /admin/realms/{realm}/groups/{groupId} HTTP/1.1
Authorization: Bearer {token}
```

**Required Keycloak role**: `query-groups` on `realm-management`

**Behavior**: Fetches the group detail including `SubGroups`. For each subgroup, the resolver makes an additional `GetGroupMembers` call to include subgroup members in the result. This means the resolver returns members from the group AND all direct subgroups (one level deep).

**Caching**: Results are cached for `cacheTTL` (default: 10 minutes). The cache key is the group name.

### Complete API Call Sequence

For a single `Members("ops")` call:

```
1. GetToken(realm, {client_credentials})           → token
2. GetGroups(token, realm, {search: "ops"})         → [{id: "abc", name: "ops"}]
3. GetGroupMembers(token, realm, "abc", {})         → [{email: "user1@example.com"}, ...]
4. GetGroup(token, realm, "abc")                    → {subGroups: [{id: "def"}, ...]}
5. GetGroupMembers(token, realm, "def", {})         → [{email: "user2@example.com"}, ...]
   (repeated for each subgroup)
```

Result: `["user1@example.com", "user2@example.com"]`

---

## IdentityProvider Custom Resource

The `IdentityProvider` CR is a cluster-scoped resource that configures OIDC authentication for users and optional group synchronization.

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: IdentityProvider
metadata:
  name: corporate-idp
spec:
  # OIDC configuration (required)
  oidc:
    authority: https://keycloak.example.com/realms/breakglass-e2e
    clientID: breakglass-ui           # Public client for UI auth
    jwksEndpoint: ""                  # Auto-discovered from authority
    insecureSkipVerify: false         # NEVER true in production
    certificateAuthority: |           # PEM-encoded CA cert
      -----BEGIN CERTIFICATE-----
      ...
      -----END CERTIFICATE-----

  # Issuer must match the 'iss' claim in JWT tokens
  issuer: https://keycloak.example.com/realms/breakglass-e2e

  # Group sync provider (optional)
  groupSyncProvider: Keycloak
  keycloak:
    baseURL: https://keycloak.example.com
    realm: breakglass-e2e
    clientID: breakglass-group-sync   # Service account client
    clientSecretRef:
      name: group-sync-secret
      namespace: breakglass-system
      key: value
    cacheTTL: 10m                     # Group membership cache duration
    requestTimeout: 10s               # Keycloak API request timeout
    insecureSkipVerify: false
    certificateAuthority: ""          # Use system trust or embed CA PEM

  # Session limits (optional)
  sessionLimits:
    maxActiveSessionsPerUser: 3
    groupOverrides:
      - group: "platform-*"
        unlimited: true
      - group: "ops"
        maxActiveSessionsPerUser: 5

  displayName: "Corporate Keycloak"
  disabled: false
```

**Status conditions**:

| Condition | Meaning |
|-----------|---------|
| `Ready` | Configuration is valid, OIDC provider reachable |
| `GroupSyncHealthy` | GoCloak can authenticate and query groups |
| `CacheUpdated` | Provider cache has been refreshed |
| `ConversionFailed` | Internal conversion error |
| `ValidationFailed` | Validation error in spec |

---

## ClusterConfig Conditions

The `ClusterConfig` resource uses conditions to report authentication state:

| Condition | Status | Reason | Meaning |
|-----------|--------|--------|---------|
| `Ready` | `True` | `KubeconfigValidated` / `OIDCValidated` | Cluster is reachable and auth is working |
| `Ready` | `False` | `OIDCTokenFetchFailed` / `OIDCRefreshFailed` / etc. | Cluster is not reachable |
| `RefreshTokenExpired` | `True` | `RefreshTokenExpired` | Offline refresh token is expired/revoked and `fallbackPolicy=None` |
| `DegradedAuth` | `True` | `DegradedAuth` | Primary auth failed but fallback succeeded (`fallbackPolicy=Warn`) |
| `RefreshTokenExpired` | `False` | `AuthRecovered` | Previously expired token has recovered (e.g., after rotation) |
| `DegradedAuth` | `False` | `AuthRecovered` | Previously degraded auth has recovered |

**Condition lifecycle**:
1. Checker runs → calls `OIDCTokenProvider.GetRESTConfig()`
2. `GetRESTConfig()` performs preflight token acquisition
3. If `ErrDegradedAuth` → checker sets `DegradedAuth=True` via `handleOIDCAuthError()`
4. If `ErrRefreshTokenExpired` → checker sets `RefreshTokenExpired=True` and `Ready=False`
5. On next successful check → `clearOIDCDegradedConditions()` sets both to `False` with reason `AuthRecovered`

---

## TLS and TOFU (Trust On First Use)

The controller supports three TLS strategies for both the OIDC issuer and the target cluster API server:

### 1. Explicit CA Certificate

Recommended for production. Provide the CA via:
- `certificateAuthority` field (PEM inline) for OIDC issuer TLS
- `caSecretRef` for target cluster API server TLS

### 2. Trust On First Use (TOFU)

Set `allowTOFU: true` to auto-discover CAs on first connection:

1. Controller connects to the server with `InsecureSkipVerify: true`
2. During the TLS handshake, `VerifyConnection` captures the certificate chain
3. Hostname verification is still performed against the leaf certificate
4. The root/CA certificate is extracted, PEM-encoded, and cached in memory
5. If `caSecretRef` is configured, the CA is persisted to the Secret (via SSA)
6. All subsequent connections use the cached CA with full TLS verification

**Security properties**:
- TOFU is vulnerable to MITM on the first connection only
- Hostname verification prevents connecting to the wrong server
- Certificate fingerprint is logged for audit
- After first use, the CA is persisted and verified on all connections

**RBAC requirements**: TOFU requires the controller to have `create` and `patch` permissions on Secrets in the target namespace. The persisted Secret is managed via Server-Side Apply (SSA) with the label `app.kubernetes.io/managed-by: breakglass` and annotation `breakglass.t-caas.telekom.com/tofu-ca: true`.

**Cache behavior on restart**: All in-memory caches are lost on controller restart — including TOFU CAs, cached tokens, refresh tokens, fallback credentials, and HTTP clients. If `caSecretRef` is configured, the TOFU CA is persisted and survives restarts. Without `caSecretRef`, a restart triggers re-TOFU on the next connection.

### 3. InsecureSkipTLSVerify

For testing only. Set `insecureSkipTLSVerify: true` to disable all TLS verification. The webhook emits a warning when this is used.

---

## Checker Validation Flow

The `ClusterConfigChecker` (in [`pkg/breakglass/clusterconfig/checker.go`](../pkg/breakglass/clusterconfig/checker.go)) validates cluster connectivity on a periodic interval. For OIDC-auth clusters:

```
Check(ClusterConfig)
│
├── authType == Kubeconfig?
│   └── validateKubeconfig() → read Secret, parse kubeconfig, test connection
│
├── oidcAuth configured?
│   └── validateDirectOIDCAuth() →
│       1. Validate issuerURL, clientID, server are non-empty
│       2. Validate clientSecretRef Secret exists (if set)
│       3. Validate refreshTokenSecretRef Secret exists (if set)
│       4. Validate caSecretRef Secret exists (if set)
│       5. OIDCTokenProvider.GetRESTConfig(cc) →
│          ├── Success → clearOIDCDegradedConditions() → return restCfg
│          ├── ErrDegradedAuth → handleOIDCAuthError() → DegradedAuth condition → return restCfg
│          └── ErrRefreshTokenExpired → handleOIDCAuthError() → RefreshTokenExpired + Ready=False
│
└── oidcFromIdentityProvider configured?
    └── validateOIDCFromIdentityProvider() →
        1. Validate IdentityProvider exists and is enabled
        2. Validate server is non-empty
        3. Validate referenced Secrets exist
        4. OIDCTokenProvider.GetRESTConfig(cc) → (same as above)
```

After a successful `GetRESTConfig`, the checker performs a reachability test against the cluster API server (e.g., `GET /healthz`).

---

## Obtaining Offline Refresh Tokens

To use Mode 4 (refresh token flow), you need to obtain an offline refresh token and store it in a Kubernetes Secret.

### Via Direct Access Grants (Resource Owner Password Credentials)

```bash
# Request an offline token using username/password
curl -s -X POST \
  "https://keycloak.example.com/realms/breakglass-e2e/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=password" \
  -d "client_id=breakglass-e2e-oidc" \
  -d "client_secret=breakglass-e2e-oidc-secret" \
  -d "username=test-user@example.com" \
  -d "password=test" \
  -d "scope=openid offline_access" | jq -r '.refresh_token'
```

> **Important**: The `scope=offline_access` parameter is required to receive an offline refresh token. Without it, you get a regular session-bound refresh token that expires when the SSO session ends.

### Store in Kubernetes Secret

```bash
OFFLINE_TOKEN=$(curl -s -X POST ... | jq -r '.refresh_token')

kubectl create secret generic offline-token-secret \
  --namespace breakglass-system \
  --from-literal=token="$OFFLINE_TOKEN"
```

### Programmatic (Go)

The E2E tests use `helpers.ObtainOfflineRefreshToken()`:

```go
func ObtainOfflineRefreshToken(keycloakURL, realm, clientID, clientSecret, username, password string) (string, error) {
    data := url.Values{
        "grant_type":    {"password"},
        "client_id":     {clientID},
        "client_secret": {clientSecret},
        "username":      {username},
        "password":      {password},
        "scope":         {"openid offline_access"},
    }
    resp, err := http.PostForm(
        fmt.Sprintf("%s/realms/%s/protocol/openid-connect/token", keycloakURL, realm),
        data,
    )
    // ... parse response, return refresh_token
}
```

### Token Lifetime and Revocation

- **Offline tokens do not expire by time** (unless `offlineSessionMaxLifespanEnabled` is enabled on the realm)
- **Revocation**: Admin Console → Users → Sessions → Revoke, or via Admin REST API
- **Rotation**: Some Keycloak configs return a new refresh token on each use. The controller handles this automatically.

> **Upstream reference**: [Keycloak Offline Access](https://www.keycloak.org/docs/latest/server_admin/#_offline-access)

### Via Authorization Code Flow (Production)

For production environments where Direct Access Grants are disabled, use the Authorization Code flow:

**Step 1**: Open the authorization URL in a browser:
```
https://keycloak.example.com/realms/breakglass-e2e/protocol/openid-connect/auth?
  client_id=breakglass-e2e-oidc&
  redirect_uri=http://localhost:8000&
  response_type=code&
  scope=openid+offline_access
```

**Step 2**: After authentication, Keycloak redirects to `http://localhost:8000?code=<AUTH_CODE>`. Extract the code.

**Step 3**: Exchange the authorization code for tokens:
```bash
curl -s -X POST \
  "https://keycloak.example.com/realms/breakglass-e2e/protocol/openid-connect/token" \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code" \
  -d "client_id=breakglass-e2e-oidc" \
  -d "client_secret=<YOUR_CLIENT_SECRET>" \
  -d "code=<AUTH_CODE>" \
  -d "redirect_uri=http://localhost:8000" | jq -r '.refresh_token'
```

> **Tip**: Use `kubelogin` / `kubectl oidc-login` to automate this flow for `kubectl` users.

---

## Post-Setup Verification

After configuring Keycloak, verify the setup:

### 1. Test Token Acquisition

```bash
# Client credentials flow
TOKEN=$(curl -s -X POST \
  "https://keycloak.example.com/realms/breakglass-e2e/protocol/openid-connect/token" \
  -d "grant_type=client_credentials" \
  -d "client_id=breakglass-group-sync" \
  -d "client_secret=<YOUR_SECRET>" | jq -r '.access_token')

echo "$TOKEN" | cut -d. -f2 | base64 -d 2>/dev/null | jq .
```

Verify the decoded token contains:
- `"aud"` includes `"kubernetes"`
- `"groups"` claim is present (for clients with group mapper)
- `"iss"` matches your issuer URL exactly

### 2. Check ClusterConfig Status

```bash
kubectl get clusterconfig -n breakglass-system -o yaml | \
  grep -A5 'conditions:'
```

Expected: `type: Ready`, `status: "True"`

### 3. Check IdentityProvider Status

```bash
kubectl get identityprovider -o yaml | grep -A5 'conditions:'
```

Expected: `type: Ready`, `status: "True"` and `type: GroupSyncHealthy`, `status: "True"`

### 4. Test Group Sync

Check controller logs for successful group resolution:
```bash
kubectl logs -n breakglass-system deployment/breakglass-controller | \
  grep -i 'group.*member\|keycloak.*group'
```

---

## Troubleshooting

### OIDC Discovery Fails

```
OIDCDiscoveryFailed: OIDC discovery request failed
```

**Cause**: Controller cannot reach `{issuerURL}/.well-known/openid-configuration`

**Fix**:
1. Verify the issuer URL is correct and accessible from the controller pod
2. Check TLS: use `certificateAuthority`, `allowTOFU: true`, or `insecureSkipTLSVerify: true` (test only)
3. For in-cluster Keycloak: ensure DNS resolution works (add to `/etc/hosts` or use a Kubernetes Service)

### Token Fetch Fails

```
OIDCTokenFetchFailed: client credentials flow failed: token request returned status 401
```

**Cause**: Invalid client ID or secret

**Fix**:
1. Verify the client exists in Keycloak and is enabled
2. Verify the client secret matches the Secret in Kubernetes
3. For service account clients: ensure `serviceAccountsEnabled: true`

### Refresh Token Expired

```
RefreshTokenExpired=True: Refresh token expired or revoked
```

**Cause**: The offline refresh token in the Secret is no longer valid

**Fix**:
1. Obtain a new offline token (see [Obtaining Offline Refresh Tokens](#obtaining-offline-refresh-tokens))
2. Update the Kubernetes Secret
3. The controller will detect the new token on the next check cycle
4. Consider using `fallbackPolicy: Warn` to maintain availability during token rotation

### Group Sync Fails

```
Keycloak groups search failed: 403 Forbidden
```

**Cause**: The `breakglass-group-sync` service account lacks required realm-management roles

**Fix**:
1. Verify the service account has `view-users`, `query-users`, `query-groups` roles on `realm-management`
2. Re-run role assignment (see [Client 3](#3-breakglass-group-sync-service-account--confidential))

### Audience Mismatch

```
the audience in the token does not match the expected audience
```

**Cause**: Token's `aud` claim doesn't include `kubernetes`

**Fix**:
1. Add `oidc-audience-mapper` protocol mapper to the client with `included.custom.audience=kubernetes`
2. Verify the mapper is applied: decode the token at [jwt.io](https://jwt.io) and check the `aud` claim

### Groups Not in Token

**Cause**: Missing `oidc-group-membership-mapper` protocol mapper

**Fix**:
1. Add the `groups` protocol mapper to the client
2. Ensure `full.path=false` for flat group names
3. Verify by decoding the token and checking for the `groups` claim

### DegradedAuth Condition Active

```
DegradedAuth=True: Primary auth failed, using fallback credentials
```

**Cause**: The primary refresh token flow failed, and `fallbackPolicy: Warn` triggered a successful fallback to client_credentials.

**Implications**:
- The cluster is **still reachable** — the fallback is working
- The controller is using service account credentials instead of the original user identity
- This may affect audit trail granularity

**Fix**:
1. Obtain a new offline refresh token (see [Obtaining Offline Refresh Tokens](#obtaining-offline-refresh-tokens))
2. Update the Kubernetes Secret referenced by `refreshTokenSecretRef`
3. Wait for the next checker cycle — the condition will clear automatically with reason `AuthRecovered`
4. If the issue recurs frequently, consider using `fallbackPolicy: Auto` (silent) or investigate why the refresh token keeps expiring

---

## Production Considerations

### High Availability

- **Keycloak behind a load balancer**: The controller caches the OIDC discovery response (token endpoint URL). Keycloak nodes behind a load balancer are transparent — the controller uses the token endpoint URL from discovery, not the issuer URL directly.
- **Session replication**: Offline refresh tokens are stored in the Keycloak database, not in-memory sessions. They survive Keycloak node restarts and HA failovers.
- **DNS**: Ensure the Keycloak hostname resolves correctly from within the controller pod. For in-cluster Keycloak, use a Kubernetes Service or add an entry to `/etc/hosts`.

### Controller Restart Cache Loss

All in-memory state is lost on controller restart:
- **OIDC tokens**: Re-acquired on the next request (transparent to users)
- **TOFU CAs**: Re-discovered on the next connection (if `caSecretRef` is configured, the CA survives in the Secret)
- **Fallback credentials**: Re-resolved from the IdentityProvider on the next check
- **Group membership cache**: Re-populated from Keycloak on the next query

A restart may cause a brief spike in Keycloak API calls and token requests as all caches are repopulated.

### Token Lifetimes

- **Access tokens** (5 min default): Short-lived by design. The controller caches and refreshes them proactively (30s buffer).
- **Offline refresh tokens** (indefinite by default): Monitor for revocation. Consider enabling `offlineSessionMaxLifespanEnabled` to enforce a maximum lifetime.
- **Group membership cache** (10 min default via `cacheTTL`): Tune based on how frequently group memberships change in your organization.

---

## Reference Links

### Keycloak Documentation
- [Server Administration Guide](https://www.keycloak.org/docs/latest/server_admin/) — Realms, clients, users, roles
- [Securing Applications Guide](https://www.keycloak.org/docs/latest/securing_apps/) — OIDC, token exchange, service accounts
- [Admin REST API Reference](https://www.keycloak.org/docs-api/latest/rest-api/) — Complete API specification
- [Offline Access](https://www.keycloak.org/docs/latest/server_admin/#_offline-access) — Offline tokens
- [Token Exchange](https://www.keycloak.org/docs/latest/securing_apps/#_token-exchange) — RFC 8693 implementation
- [Protocol Mappers](https://www.keycloak.org/docs/latest/server_admin/#_protocol-mappers) — Token claim configuration
- [Service Accounts](https://www.keycloak.org/docs/latest/server_admin/#_service_accounts) — Client credentials flow

### OAuth 2.0 / OIDC Standards
- [RFC 6749 — OAuth 2.0 Authorization Framework](https://datatracker.ietf.org/doc/html/rfc6749) — Client credentials, refresh tokens
- [RFC 8693 — OAuth 2.0 Token Exchange](https://datatracker.ietf.org/doc/html/rfc8693) — Token exchange flow
- [OpenID Connect Core](https://openid.net/specs/openid-connect-core-1_0.html) — OIDC specification
- [OpenID Connect Discovery](https://openid.net/specs/openid-connect-discovery-1_0.html) — Well-known configuration

### Kubernetes OIDC
- [Kubernetes Authentication](https://kubernetes.io/docs/reference/access-authn-authz/authentication/) — OIDC token authentication
- [Structured Authentication Configuration](https://kubernetes.io/docs/reference/access-authn-authz/authentication/#using-authentication-configuration) — K8s 1.30+ AuthenticationConfiguration
- [API Server Flags](https://kubernetes.io/docs/reference/command-line-tools-reference/kube-apiserver/) — `--oidc-*` flags

### GoCloak Library
- [GoCloak v13 GitHub](https://github.com/Nerzal/gocloak) — Go client for Keycloak Admin REST API
- [GoCloak Documentation](https://pkg.go.dev/github.com/Nerzal/gocloak/v13) — API reference

### Breakglass Documentation
- [Cluster Configuration](./cluster-config.md) — ClusterConfig CRD reference
- [Identity Provider](./identity-provider.md) — IdentityProvider CRD reference
- [Configuration Reference](./configuration-reference.md) — All configuration options
- [Security Best Practices](./security-best-practices.md) — Production hardening
