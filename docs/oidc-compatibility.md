<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# Kubernetes OIDC identity mapping

Breakglass keeps the authenticated requester principal and the target username
Kubernetes includes in SubjectAccessReviews distinct. A provider-level claim
and prefix define the authenticated API principal and the default Kubernetes
username; a ClusterConfig-only override changes the target username without
replacing that provider principal. Changing only the target Kubernetes username
must not change who can withdraw the session, approve it, or receive its
notification emails.

## Simple claim and prefix

For a cluster whose API server authenticates `preferred_username: k834798` as
`tdi_security_oidc:k834798`, configure:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: ClusterConfig
metadata:
  name: spoke
spec:
  # Include the usual connection configuration here.
  userIdentifierClaim: preferred_username
  userIdentifierPrefix: "tdi_security_oidc:"
```

An IdentityProvider can supply the default claim and prefix. ClusterConfig
settings override those defaults. An explicit empty cluster prefix disables an
inherited prefix; an omitted prefix inherits it. Claim names can identify any
string-valued JWT claim, including `upn` or a provider-specific claim.

The shorthand prefix is literal. For legacy API-server flags, translate
`--oidc-username-prefix=-` to `userIdentifierPrefix: ""`. If the API server uses
its implicit non-email prefix, explicitly configure the issuer URL followed by
`#`. This preserves existing unprefixed Breakglass configurations and avoids
silently changing already-issued grants. The separator is part of the prefix.

## Email is independent from the Kubernetes principal

The username sent to Kubernetes and the email used by Breakglass are separate
values. Breakglass verifies the presented bearer JWT (normally the OAuth access
token sent by the frontend) and reads the standard `email` claim from that
verified token; it does not fetch UserInfo, inspect a browser profile, or
reverse a prefix/CEL expression to derive an address. Other clients must present
a bearer token containing the claims they expect Breakglass to use.

The frontend requests `openid profile email`, but requesting the scope alone is
not enough. The identity provider must put the email claim in the bearer token
that the client sends to the Breakglass API. For the frontend, configure the
provider's protocol mapper or access-token claim mapping when it emits email
only in the ID token or only from UserInfo. Breakglass has no configurable
alternate email-claim setting.

For a verified token such as:

```json
{
  "sub": "7c2f...",
  "email": "christos.ntogkas@telekom.com",
  "preferred_username": "k834798"
}
```

with `userIdentifierClaim: preferred_username` and
`userIdentifierPrefix: "tdi_security_oidc:"` on the IdentityProvider, and no
ClusterConfig override, a new session contains:

```yaml
spec:
  user: tdi_security_oidc:k834798
  requesterUsername: tdi_security_oidc:k834798
  requesterEmail: christos.ntogkas@telekom.com
```

`spec.user` is the exact Kubernetes authorization username. The requester
fields preserve the authenticated API principal and standard email separately,
so clients can retrieve them from `GET /api/breakglassSessions` or
`GET /api/breakglassSessions/{name}` without decoding a token. Email is used
for display and notifications; the requester subject/principal is used for
ownership when email is absent. Email-domain restrictions require a matching
standard email claim, and requester notifications are skipped when no usable
email is present. A custom claim can be the Kubernetes username, but a
different custom claim cannot currently be configured as the requester email.

To troubleshoot a missing address, inspect the access-token payload locally or
use the identity provider's token inspector and check whether `email` is
present there. Decoding a JWT without verifying its signature is for inspection
only; never use decoded claims to authorize a request, paste bearer tokens into
logs or tickets, or assume that an ID-token/UserInfo email reaches the API.

## Structured mappings and validation

Use `spec.kubernetesIdentity` on IdentityProvider or ClusterConfig for the same
mapping syntax as Kubernetes `AuthenticationConfiguration`. A cluster policy
replaces the provider mapping policy as a whole. Do not combine a structured
policy with shorthand claim/prefix fields on the same resource. A cluster can
override an inherited claim-based username with shorthand fields. If the
provider username uses an expression, a cluster prefix override must also set
an explicit claim, or the cluster must supply a complete structured policy.

```yaml
spec:
  kubernetesIdentity:
    claimMappings:
      username:
        expression: "'tdi_security_oidc:' + claims.preferred_username"
      groups:
        claim: roles
        prefix: ""
      uid:
        claim: sub
      extra:
        - key: example.com/tenant
          valueExpression: "claims.tenant"
    claimValidationRules:
      - expression: "claims.tenant == 'operations'"
        message: "operations tenant required"
    userValidationRules:
      - expression: "!user.username.startsWith('system:')"
        message: "reserved Kubernetes username"
```

Kubernetes' upstream authenticator evaluates these fields. Username expressions
must return a string; groups accept a string or string array; extra values use
Kubernetes' CEL rules. Claim validation runs against the verified JWT, and user
validation runs against the mapped identity. Invalid expressions, incorrect
result types, missing required claims, and failed validation deny the request.
For claim-based username or group mappings, explicitly provide `prefix`, even
when its value is `""`. Expression mappings include their own prefix and cannot
also specify `claim` or `prefix`.

When using the `email` username claim, Kubernetes requires a present
`email_verified` claim to be Boolean `true`; an absent claim is accepted for
upstream compatibility. To require explicit verification, including when the
username comes from another claim, configure a provider claim-validation rule
with `expression: "claims.?email_verified.orValue(false) == true"`. CEL
username expressions that use email must also satisfy the upstream
email-verification validation requirements.

## Authentication versus target policy

Provider issuer, discovery, TLS trust, signing algorithms, and accepted
audiences authenticate the token presented to Breakglass. A ClusterConfig
mapping does not redirect discovery, select a different issuer, or turn off
token verification. Target mappings use the authenticated provider's token and
connection policy. Provider group mappings feed Breakglass authorization; cluster
mappings do not replace authenticated provider groups in template or escalation
allowlists. Target groups, UID and extra fields still participate in upstream
user-validation rules. Configure the same claim semantics as the spoke; ensure the
identity provider issues consistent identity claims to the Breakglass and
Kubernetes clients.

The existing `oidc.expectedAudience` remains required. `oidc.audiences` permits
additional accepted audiences. `oidc.supportedSigningAlgs` selects supported
asymmetric signing algorithms, and `oidc.discoveryURL` can select a separate
HTTPS discovery URL. Private certificate authorities remain supported through
`oidc.certificateAuthority`; insecure TLS verification remains rejected.

Kubernetes API-server process settings such as egress-selector wiring and
anonymous authentication are not identity mappings and are not imported into
Breakglass. Breakglass retains its provider allowlists, group-sync policy,
request approval rules, readiness checks, and session expiry enforcement.

Breakglass also retains its existing requirement for an expiration claim and
rejects tokens with a future issued-at time. Without structured group mappings,
the existing `groups` and Keycloak `realm_access.roles` compatibility behavior
remains available. Structured group mappings are authoritative, including an
empty mapped group list. These are Breakglass policies around the upstream
authenticator, rather than additional Kubernetes authentication settings.

## Existing sessions and clients

`BreakglassSession.spec.user` remains the exact Kubernetes authorization
username. New sessions separately record authenticated requester provenance
and email. Ownership and self-approval checks use that provenance, while email
notifications use the requester email. Existing sessions with neither a recorded provider name nor issuer retain
legacy ownership checks only through the trusted single-provider compatibility
path. Partial provider provenance fails closed. Configuration changes do not
rewrite existing sessions; recreate a session whose Kubernetes identity was
incorrect at creation.

Tokens without email use their authenticated provider principal for session
ownership and identity matching. The default authenticated rate limiter keys
these users by issuer, provider name, and authenticated principal. Email-domain
restrictions still require a real matching email claim, and notification email
is skipped when absent.

The frontend uses server-computed requester metadata instead of trying to
reverse username expressions. DebugSession ownership likewise remains separate
from its persisted Kubernetes participant identity. Per-user limits and
duplicate-grant detection retain their existing Kubernetes-username scope.

See the upstream [authentication reference](https://kubernetes.io/docs/reference/access-authn-authz/authentication/)
and [AuthenticationConfiguration API](https://kubernetes.io/docs/reference/config-api/apiserver-config.v1/)
for the mapping language and validation contracts.

## Regression test coverage

The unit tests exercise these supported behaviors and known failure classes:

| Contract | Positive and negative cases |
| --- | --- |
| Identity mapping | Arbitrary claims, literal and empty prefixes, provider inheritance, cluster overrides, CEL mappings, missing and wrongly typed claims |
| Validation | Claim and user rules, invalid expressions and mapping configuration, email verification present/absent/false/wrong type |
| Token authentication | Accepted and rejected audiences, issuer mismatch, signatures, signing algorithms, expiry and future timestamps |
| Provider connection | Default/custom discovery, direct JWKS, trusted CA changes, transport/HTTP/JSON errors, missing keys and key rotation |
| Engine lifecycle | Cache bounds, concurrent creation, eviction, shutdown during creation, nil and repeated close |
| Requester identity | Provider and issuer scope, subject and username matching, no-email users, legacy compatibility and partial provenance rejection |
| Notifications | With mail enabled, missing requester email suppresses approval, rejection, idle-expiry and activation messages; persisted email is used instead of the mapped principal |
| API and UI | Configuration loading, native policy conversion, server-computed ownership, explicit false metadata and legacy fallback |

Run `go test ./pkg/oidc ./pkg/api ./api/v1alpha1 ./pkg/config ./pkg/breakglass`
for the backend regression suite. Frontend ownership tests are in
`frontend/tests/unit/views/SessionBrowser.spec.ts`. The real-cluster OIDC E2E
flow separately verifies denial before approval, authorization of the exact
prefixed principal afterward, and denial of the unprefixed username and email.
Its RBAC fixture uses a dedicated namespace so unrelated deny-policy fixtures
cannot mask the identity-mapping result. The native-policy admission fixture
includes the required OIDC client-secret reference.
The target-connection fixture also grants its OIDC service user impersonation
of the synthetic authorization checker and the test's grant group, plus read
access to the test namespace. These are connection permissions, separate from
the requested user's temporary grant; the test still requires denial before
approval and denial of other principals after approval.

Notification E2E assertions decode MIME transfer encoding before matching the
rendered content. Run `go test ./e2e/api -run '^TestDecodeMailHogBody'` for the
offline MIME regression tests, including the real request template encoded by
gomail and malformed or unsupported transfer encodings.

Unit case coverage and statement coverage are separate measures; these tests
do not imply exhaustive coverage of every possible JWT or CEL expression.
