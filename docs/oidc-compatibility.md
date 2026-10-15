<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# Kubernetes OIDC identity mapping

Breakglass has two identities to keep distinct: the authenticated requester who
owns a session, and the username Kubernetes includes in SubjectAccessReviews.
Changing the Kubernetes username must not change who can withdraw the session,
approve it, or receive its notification emails.

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

Kubernetes enforces `email_verified` when using the `email` username claim. CEL
expressions that use email must satisfy the upstream email-verification
validation requirements; do not use an expression to bypass those requirements.

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
notifications use the requester email. Existing sessions without the new
provenance retain the legacy ownership checks. Configuration changes do not
rewrite existing sessions; recreate a session whose Kubernetes identity was
incorrect at creation.

Tokens without email use their authenticated provider principal for session
identity and per-user rate limiting. Email-domain restrictions still require
a real matching email claim, and notification email is skipped when absent.

The frontend uses server-computed requester metadata instead of trying to
reverse username expressions. DebugSession ownership likewise remains separate
from its persisted Kubernetes participant identity. Per-user limits and
duplicate-grant detection retain their existing Kubernetes-username scope.

See the upstream [authentication reference](https://kubernetes.io/docs/reference/access-authn-authz/authentication/)
and [AuthenticationConfiguration API](https://kubernetes.io/docs/reference/config-api/apiserver-config.v1/)
for the mapping language and validation contracts.
