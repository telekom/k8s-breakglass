# Identity binding

Session ownership is a principal tuple, not just an email or username. Breakglass sessions store the requester provider and issuer; debug sessions also store those fields on participants. Owner reads, list filters, withdrawal/rejection, termination, renewal, joins, departures and debug-resource mutations check this binding. `allowIDPMismatch` remains a spoke authorization compatibility setting and does not let a principal from another provider own or manage the session.

Approver history records each email/provider pair, preserving unknown legacy slots instead of attributing them to later signers. Provider-scoped group hierarchy is used for approval membership. The legacy flattened union is accepted only when authentication explicitly resolved a single identity provider. Cluster `identityProviderRefs` are checked before group resolution, independent of escalation restrictions. Group lookup and the stored session subject use the same configured `userIdentifierClaim`.

## Existing sessions

The authentication middleware permits unbound legacy records only when it is configured in legacy single-JWKS mode, or when exactly one enabled IdentityProvider CR exists and its name and issuer match the authenticated principal. It counts raw enabled CRs: configuration conversion errors do not hide a second provider. A lookup failure leaves legacy access disabled without denying access to correctly bound sessions. Empty or absent JWT fields never establish single-provider mode.

In a multi-provider deployment, unbound existing owner, participant and historical-approver records are ambiguous. Administrators should finish or recreate those sessions with an identified provider before switching to multiple providers. Adding a second enabled provider immediately removes the legacy allowance; independently configured current approvers retain their normal policy-authorized access. Invitations are scoped to the requester's provider; joining records the invitee's authenticated provider and issuer.

## Kubernetes requests

The spoke must propagate `identity.t-caas.telekom.com/issuer` in SubjectAccessReview and AdmissionReview user extras. Debug pod operations and direct ephemeral-container admission compare this issuer with the participant binding and preserve owner/participant versus viewer restrictions. Missing issuer is denied. Unbound legacy participants can use a matching issuer only when one enabled provider is configured; direct webhook callers cannot supply the trusted API middleware's legacy allowance.

## Concurrent transitions

Status apply configurations retain the original caller resource version through the final Kubernetes API mutation. A competing update produces a conflict rather than overwriting newer status. Manual SSA status converters also retain all new provenance fields; CRD generation is required on upgrade so the API server preserves them.

## Admission diagnostics and constraint snapshots

Adding an ephemeral container requires exactly one nonempty issuer extra; missing,
empty, or multiple issuer values are rejected before session lookup. Requests that
add no ephemeral container still require valid issuer provenance and an active
session, as before.
Resolved debug constraints are independent snapshots in both API responses and
session status, including when no binding constraints are configured. Changes to
a resolved snapshot do not change the source template or binding.

The debug webhook E2E fixture forwards the issuer from the API-authenticated token,
including configured Keycloak host overrides. It verifies matching issuer access
and missing/wrong issuer denial separately from pod, participant, and session-state
restrictions.

Cluster identity-policy lookup failures are logged before returning an internal
error. Issuer uniqueness errors identify `spec.issuer` when explicitly configured,
or `spec.oidc.authority` when authority supplies the effective issuer.

The OIDC inheritance E2E case lists the existing IdentityProviders and selects
exactly one by effective issuer (`spec.issuer`, falling back to
`spec.oidc.authority`). This keeps the ClusterConfig reference coverage valid
in both single-cluster setup (the bootstrap provider) and multi-cluster setup
(`main-idp` alongside other providers), while respecting cluster-wide issuer
uniqueness and avoiding duplicate fixture creation.
