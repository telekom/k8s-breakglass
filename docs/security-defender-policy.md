# Security policy enforcement

Breakglass applies DenyPolicy pod security rules to the effective pod security context. A container inherits `pod.spec.securityContext.runAsUser` when its own value is unset, so inherited UID 0 is evaluated as `runAsRoot` and contributes to the risk score.

Pod label exemptions require the label key to exist. An empty configured value matches an explicitly present empty label and does not exempt a pod missing the key.

Malformed namespace glob patterns fail closed. An invalid deny filter denies namespace matching, while an invalid allow filter allows no namespace. Namespace filters used for debug admission are evaluated against the target spoke cluster through the same REST-config adapter as debug API operations. A missing production adapter provider fails closed.

Pod security overrides are usable only when enabled, scoped, and authorized by the owning escalation. Owner references require the exact API version, kind, controller flag, and nonempty matching UID. If `requireApproval` is set, the session must record an approver and the escalation must configure users or groups as override approvers. User entries match recorded email identifiers case-insensitively after provider restrictions are checked; group entries resolve actual member identifiers through the configured identity-provider GroupMemberResolver and compare them with recorded approvers. Kubernetes impersonation/SelfSubjectReview is not used as group membership proof. Lookup failure disables the relaxation, while ordinary policy evaluation still applies. The policy evaluator also requires the webhook approval marker, bound to the same selected session.

Each recorded approval is paired by index with `status.approverIdentityProviders`.
Additional approval checks enforce the escalation's current provider allowlist
before matching either explicit users or group members. Group membership is
resolved through the recorded provider, including when multiple providers are
allowed. A same-named identity from another provider cannot borrow membership.
Historical missing/empty provider slots cannot satisfy provider restrictions or
group-only additional approvals; they are never inferred from the requester,
last approver, or current default provider. Unrestricted explicit-user policies
retain their identifier-only semantics. Provider load or membership failures
disable the relaxation. Existing approved sessions with unknown provenance may
need a new authenticated approval.

A configured spoke REST-config lookup failure cannot fall back to a local Kubernetes context during approval group lookup. Explicit nil-provider legacy construction retains the legacy lookup behavior.

Ephemeral-container admission requires an active owner or participant debug-session role. Viewer participants cannot use direct Kubernetes ephemeral-container admission to bypass the REST operation role check.

## Approver membership freshness

Override authorization reuses a resolver only for the same recorded provider and effective group-sync configuration. Each lookup reloads the provider and its Secret credentials before reuse; a failed read denies that lookup, and changed credentials, issuer, endpoint, realm, TLS configuration, timeout, or cache TTL replace the resolver. Provider configuration reads and cache publication are serialized; membership network calls run after that lock is released.

Unchanged providers reuse the configured Keycloak membership cache (`spec.keycloak.cacheTTL`, default 10 minutes) and token cache. Group membership revocation therefore becomes visible when that membership entry expires, rather than requiring a fresh IdP lookup on every SAR. Credential or configuration changes invalidate the resolver on the next successful configuration read. Reads observe the configured Kubernetes client; cache-backed clients remain subject to informer propagation delay.

Provider loading and group-resolution diagnostics use the webhook logger, including resolver creation and membership-cache hits at their existing log levels.
Within one approval decision, each provider/group membership result is reused, including failures; a new decision retries membership resolution.
