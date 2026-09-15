# Debug API security fixes

Debug resource mutations use an uncached hub read to recheck active state, expiry
and operator participation immediately before the spoke mutation. This narrows
the revocation window; it does not create an atomic transaction between clusters.
Pod-copy and node-debug creation compensate for failed or revoked status recording
by deleting only the UID returned from creation.

Successful ephemeral injection is irreversible. Its evidence is recorded even if
the request is canceled or the session becomes terminal, using a bounded detached
tracking context. A late revocation returns a policy error after recording the
injection. A deleted session or unavailable hub can still prevent tracking;
operators must retain target-cluster audit logs and tear down the target pod when
container removal is required. Terminal sessions are not reactivated by tracking.

Node-debug checks enforce required affinity, required label presence, and denied
nodes/labels. Empty required affinity remains unsatisfiable when constraints are
combined. Template target namespaces remain authoritative for legacy templates.

Notification mailbox matching trims whitespace and folds case. Excluded groups
are expanded through the configured primary Keycloak group resolver before
filtering actual recipient mailboxes. The resolver uses its existing membership
cache; this does not promise instantaneous group-membership changes. Missing or
failed group resolution suppresses that notification and emits a warning rather
than sending to an unknown excluded membership. Deployments without primary
Keycloak group synchronization cannot use group exclusions to selectively send;
use explicit user exclusions there. The resolver is selected at startup.

Repeated leave requests do not change historical leave timestamps, and rejoined
participants can leave their current active row. Failure to load a recorded
binding denies approver-based session reads instead of falling through to broader
template permissions. Existing requester and participant read access is unchanged.

The session-creation E2E check compares the DebugSession namespace with its
selected ClusterConfig namespace, independently of the controller pod or test
helper namespace, while asserting the template's spoke target namespace
separately. The resource namespace comes from the selected ClusterConfig.

When durable debug-session quota admission races the reconciler, the API retries
only the bounded admission operation after an uncached read confirms the same
UID, immutable spec, and non-terminal object. It never repeats the API Create;
replacement, spec changes, terminal state, and exhausted conflicts fail closed.

The API create/get fixture registers the returned DebugSession name and
namespace (and captures its UID) for cleanup. This prevents the single-cluster
fixture from leaving a session in `default` when the helper's controller
namespace is `breakglass-system`, while retaining the existing cleanup skip
controls.

Fixture guidance follows the same boundary: omit the deprecated API `namespace`
field when exercising a template's default target, so the returned hub
`DebugSession` namespace remains the ClusterConfig namespace while its target is
`breakglass-debug`. Helm scheduling fixtures use exact denied node names such as
`control-plane-1` and `etcd-1`; wildcard matching belongs in denied label
selectors.
