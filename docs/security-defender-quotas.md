<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# Durable session quota admission

API session requests first create a provisional object to obtain a Kubernetes
UID. The controller records that UID in the shared
`breakglass-session-quota-v1` ConfigMap in the configured controller namespace.
One resource-version compare-and-swap reserves every applicable scope together.
Only then does the API complete admission and send successful creation responses
or request notifications. Provisional objects are visible but cannot grant
breakglass access or progress to debug workloads without admission.

The ledger covers regular-session tuple uniqueness (user, cluster, granted
group), global per-user limits, escalation-UID totals, debug template-UID totals,
binding-UID totals, and binding per-user limits. Regular user identity preserves
the existing canonical `spec.user` quota semantics across escalations and
providers. Debug per-user limits preserve username/email alias matching. Limits
from IDP group overrides use the authenticated group snapshot captured at request
time; policy resources are read from the API server when admission is attempted.
Template concurrency limits span session namespaces and bindings. A binding may
further restrict template concurrency.

Reservations include pending, approval-waiting, scheduled, and active sessions.
They have no process lease or clock expiration. A crashed worker, failed initial
status update, slow workload deployment, or canceled request cannot release its
slot. Retries for the same UID are idempotent; existing reservations are
preserved when limits tighten. A request uses the live policy snapshot read for
its admission attempt; policy changes are not an atomic transaction with
admission already in flight.

Quota denial records a terminal rejection/failure with an optimistic status
write. Cleanup of ledger entries happens when a candidate scope is full or the ledger
reaches its storage bound, only after an authoritative GET proves that exact UID
terminal or deleted. Unrelated entries remain conservatively occupied without
per-admission reads. When a saturated scope contains an unreadable reservation,
that reservation remains occupied while other entries are checked for confirmed
terminal cleanup; admission still fails closed if capacity cannot be proven.
Storage pressure triggers cleanup across both session kinds. Missing
entries in a list never prove that a reservation is free. Expiry timestamps
alone do not release slots before lifecycle cleanup records terminal state.
Status writes for managed sessions use resource-version fencing so stale
activation cannot revive a terminal session. Spoke resource cleanup remains the
responsibility of the debug lifecycle controller.

The regular cleanup loop completes empty-status provisional admissions after a
crash. Debug reconciliation retries admission before approval-waiting or
activation, including sessions created directly as Kubernetes resources, and
never resolves templates or deploys workloads while the admission annotation is
still provisional. API completion retries resource-version conflicts against a
fresh same-UID object; repeated conflicts remain fail-closed without repeating
the Kubernetes Create or duplicating the durable ledger reservation.
Failed API calls can therefore leave recoverable provisional objects; inspect
the session list before submitting a replacement request. Explicit quota denials
are terminal and do not later activate. Nonterminal legacy sessions are counted
conservatively during bootstrap, including resolved bindings on sessions without
an explicit binding reference. Already recorded reservations use their immutable
ledger scopes even if their template or binding is later deleted. A legacy
session whose scopes have never been recorded and whose policy is missing blocks
bootstrap until an operator restores its policy or completes its lifecycle.
Auto-discovery rejects failed, missing, or ambiguous cluster-label data rather
than silently dropping selector-based binding limits.

## Deployment and recovery

Stop old API/controller writers before enabling this version, then restart every
writer with the same configured controller namespace before reopening traffic.
Mixed old/new replicas cannot provide atomic quotas because old writers bypass
the admission protocol. Existing nonterminal sessions remain counted during
migration; an already over-limit population can temporarily prevent admission.
Automation that reuses a template with a finite concurrency limit must complete
or delete each nonterminal session before creating the next fixture session.
Privileged writers of session spec/status, admission annotations, or ledger
ConfigMaps remain in the controller's trust boundary.

All API and lifecycle roles need ConfigMap get/create/update and session
get/list/patch/status-update permissions. The shipped controller role already
includes these operations; review custom API-only roles. Startup validation
requires a nonblank `--breakglass-namespace` (or `BREAKGLASS_NAMESPACE`) when
API, controller, or cleanup roles are enabled. Read-only frontend or webhook-only
processes may omit it; the value is never defaulted because replicas must share
one explicit ledger namespace. The ledger uses version
1 JSON and refuses unsupported/corrupt data or serialized size above 512 KiB.
It fails closed when storage/read/CAS retries fail. This deliberately bounds
storage; deployments approaching that ceiling need a sharded reservation
protocol before increasing capacity.

Do not delete or edit the ledger to clear quota errors. Process timeout is not
proof that a session stopped. Resolve the owning session through its terminal
lifecycle or delete that exact session with normal cleanup, then retry admission.
Ledger restoration/rebuild requires stopping all writers and accounting for all
nonterminal sessions and provisional reservations before service resumes.

Admission preserves requester provider/issuer fields and provider-aligned approval
history. Status writes reject the caller's stale resource version before updating
admission metadata, so an older approval snapshot cannot overwrite a newer vote.
Debug lifecycle binding discovery errors stop processing before admission or
activation; a later quota lookup cannot substitute for the binding used to
evaluate approval and workload constraints.

Regular sessions must have one unambiguous controlling `BreakglassEscalation`
owner with the current API version, name, and UID. Admission and recovery verify
that the live escalation still has that UID before using its policy. Invalid
unrecorded legacy ownership blocks bootstrap until corrected; invalid metadata
never removes an already-recorded UID reservation. Additional noncontrolling
owners of other resource kinds do not change the escalation quota scope.

When durable admission is enabled, regular-session quota prechecks use indexed
informer reads as an advisory check. A stale precheck can pass, but the mandatory
uncached UID reservation gate still rejects excess usage before success or
activation. Constructors without durable admission retain uncached prechecks.
