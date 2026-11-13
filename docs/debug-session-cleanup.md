<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
-->

# DebugSession cleanup recovery

DebugSession status keeps a `deployedResources` inventory containing the API
version, kind, namespace, name, and (when available) UID of resources created
by the workload reconciler. The typed deployed-resource cleanup path supports
Pods, DaemonSets, Deployments, Jobs, ResourceQuotas, and
PodDisruptionBudgets. Auxiliary and multi-document pod-template resources use
their separate status inventories and unstructured cleanup paths; an unknown
deployed kind is retained and reported for operator action.

The UID is captured immediately after each successful create/apply and is used
as a delete precondition. This prevents a later object with the same name from
being removed. The copied-pod and node-debug paths use the same inventory.

If a spoke API call fails, the controller retains the residual identities and
requeues DebugSession reconciliation. It also sets the durable
`CleanupFailed=True` condition with reason `CleanupFailed` and a bounded list
of residual identities. The condition is cleared with reason
`CleanupRecovered` only after a later attempt has observed the inventory gone.
The `debug_session.cleanup_failed` audit event is emitted when cleanup starts
failing and again only when the set of residual identities changes (compared
by a digest of the complete set, shown as `residual set <digest>` at the start
of the condition message, so truncation cannot hide a change), never with
raw API errors or credentials; `debug_session.cleanup_recovered` is the final
event. Failed cleanup is retried with bounded exponential backoff: the delay
equals the time since `CleanupFailed` became `True`, clamped between 5 seconds
and 5 minutes, so it survives controller restarts and resets on recovery.
Status writes and other watch events do not bypass this delay. A missing
`ClusterConfig`, REST configuration, or target client is a retryable outage,
not proof that cleanup completed. A `NotFound` response is treated as
successful cleanup. The delete request is UID-preconditioned and followed by a
read to verify that the tracked UID is gone. If finalizers keep that UID present,
or verification fails, the inventory is retained and cleanup is retried. A
different UID at the same name is left untouched and retires the old inventory.

A copied session annotation on a live resource does not recover a missing original
UID. Legacy inventory without an immutable UID requires the explicit operator
recovery mechanism; mutable ownership markers alone never authorize deletion.

If kubectl-debug cleanup encounters a missing ClusterConfig, it retains all
resource inventories and operation evidence and returns a retryable error.

Concurrent cleanup retries preserve the live `CleanupFailed` condition's
transition metadata when residual inventory wins a recovery race; recovery
metadata advances only when the condition actually changes.

If cleanup succeeds but persisting its status fails, the controller returns the
status error for retry without emitting a cleanup-failure audit event. That
event is reserved for an operation that could not be completed or verified.

When no spoke resources remain, cleanup removes the session's completed pod
authorization references. References added concurrently after cleanup started
are retained by the baseline-aware status merge.

Cleanup preserves UID-less create-operation intents even when `Created` was already
recorded. Such intents never authorize a name-only lookup or deletion. A later
persisted UID outcome replaces only the same operation and full resource identity;
conflicting UIDs remain separate inventory. Legacy child resources without an
operation ID still require the explicit original-UID recovery annotation.

Residual identities include API version and kind. Injected ephemeral-container
history is retained for audit but does not by itself indicate failed cleanup;
copied Pods and unresolved operations still require cleanup or recovery. Recovery
events use the condition observed by the successful status write. API lifecycle
events also honor the template's `audit.enabled` setting.

Cleanup retention checks share the same policy across session reconciliation and
ClusterConfig deletion. Partial auxiliary identities and UID-less children remain
outstanding; only confirmed retained identities and confirmed deleted pod-template
entries are exempt. Rejected sessions retain terminal accounting behavior.

Legacy deployed references without a source still honor auxiliary retention when
the full API version, kind, namespace, name, and UID match. Coordinate matches
alone select conservative policy review; mismatched UIDs remain durable residuals
and cannot be retired using another object's deleted status.

Without a cluster provider, terminal sessions can still durably clear AllowedPods-only
authorization bookkeeping. Concurrently added entries survive the merge and retry;
spoke identities and unresolved create intents remain protected.

Cleanup evidence deduplicates the normalized, length-limited identities actually reported. Once the 16-entry report is full, further inventory entries do not grow the evidence identity set. Durable resource inventory remains unchanged.

## Kinds the target cluster does not serve

A template can render an auxiliary resource whose API the target cluster does
not serve, for example a Kyverno `PolicyException` on a management cluster
without Kyverno. The controller handles this as follows:

- **Activation preflight.** Before the first target write (including target
  namespace creation), every enabled auxiliary resource with
  `failurePolicy: Fail` is rendered and its exact API version is resolved on
  the target with a `List` limited to one item. Only the error class matters:
  the RESTMapper raises `NoMatch` before any request is sent, so the limit
  never affects the decision, and other errors (for example `Forbidden`) do
  not fail the preflight. If the kind is not served, the session fails at once
  with a message such as `auxiliary resource "policy-exception" requires
  policies.kyverno.io/v1 PolicyException, which target cluster "mgmt" does not
  serve; install the API on the target or remove the resource from the
  template`. Nothing is applied. Optional (`Ignore`/`Warn`) resources are not
  preflighted.
- **Create.** A client-side `NoMatch` is a definitive rejection, like an API
  `Invalid` or `Forbidden` response: the request never left the client, so the
  persisted create intent is retired and no residual remains.
- **Cleanup.** Cleanup never infers deletion from discovery. A `NoMatch` proves
  nothing about stored objects: deregistering an APIService hides its kinds
  while the extension server keeps the objects, and an unresolved create
  intent may be a committed create whose response was lost. Such entries stay
  `CleanupFailed` residuals, retried with backoff and audited once per
  distinct residual set.

### Retiring residuals the controller cannot prove gone

Uninstalling a CRD deletes its objects, but cleanup then gets `NoMatch`
forever. When an operator has verified that residual resources are gone, they
create a `DebugSessionCleanupAcknowledgement` in the session's namespace that
lists the exact identities, copied from the session status:

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionCleanupAcknowledgement
metadata:
  name: <session>-ack-1
  namespace: <session namespace>
spec:
  sessionName: <session>
  sessionUID: <session metadata.uid>
  acknowledgedBy: <your username, see kubectl auth whoami>
  reason: "CHG-1234: Kyverno CRDs removed"
  identities:
  - apiVersion: policies.kyverno.io/v1
    kind: PolicyException
    namespace: breakglass-debug
    name: <name>
    uid: <uid>   # omit only for an unresolved create intent
```

**Authorization (four-eyes).** Creating the object requires RBAC `create` on
`debugsessioncleanupacknowledgements`, which the API server enforces itself.
Writing a DebugSession grants nothing. The ClusterRole
`breakglass-debugsession-cleanup-acknowledger` grants it and is **bound to
nobody by default**. It is defined as `debugsession-cleanup-acknowledger` in
`config/rbac/debugsession_cleanup_acknowledger_role.yaml`; the `breakglass-`
part is the kustomize `namePrefix` of `config/base`. A binding to the
unprefixed name grants nothing. If you deploy with your own overlay and
prefix, find the rendered name with
`kubectl get clusterrole -o name | grep cleanup-acknowledger`. (The Helm
charts in `charts/` render only configuration objects, not the controller or
its RBAC, so there is no Helm-rendered variant of this role.) Bind it only to
operators who are independent of the sessions they acknowledge:

```yaml
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: debugsession-cleanup-acknowledgers
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: breakglass-debugsession-cleanup-acknowledger
subjects:
- apiGroup: rbac.authorization.k8s.io
  kind: Group
  name: platform-cleanup-reviewers   # operators independent of the sessions
```

To allow acknowledgements in one namespace only, reference the same
ClusterRole from a RoleBinding in the session's namespace instead.

- The object is immutable: the CRD rejects any change to `spec`.
- It is bound to one session instance by `sessionUID`.
- `acknowledgedBy` must equal the creating user, so the audit actor cannot be
  forged. The validating webhook
  `debugsessioncleanupacknowledgement.validation.breakglass.t-caas.telekom.com`
  enforces this, and the controller refuses acknowledgements while that
  webhook is inactive.
- On Kubernetes 1.30 or newer, also deploy the optional kustomize component
  `config/components/cleanup-acknowledgement-policy`. Its
  ValidatingAdmissionPolicy enforces the same rule in the API server itself,
  even before the controller and its webhook are deployed (for example during
  an upgrade). The component is not part of `config/crd` or `config/base`, so
  hubs from Kubernetes 1.24 keep working.
- **Four-eyes.** An acknowledgement whose `acknowledgedBy` is the session's
  requester, approver or a participant is rejected, recorded and audited.
  Usernames are also compared without any `prefix:` part, because the hub API
  server may prefix usernames (for example `oidc:alice@example.com`) while
  session identities are stored unprefixed or with a spoke prefix. Group
  membership is not compared: four-eyes concerns the acting person.
  The requester and participants are compared by username, email and
  Kubernetes user. The approver is compared by `approvedBy` and every entry
  of `status.approval.approvedByIdentities` (username, email and, when it
  resolved, the target-cluster Kubernetes user), which the hub records at
  approval. A session approved before that field existed cannot be fully
  compared, so its acknowledgements are rejected (fail closed) unless the
  controller runs with `--allow-legacy-approver-cleanup-acknowledgement`,
  which compares `approvedBy` alone.

**Requirements.**

- **Validating webhook.** The controller processes acknowledgements only while
  that webhook is registered for CREATE with `failurePolicy: Fail` and no
  namespace selector, object selector or match conditions. Otherwise (for
  example with `--enable-webhooks=false` or `ENABLE_VALIDATING_WEBHOOKS=false`)
  `acknowledgedBy` is unverified, so every acknowledgement is rejected,
  recorded and audited with this reason.
  The controller also requires the API server to have created the
  acknowledgement after that webhook configuration was last created or
  changed (its `creationTimestamp` and `managedFields` times) plus a 30-second
  propagation margin. An acknowledgement created earlier, for example before
  the webhook was installed or while it was reconfigured, has an unverified
  `acknowledgedBy` and is rejected; create it again.
- **CRD before controller.** Apply the current CRDs (including
  `debugsessioncleanupacknowledgements` and the DebugSession status field
  `cleanupAcknowledgements`) before the controller. Without the
  acknowledgement CRD the controller still starts and cleans up as before,
  but acknowledgements are unavailable until the CRD is applied and the
  controller restarts. An older DebugSession CRD
  prunes the status field; the controller then logs an error once. The
  retirement itself still persists and is audited, but the session keeps no
  provenance record and no `CleanupAcknowledged` reason.
- **Status trust.** Like every other status field, the records can be forged
  or suppressed by anyone who may write `debugsessions/status` or
  `debugsessioncleanupacknowledgements/status`. Grant these subresources only
  to the controller.

**How the controller processes it.** Each acknowledgement is processed once,
oldest first, before any mode-specific cleanup. As a result, node-maintenance
and hotfix residuals are retired before their Leases are released. A new
acknowledgement triggers a reconcile of its session at once.

- A controller replica first claims the acknowledgement (`status.phase:
  Processing`). A claim older than 2 minutes, or dated more than 30 seconds
  in the future, is taken over by another replica.
- The replica decides against the live session and records the decision
  (`Applied` or `Rejected`, `retired`, `message`, `processedAt`) on the
  acknowledgement **before** it changes the session. A replica whose claim was
  taken over cannot record a decision and changes nothing.
- An `Applied` decision is then completed on the session. Completion is
  idempotent, so a replica that stopped in between finishes it on the next
  reconcile. An acknowledgement with a final phase is never decided again.
  While a claim is in progress, the session is reconciled again when the
  claim expires, and a deleted session keeps its finalizer until then.
- It is applied only while `CleanupFailed=True`, and only if **every** listed
  identity is an outstanding cleanup residual, compared field by field
  (apiVersion, kind, namespace, name and UID). Intentionally retained
  resources (`deleteAfter: false`) are not residuals. Unlisted residuals are
  kept. An acknowledgement may list any subset (at most 256 identities);
  more residuals are retired with further acknowledgements, and cleanup
  completes once every residual is retired.
- Every outcome is audited as `debug_session.cleanup_acknowledged` (severity
  warning) with the acknowledging user as actor. If the controller stops
  between recording the outcome and emitting the event, that event is lost.
- **Rejected:** nothing is retired, the cleanup backoff is unchanged, and the
  reason is in the acknowledgement's `status.message`. Fix the problem and
  create a new acknowledgement.
- **Applied:** matching entries are marked `deleted` (pod-template and deployed
  entries are dropped) with the reason in their `error` field. The DebugSession
  also records the acknowledgement in `status.cleanupAcknowledgements` (at most
  64 per session). An Applied decision whose record no longer fits is still
  carried out, with its provenance kept on the acknowledgement object, so the
  record limit can never block cleanup. An
  Applied acknowledgement is only ever applied to the session instance named
  by its `sessionUID`.
- After completing an Applied decision on the session, the replica marks the
  acknowledgement completed (`status.completedAt`) with a guarded write. Only
  the replica that wins this write audits the Applied outcome, so it is
  audited at most once, also when cleanup had already removed the residuals
  or a completion was retried. If that replica stops right after the write and
  before it emits the event, the event is lost (the outcome stays recorded on
  the acknowledgement). A completed acknowledgement is never processed
  again, and the residuals it retired stay retired even when no session
  record could be kept. An Applied acknowledgement carries the finalizer
  `breakglass.t-caas.telekom.com/cleanup-acknowledgement-retention`, which
  the controller removes once its session instance is gone (confirmed with an
  uncached read, so a lagging cache or a recreated session of the same name
  cannot release it), so deleting the acknowledgement cannot drop that
  evidence. If the DebugSession CRD is no longer served (for example during
  an uninstall), no session can exist and the controller releases the
  finalizer; a transient discovery failure does not release it. Rejected
  acknowledgements carry no finalizer. The replica that records a rejection audits it.
  - If no residual remains, the condition becomes `CleanupFailed=False` with
    reason `CleanupAcknowledged`, followed by `debug_session.cleanup_recovered`.
  - If residuals remain, the new residual set is reported once with
    `debug_session.cleanup_failed`.
- If node-maintenance or hotfix cleanup fails while the session is being
  deleted, the failure is recorded as `CleanupFailed`, so it is visible and
  can be acknowledged.

### Transitional opt-outs

These behaviours are on by default. Each can be turned off with a flag on the
controller. The flags are escape hatches and may be removed in a later
release:

| Flag | Environment | Restores |
|------|-------------|----------|
| `--disable-debug-session-unserved-kind-handling` | `BREAKGLASS_DISABLE_DEBUG_SESSION_UNSERVED_KIND_HANDLING` | No activation preflight; the session fails at the first create instead. |
| `--disable-debug-session-cleanup-backoff` | `BREAKGLASS_DISABLE_DEBUG_SESSION_CLEANUP_BACKOFF` | Fixed 5-second cleanup retries and one `debug_session.cleanup_failed` event per failed attempt. |
| `--allow-legacy-approver-cleanup-acknowledgement` | `BREAKGLASS_ALLOW_LEGACY_APPROVER_CLEANUP_ACKNOWLEDGEMENT` | Acknowledgements for sessions approved before `approvedByIdentities` was recorded compare the approver by `approvedBy` alone instead of being rejected. |

The `NoMatch` create classification is not gated: it only records that a
request which never left the client created nothing.
