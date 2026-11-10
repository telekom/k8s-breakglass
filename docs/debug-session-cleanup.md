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
without Kyverno. Such an object cannot exist: the client rejects the request
with a RESTMapper `NoMatch` before it reaches the API server, and removing a
CRD deletes its objects. The controller therefore handles it as follows:

- **Activation preflight.** Before the first target write (including target
  namespace creation), every enabled auxiliary resource with
  `failurePolicy: Fail` is rendered and its exact API version is resolved on
  the target with a `List` limited to one item. Only the error class matters:
  the RESTMapper raises `NoMatch` before any request is sent, so the limit
  never affects the decision, and other errors (for example `Forbidden`) do
  not fail the preflight. If one is not served, the session fails at once with a message
  such as `auxiliary resource "policy-exception" requires
  policies.kyverno.io/v1 PolicyException, which target cluster "mgmt" does not
  serve; install the API on the target or remove the resource from the
  template`. Nothing is applied. Optional (`Ignore`/`Warn`) resources are not
  preflighted; their create fails definitively and follows their policy.
- **Create.** A client-side `NoMatch` counts as a definitive rejection, like
  an API `Invalid` or `Forbidden` response, so the persisted create intent is
  retired instead of being left unresolved.
- **Cleanup.** When reading, deleting, or resolving an unresolved create intent
  for an auxiliary, pod-template, or deployed resource fails with `NoMatch` (or
  a discovery error in which every group-version is `NotFound`), the controller
  also checks that **no** version of that group/kind is served. If none is, the
  entry is treated as already deleted: it is logged once at info level, marked
  `deleted` and its `error` field records `target cluster does not serve
  <apiVersion> <kind>; nothing can exist to delete`. The
  `breakglass_auxiliary_resource_cleanups_total` counter uses
  `status="not_served"` for these entries (the `category` label is the
  auxiliary category, `pod-template`, or the deployed resource source). Pod-template and
  deployed-resource entries are removed from the inventory like a confirmed
  deletion. Absence is confirmed against the target's legacy discovery
  documents as well, because aggregated discovery hides an unavailable
  APIService; any discovery error keeps the entry retryable. Without that
  confirmation the controller fails closed. Workload, node-maintenance and
  hotfix cleanup all perform it. A kind that is still served at
  another version, or a transient discovery failure, stays a retryable
  residual.

### Transitional opt-outs

Both behaviours are on by default. Each can be turned off with a flag on the
controller. The flags are escape hatches and may be removed in a later
release:

| Flag | Environment | Restores |
|------|-------------|----------|
| `--disable-debug-session-unserved-kind-handling` | `BREAKGLASS_DISABLE_DEBUG_SESSION_UNSERVED_KIND_HANDLING` | No activation preflight; cleanup retries entries of unserved kinds indefinitely. |
| `--disable-debug-session-cleanup-backoff` | `BREAKGLASS_DISABLE_DEBUG_SESSION_CLEANUP_BACKOFF` | Fixed 5-second cleanup retries and one `debug_session.cleanup_failed` event per failed attempt. |

The `NoMatch` create classification is not gated: it only records that a
request which never left the client created nothing.
