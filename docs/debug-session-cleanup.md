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
`CleanupRecovered` only after a later attempt has observed the inventory gone;
the failure event is emitted once per failed attempt without exposing raw API
errors or credentials. A missing
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
