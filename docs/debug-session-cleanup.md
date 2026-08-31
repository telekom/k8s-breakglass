<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: Apache-2.0
-->

# DebugSession cleanup recovery

DebugSession status keeps a `deployedResources` inventory containing the API
version, kind, namespace, name, and (when available) UID of every resource
created on the spoke cluster. Terminal-session cleanup deletes from this
inventory using idempotent, generic Kubernetes deletes, so auxiliary resources,
PVCs, NetworkPolicies, RBAC objects, and new resource kinds are handled in the
same recovery path.

The UID is captured immediately after each successful create/apply and is used
as a delete precondition. This prevents a later object with the same name from
being removed. The copied-pod and node-debug paths use the same inventory.

If a spoke API call fails, the controller retains the residual identities and
sets the `CleanupFailed=True` status condition. The terminal session is
requeued periodically and retries the same inventory after a controller
restart. A missing `ClusterConfig`, REST configuration, or target client is a
retryable outage, not proof that cleanup completed. A `NotFound` response is
treated as successful cleanup. Resources with finalizers remain tracked until
the API confirms deletion.
