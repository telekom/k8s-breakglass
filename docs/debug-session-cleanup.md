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

If a spoke API call fails, the controller retains the residual identities and
sets the `CleanupFailed=True` status condition. The terminal session is
requeued periodically and retries the same inventory after a controller
restart. A `NotFound` response is treated as successful cleanup. UID
preconditions prevent a stale name from deleting a replacement resource.
