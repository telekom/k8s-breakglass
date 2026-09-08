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
requeues the terminal session. Cleanup errors are logged and surfaced through
the reconciler error path; there is no `CleanupFailed` condition. A missing
`ClusterConfig`, REST configuration, or target client is a retryable outage,
not proof that cleanup completed. A `NotFound` response is treated as
successful cleanup. The delete request is UID-preconditioned, but once the API
accepts it the inventory entry is retired; Kubernetes finalizers may therefore
keep the object terminating after the controller's delete request succeeds.
