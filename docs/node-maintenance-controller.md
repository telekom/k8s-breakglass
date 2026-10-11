<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: CC-BY-4.0
-->

# Typed node-maintenance sessions

`DebugSessionTemplate.spec.nodeMaintenance` opts a profile into the controller's
fixed executor. It is absent by default. Only `neighbor-replace` and
`bridge-fdb-replace` are supported; this does **not** enable broad flushes, link
cycling, kexec, arbitrary host commands, traffic mirroring or CRA.

## Operator prerequisites

- Provision the target-cluster namespace `breakglass-node-maintenance`. All
  profiles share this one Lease/workload namespace; requester namespaces cannot
  create separate lock domains. Its admission policy must allow the fixed
  NET_ADMIN-only host-network Pod without mutating or widening its contract.
- Give the controller's existing privileged ClusterConfig identity permission
  to read Nodes/namespaces and create/read/delete Jobs, Pods and coordination Leases,
  and update Job status,
  in that namespace. Requesters must not have Pod, Lease or session-status write
  access. Do not impersonate a requester for this executor.
- Requests must use the authenticated HTTP API. Directly created CRs without its
  durable authenticated-requester provenance cannot reach maintenance approval
  or execution; an unverified `spec.requestedBy` is not a four-eyes identity.
- Supply a verified, signed node-maintenance image **by manifest digest**,
  including the controller deadline guard. A mutable tag is rejected. No image
  is published or operationally certified by enabling this API.
- Explicitly allow every node **name and UID**, interface and tuple supported by
  the node class. Node replacement requires a new profile entry and approval.
  Prevent Node replacement/force-deletion and other privileged network writers
  while a maintenance Lease is held. Kubernetes cannot atomically transact a
  Node read with a Pod creation or a kernel operation; final UID fences do not
  provide such an impossible guarantee.
- Set an explicit `constraints.maxDuration`, allowed users/groups/clusters and
  independent approvers. `constraints.idleTimeout` is rejected on maintenance
  templates and their bindings: the executor only honours the hard expiry, and
  no debug activity extends an idle deadline. Bind production only to the approved emergency persona
  and support workflow. The generic controller does not infer production from
  a cluster name or invent organizational approval groups.
- Configure synchronous **durable** audit delivery. Execution fails closed on
  a missing/disabled/filtered/failed sink; an asynchronous queue or Kubernetes
  Event is not an execution receipt.

## Template and typed request

Create a workload-mode template with **no** `workloadType`, Pod template,
variables, overrides, scheduling choices, impersonation, auxiliary resources,
artifact recipes or interactive sharing. The executor constructs a fixed Job
and exactly one UID-owned Pod instead of rendering a caller-controlled workload.
The Job sets `managedBy: breakglass.t-caas.telekom.com/node-maintenance`, requiring
Kubernetes 1.32+ with `JobManagedBy` enabled. The built-in Job controller therefore
does not create/recreate Pods. The Breakglass controller creates one Pod and
observes its terminal result; it never replays a lost mutation. Merely setting
`backoffLimit: 0` on a built-in managed Job would not provide that guarantee.
The Job also remains `suspend: true`: if an unsupported API server prunes
`managedBy`, its built-in controller cannot execute the template before the
Breakglass controller rejects the response. The external manager, not the
built-in Job controller, owns the one Pod and terminal Job status.

The profile fields are:

```yaml
spec:
  mode: workload
  targetNamespace: breakglass-node-maintenance
  constraints:
    maxDuration: 5m
    defaultDuration: 5m
  approvers:
    groups: [YOUR_INDEPENDENT_APPROVER_GROUP]
  nodeMaintenance:
    action: neighbor-replace
    image: YOUR_VERIFIED_NODE_MAINTENANCE_IMAGE_BY_DIGEST
    allowedTargets:
      - targetNode: exact-node-name
        targetNodeUID: exact-live-node-uid
        interface: exact-interface
        neighborAddress: 192.0.2.2
        entryMAC: "02:00:00:00:00:02"
```

These are operator substitution markers, not usable published image/group/Node
claims. Also configure `allowed` and a mandatory `requestReason` for your policy.
Binding-level approvers may replace the template set, but must remain nonempty
and cannot configure `autoApproveFor`. Auto-approval is never permitted.
Maintenance approval uses the captured immutable binding approvers, not a live
binding edit made after the request reached PendingApproval.

`POST /debugSessions` accepts `nodeMaintenance` using the same typed object as
`DebugSession.spec.nodeMaintenance`, alongside the existing template, cluster,
duration and reason fields:

```json
{
  "templateRef": "YOUR_APPROVED_TEMPLATE",
  "cluster": "YOUR_SUPPORTED_CLUSTER",
  "requestedDuration": "5m",
  "reason": "YOUR_REQUIRED_CHANGE_OR_INCIDENT_REFERENCE",
  "nodeMaintenance": {
    "targetNode": "exact-node-name",
    "targetNodeUID": "exact-live-node-uid",
    "interface": "exact-interface",
    "neighborAddress": "192.0.2.2",
    "entryMAC": "02:00:00:00:00:02"
  }
}
```

For `bridge-fdb-replace`, use `bridge`, `interface` (the exact bridge port),
`entryMAC`, and integer `vlan` (1–4094); omit `neighborAddress`. Neighbour requests
must omit `bridge` and `vlan`. MACs/IPs must be canonical and MACs nonzero unicast;
IPv4-mapped IPv6 neighbour addresses, CIDRs, wildcards,
alternate interfaces/UIDs and unknown free-text fields are rejected. Every
request field must equal an entry in the template's allowlist. Action/image are
template-owned, never requester inputs.

## Approval, execution and cleanup

The server validates the request and live Node UID before PendingApproval.
Existing immutable session specs and resolved template/binding snapshots bind
the existing approval flow to that exact operation. The requester cannot
self-approve; empty/auto-approval binding overrides are rejected.

Before any execution, the controller re-reads the live session, independent
approval, ClusterConfig provenance, namespace UID and Node UID. It acquires the
deterministically named per-node Lease with an operation ID derived from the
session UID. API-server atomic Create and UID/resourceVersion-fenced Delete
arbitrate ownership; **Lease age alone never permits takeover**. A contender
remains PendingApproval with an exclusive-Lease wait message and no executor.

The single Pod has:

- exact `nodeName`, `hostNetwork: true`, no host PID/IPC;
- root UID/GID, NET_ADMIN only, all other capabilities dropped;
- read-only root filesystem, RuntimeDefault seccomp, no privilege escalation;
- no token, hostPath, stdin, TTY, sidecars or init containers;
- fixed helper command, controller-built typed argv and canonical tuple env;
- fixed `restartPolicy: Never`, deadline, requests and memory limit (no CPU limit);
- bounded `/evidence` emptyDir, not an arbitrary host or upload path.

The helper checks the absolute controller deadline before preflight and again
before mutation. Operation/approval/recording env IDs correlate the immutable
session decision and audit events; they do not fabricate an external recording
service. `/evidence` is ephemeral and is removed with the Pod. This executor
does not implement durable bundle export/retention; operational environments
requiring it must remain disabled until an approved integration exists.

Job and Pod creation intents are separately persisted before each Create.
A fence or Lease check that fails after an intent is persisted but before the
Create call clears that intent again, so a retry or cleanup is not blocked by
an outcome that is known not to exist. An ambiguous response is recovered
only by exact UID/contract match; a missing unknown-outcome Pod is **never**
recreated, and its Lease remains blocked for supported operator recovery.
The controller-owned Job envelope cannot switch to the built-in Job manager;
its UID, selector and fixed Pod template are checked on reconciliation.
Audit events carry the canonical tuple, node/session/Job/Pod/Lease UIDs, image,
approval actor/time and observed result. `succeeded` means the fixed helper Pod
completed successfully, not certification of a node class or all networking.
Failures/interruption/unknown outcomes are not reported as success.

Required event types are `debug_session.node_maintenance.execution_intent` and
`debug_session.node_maintenance.result`; both are sensitive events and use
synchronous durable delivery. Include them in any configured sink allowlist.
Terminal Job observation revalidates live session/approval, target credentials,
Node and namespace identity; the expiry observation permits the original elapsed
deadline only so expiry can be recorded, never to execute another mutation.
Cleanup rechecks credentials before its result receipt and verifies the Lease's
Node UID annotation even when recovering an unpersisted Lease UID.
It resolves Job/Lease ownership before result delivery. A cancelled contender
with no execution intent receives no executor result receipt and never deletes
the other session's Lease.

Successful execution terminates the session; failed/interrupted execution
fails/expires it. A dedicated finalizer, installed before activation acquires
any hub connection lease, retains cleanup responsibility after session
deletion. Before it is removed it releases the session's hub connection lease,
including a lease whose reference never reached status because the session was
deleted mid-activation. Cleanup deletes only the exact owned Pod and Job, proving
both absent before deleting the exact owned Lease. Namespace/UID ambiguity, pending
termination, audit failure or target outage retain inventory and the lock.
Cancellation records a matching Pod's observed terminal result when available.
Recovery captures an exact matching Pod UID before delivering the cleanup result
receipt, including cancellation of a nonterminal Pod with an unknown outcome.
After unknown/interrupted execution, an unavailable Node is not proof that its
writer stopped: the Lease remains held even after API object deletion. Node
UID replacement likewise requires supported operator recovery, not takeover.
Never force-remove a Pod/finalizer/Lease merely because a timestamp expired.

## Validation

Run the focused unit and snapshot tests:

```sh
go test ./api/v1alpha1 ./api/v1alpha1/applyconfiguration/ssa ./pkg/breakglass/debug \
  -run '^TestNodeMaintenance' -count=1
```

`bash hack/node-maintenance-controller-kind.sh` creates an owned disposable Kind
cluster and local registry, builds the real helper and uses its manifest digest.
It exercises the controller and existing approval HTTP flow against the real
API server: unapproved/self-approved/mismatched-UID denial, Lease contention,
exact neighbour/FDB mutation with decoy preservation, audit outcome and cleanup.
Cancellation uses the actual terminate HTTP handler; expiry exercises the
controller's terminal reconciliation and verifies Job/Pod/Lease removal.
Expiry uses an original 60-second requested duration so slow CI API round trips
can finish activation before the unchanged deadline; cleanup waits are bounded.
CI runs neighbour and FDB acceptance in independent disposable-cluster lanes;
the default local command runs both.
OIDC middleware and audit delivery are test fixtures, not a claim of live IdP,
production support or external recording validation. The script uses immutable Docker IDs for its Kind node, registry (including
anonymous volumes) and image cleanup; it never deletes a replacement by name.
Failed creates without provable ownership are left to runner recovery, not
removed by a guessed name.
Only the five API types exercised by this proof are installed; the independent
full CRD/schema and manifest CI gates still validate all generated contracts.
