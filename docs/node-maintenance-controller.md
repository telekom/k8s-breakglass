<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: CC-BY-4.0
-->

# Typed node-maintenance sessions

`DebugSessionTemplate.spec.nodeMaintenance` opts a profile into the controller's
fixed executor. It is absent by default. Only `neighbor-replace`,
`bridge-fdb-replace`, `link-cycle`, `restart-autonegotiation`,
`kexec-recovery`, `service-restart` of an allowlisted systemd unit,
`module-load` of an allowlisted kernel module and `sriov-reprovision` of an
allowlisted SR-IOV physical function are supported. `neighbor-replace`,
`bridge-fdb-replace` and `kexec-recovery` can run as a preview; the link actions,
`service-restart`, `module-load` and `sriov-reprovision` cannot (`dryRun` is rejected). This does **not** enable broad flushes,
a caller-selected kernel, unit or module, arbitrary host commands or traffic mirroring.

`link-cycle` (down, then up) and `restart-autonegotiation` act on one exact
Node and interface; `entryMAC`, neighbour, bridge, VLAN and VRF must be empty
in the request and in every allowlist entry. The helper pins the interface by
ifindex and refuses it when a default route of any routing table, including a
multipath nexthop, uses the interface or a device stacked on it (bond, VLAN,
bridge, VRF), because dropping that carrier cuts the node off. The routes are
captured in the evidence bundle (`before-default-routes-ipv4.txt`,
`before-default-routes-ipv6.txt`). Known limit: the default-route check and
the autonegotiation reset address the interface by name after the ifindex is
pinned, so a root actor that renames interfaces on the node at the same moment
can make them see another device; the autonegotiation post-check reports the
rename.

## Operator prerequisites

- Provision the target-cluster namespace `breakglass-node-maintenance`. All
  profiles share this one Lease/workload namespace; requester namespaces cannot
  create separate lock domains. Its admission policy must allow the fixed
  NET_ADMIN-only host-network Pod without mutating or widening its contract.
- Give the controller's existing privileged ClusterConfig identity permission
  to read Nodes/namespaces and create/read/delete Jobs, Pods and coordination Leases,
  and update Job status,
  in that namespace. For `kexec-recovery` it additionally needs to get and
  patch Nodes, list Pods in all namespaces and create `pods/eviction`.
  Requesters must not have Pod, Lease or session-status write
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
variables, overrides, scheduling choices, impersonation, auxiliary resource
defaults or requester selections, artifact recipes or interactive sharing. The executor constructs a fixed Job
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

For a neighbour in a VRF, add `vrf` with the exact VRF device that is the
master of `interface`; the helper rejects any other master and resolves the
neighbour route inside that VRF. `vrf` is valid only for `neighbor-replace`.

For `bridge-fdb-replace`, use `bridge`, `interface` (the exact bridge port),
`entryMAC`, and integer `vlan` (1–4094); omit `neighborAddress`. Neighbour requests
must omit `bridge` and `vlan`. MACs/IPs must be canonical and MACs nonzero unicast;
IPv4-mapped IPv6 neighbour addresses, CIDRs, wildcards,
alternate interfaces/UIDs and unknown free-text fields are rejected. Every
request field must equal an entry in the template's allowlist. Action/image are
template-owned, never requester inputs.

### Preview profiles

`nodeMaintenance.dryRun: true` turns a template into a preview of the same
exact tuple. The helper runs every validation and preflight capture, records
`dry_run=true`, `action_performed=false` and a `previewed` event, and never
calls the mutating action. The preview Pod drops all capabilities and adds
none. The canonical tuple carries `&dry_run=true` (and `&vrf=` when set), so a
preview approval cannot execute a mutation and an execution approval cannot be
replayed as a preview. Because the flag is template-owned, operators publish a
preview template and a separately approved execution template for the same
allowlist; requesters cannot toggle it.

### Per-session admission exceptions

A maintenance template may declare `auxiliaryResources` that must exist before
the executor, for example a per-session Kyverno `PolicyException` that admits
only this session's Job and Pod. Every resource must set `createBefore: true`,
must not be optional or `deleteAfter: false`, must use `failurePolicy: fail`
(or omit it), and must name a category listed in
`requiredAuxiliaryResourceCategories`; every required category must contain at
least one resource. `auxiliaryResourceDefaults`, requester
`selectedAuxiliaryResources` and binding overrides remain rejected. The
resource kind is not restricted, so RBAC on `DebugSessionTemplate` decides who
may add resources that a maintenance session creates.

The controller renders and creates these resources on the target cluster after
acquiring the node Lease and before the Job. Templates can bind such a
resource to the approved Node with `.target.nodeName` and `.target.nodeUID`.
Kyverno loads new exceptions asynchronously, so while a
`PolicyException` created by the session is younger than the admission window
of workload sessions, an admission-webhook denial of the Job or Pod rolls back
its create marker (a denied create committed nothing) and requeues the session
after one second instead of failing it. A denial after the window fails the
session. Cleanup deletes them after the Pod and Job are
proven absent and before the Lease is released.

### Kexec recovery profiles

`action: kexec-recovery` reboots one drained worker Node into a provider-owned
recovery kernel. The allowlist entries carry only `targetNode` and
`targetNodeUID`; interface and tuple fields are rejected. The profile pins the
bundle:

```yaml
  constraints:
    maxDuration: 30m   # at least drainTimeoutSeconds + 300s
  nodeMaintenance:
    action: kexec-recovery
    image: YOUR_VERIFIED_NODE_MAINTENANCE_IMAGE_BY_DIGEST
    kexec:
      profile: provider-recovery
      hostPath: /var/lib/provider/recovery   # holds kernel, initrd, cmdline
      kernelSHA256: <64 hex>
      initrdSHA256: <64 hex>
      cmdlineSHA256: <64 hex>
      drainTimeoutSeconds: 600
    allowedTargets:
      - targetNode: exact-node-name
        targetNodeUID: exact-live-node-uid
```

With `dryRun: true` the profile only runs `kexec-recovery-validate`: no
capabilities, RuntimeDefault seccomp, no host PID, no cordon and no drain.
Publish it as a separately approved validation template.

For execution the controller rejects Nodes labelled
`node-role.kubernetes.io/control-plane` or `node-role.kubernetes.io/master`,
then, after acquiring the node Lease and before any auxiliary resource or
executor exists:

1. records the Node boot ID and `cordonedAt` in the session status;
2. cordons the Node and marks the cordon with the
   `breakglass.t-caas.telekom.com/maintenance-cordon` annotation set to the
   operation ID (a Node that is already cordoned keeps its foreign cordon);
3. evicts every Pod on the Node like `kubectl drain --ignore-daemonsets
   --delete-emptydir-data --force`: DaemonSet, mirror, terminated and
   `breakglass-node-maintenance` Pods stay, PodDisruptionBudgets are honoured
   through the Eviction API with the observed Pod UID as a precondition (a
   same-name replacement on another Node is never evicted), and the session
   waits with the message "Draining Node before kexec-recovery";
4. fails the session without an executor once `drainTimeoutSeconds` has
   passed, even if the last Pod left after the deadline, or when the boot ID
   changes during the drain.

The executor Pod adds only `SYS_BOOT`, uses the host PID namespace and an
unconfined seccomp profile (both required by the kernel interfaces), never the
host network, and mounts `hostPath` read-only at `/recovery`. Its memory limit
is 1Gi because it loads sealed in-memory copies of the verified files. It tolerates the
cordon and NotReady/unreachable taints so the receipt survives the reboot. Its
admission exception, if any, belongs in the per-session auxiliary resources.

A successful kexec kills the executor, so the result is decided by the Node,
not by the Pod phase. On a Ready Node a terminated executor whose termination
message reports `kexec_loaded=0` and the approved `boot_id` is `failed`, even
if the Node rebooted later for another reason. Otherwise a new boot ID is
`succeeded`; it proves a reboot, not which kernel booted. A kill, eviction or
Pod deadline can stop the executor between loading and rebooting, so a
terminated executor without that proof is not `failed`. Anything else is `interrupted` at expiry or `unknown`
at cleanup. Cleanup uncordons the Node only
when this operation owns the cordon and the outcome is `succeeded` or `failed`,
or when no executor was created. An unproven reboot leaves the Node cordoned
with its annotation for an operator; remove it with `kubectl uncordon` and
`kubectl annotate node NODE breakglass.t-caas.telekom.com/maintenance-cordon-`
after checking the console and, if `/sys/kernel/kexec_loaded` is `1`, unloading
the image with `kexec -u` or rebooting. Audit events also carry `bootID`.

Cleanup deletes the executor Pod and waits until it is gone before it releases
the node Lease, the session finalizer and the cordon. If the recovery kernel
does not start kubelet, the Pod stays `Terminating` and cleanup waits. After
the console shows that the executor no longer runs (the Node runs the recovery
kernel or is powered off), remove the Pod with
`kubectl -n breakglass-node-maintenance delete pod OPERATION_ID --force --grace-period=0`.

### Service restart profiles

`action: service-restart` restarts one allowlisted host systemd unit
(`containerd.service`, `kubelet.service` or `cra.service`) on one drained
worker Node. The allowlist entries carry `targetNode`, `targetNodeUID` and
`unit`; interface and tuple fields are rejected, and there is no preview.

```yaml
  constraints:
    maxDuration: 20m   # at least drainTimeoutSeconds + 600s
  nodeMaintenance:
    action: service-restart
    image: YOUR_VERIFIED_NODE_MAINTENANCE_IMAGE_BY_DIGEST
    service:
      drainTimeoutSeconds: 600
      restartPods:            # optional, at most four selectors
        - namespace: kube-system
          matchLabels:
            app.kubernetes.io/name: network-operator-agent-cra-vsr
    allowedTargets:
      - targetNode: exact-node-name
        targetNodeUID: exact-live-node-uid
        unit: cra.service
```

Before the drain the controller requires every `restartPods` selector to match
at least one Pod on the Node (select DaemonSet Pods: the drain evicts other
Pods); otherwise it fails without executing. It rejects control-plane Nodes and
drains like a kexec execution (steps 2 to 4 above, without the boot ID). The
executor Pod has no capabilities, RuntimeDefault seccomp, a read-only root
filesystem and no host PID, and uses the host network only to read host links.
It mounts systemd's private socket `/run/systemd/private` from a `Socket`
hostPath. `readOnly` does not restrict a socket: the fence is the fixed
entrypoint and the `service-action` helper, which can only probe a unit
(`LoadUnit` and property reads, after a `Peer.Ping`) and call
`RestartUnit(<unit>, "replace")` for an allowlisted unit; the image has no
`systemctl` or general D-Bus client. The executor is a Pod, so the kubelet and
containerd must still start Pods on the Node: use the action for a degraded but
responsive unit. A Node without that socket, or one that cannot start the Pod,
leaves the executor Pending until the deadline (`interrupted`). The executor
tolerates the `not-ready` and `unreachable` NoExecute taints, so a restart that
briefly makes the Node NotReady does not evict it. The helper waits until the unit
is active again with a new activation time; on a CRA node (where `cra.service`
is loaded) a `containerd.service` or `cra.service` restart also waits for
`cra.service`, the host `hbn` and `netconf` links and, when present, a global
address on `oam0`. `cra.service` declares `Requires=containerd.service`, so a
containerd restart on a CRA node always restarts the router container and
briefly removes the node network.

After the helper succeeded the controller requires the Node to be Ready,
deletes each Pod that matches `restartPods` on that Node exactly once (UID
precondition), and waits until every selector has a new Ready Pod on the Node.
Use this for agents that must re-apply configuration to the restarted service,
for example a network agent that only pushes its configuration when its own
revision changes. Only then is the result `succeeded` and cleanup uncordons the
Node. A failed helper, or a Node or replacement Pod that is not Ready before
the deadline, is `failed` with the advisory "recommend replacing it"; the Node
stays cordoned. A succeeded helper whose post-checks never ran (cancellation)
is `unknown` and also stays cordoned. An executor that proves it changed
nothing (it refused in preflight before the restart request, reported as the
termination message `action_issued=0`, or the kubelet reported its container
as never started) sets `status.nodeMaintenance.hostUnchanged`, and cleanup
uncordons the Node. An executor Pod without any container status, or one that
ran, keeps the cordon. The helper checks the session deadline again right
before the restart request, so a container that starts after the deadline
restarts nothing. Nothing
on the Node is persisted.

The controller's ClusterConfig identity additionally needs `delete` on Pods in
the `restartPods` namespaces (the drain already needs Pod `list`, eviction and
Node `patch`). Admission
policies that forbid hostPath volumes need a per-session exception for the
executor Pod in the template's auxiliary resources.

### Module load profiles

`action: module-load` loads one kernel module of the running kernel, with the
dependencies and soft dependencies the host module tree lists, until the next
reboot. Each allowlist entry
carries `targetNode`, `targetNodeUID` and `module` (an exact name matching
`^[a-z0-9_]{1,56}$`, no parameters); there is no preview and no drain.

```yaml
  nodeMaintenance:
    action: module-load
    image: YOUR_VERIFIED_NODE_MAINTENANCE_IMAGE_BY_DIGEST
    allowedTargets:
      - targetNode: exact-node-name
        targetNodeUID: exact-live-node-uid
        module: ip6_gre
```

The executor Pod adds only `SYS_MODULE`, uses RuntimeDefault seccomp, a
read-only root filesystem, neither the host network nor the host PID
namespace, and mounts the host `/lib/modules` read-only from a `Directory`
hostPath (admission policies that forbid hostPath volumes need the same
per-session exception as the other host executors). The helper runs modprobe
with an empty configuration directory (`-C`), so no image `modprobe.d` alias,
option, softdep or install line applies; the name must resolve to itself
(`--resolve-alias`), and `--ignore-install` is set. It succeeds only when
`/sys/module/<module>` exists afterwards; an already loaded or built-in module
is recorded unchanged. Persist a needed module through node configuration; a replacement
node otherwise misses it again.

The empty configuration also discards the host's own `modprobe.d`: the module
loads with its compiled-in defaults, not with the node's `options` or `softdep`
lines (kernel command-line `module.param=` values still apply). Do not
allowlist a module whose defaults create devices or change tunables (for
example `bonding` or `dummy` create a device, `nf_conntrack` sizes its table)
without checking the node's `modprobe.d`. Every loaded module adds host attack
surface that unprivileged processes can reach, so allowlist only modules the
node configuration needs. The executor is sized for small modules (10 s
modprobe timeout, 128Mi memory). The host must have `/lib/modules` (a symlink
to a directory is fine); otherwise the executor Pod never starts and the
session ends `interrupted`. The executor does not tolerate the `not-ready` or
`unreachable` NoExecute taints, so it does not run on a Node that is already
NotReady.

### SR-IOV re-provision profiles

`action: sriov-reprovision` re-creates the SR-IOV virtual functions (VFs) of one
physical function (PF) from the node's own netplan configuration, for a node
whose VFs were not created at boot. Each allowlist entry carries `targetNode`,
`targetNodeUID`, `interface` (the PF) and `virtualFunctions` (the exact VF
count, 1 through 256, that netplan creates for that PF). The profile needs the
same `service` bounds as `service-restart`; there is no preview.

```yaml
  nodeMaintenance:
    action: sriov-reprovision
    image: YOUR_VERIFIED_NODE_MAINTENANCE_IMAGE_BY_DIGEST
    allowedTargets:
      - targetNode: exact-node-name
        targetNodeUID: exact-live-node-uid
        interface: ens1f0
        virtualFunctions: 8
    service:
      drainTimeoutSeconds: 300
      restartPods:
        - namespace: kube-system
          matchLabels:
            app: sriov-device-plugin
```

The controller cordons and drains the worker Node as for `service-restart`
(control-plane Nodes are refused). The executor Pod is the `service-restart`
Pod: no capabilities, RuntimeDefault seccomp, a read-only root filesystem, the
host network (to read the PF in sysfs) and only `/run/systemd/private` as a
read-only `Socket` hostPath. The helper asks systemd to run two fixed commands
as transient oneshot units on the host: `netplan apply --sriov-only`, which must
exit 0, and, only for VFs that are still unbound 10 seconds later,
`netplan rebind <PF>`. Each runs at most 120 seconds (the helper stops a unit
that runs longer, and systemd stops it 5 seconds later by itself if the helper
is gone; a leftover unit of an interrupted run is stopped and reported before
the next run). `netplan rebind` only binds VFs that share the PF driver
(mlx5) or use `delay-virtual-functions-rebind`; VFs with their own driver
(igbvf, ixgbevf, iavf) bind by autoprobe. A failed rebind is recorded in the
evidence; the decision is the exact VF state: the helper waits up to 120
seconds until `sriov_numvfs` of the PF equals `virtualFunctions` and every VF
exists and is bound to a driver. As for `service-restart`, `maxDuration` must cover
`drainTimeoutSeconds` plus 600 seconds. The controller recreates the
`restartPods` (typically the SR-IOV device plugin) once and requires a Ready
Node and Ready replacements before it reports success and uncordons. Anything
else keeps the Node cordoned with the advisory to replace it.

`netplan apply --sriov-only` applies the SR-IOV settings of every PF in the
node's netplan configuration and changes no other network setting; `netplan
rebind` acts on the allowlisted PF only. A PF whose current VF count differs
from netplan (for example one managed by an SR-IOV operator) is reset to the
netplan count, which removes and re-creates its VFs; check the other PFs of the
node before you approve. Enabling SR-IOV resets the PF on many NICs (ixgbe,
i40e, ice), so a PF that also carries the node address loses its link for a
few seconds. Nothing is persisted: the next boot creates the VFs from netplan
again. An executor that refuses in preflight (no SR-IOV PF, too few VFs)
changed nothing, and the controller uncordons the Node.

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

The single network-repair Pod has (see above for the kexec, service-restart, module-load and sriov-reprovision Pods):

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
  -run '^Test(NodeMaintenance|Kexec)' -count=1
```

`bash hack/node-maintenance-controller-kind.sh` creates an owned disposable Kind
cluster and local registry, builds the real helper and uses its manifest digest.
It exercises the controller and existing approval HTTP flow against the real
API server: unapproved/self-approved/mismatched-UID denial, Lease contention,
exact neighbour/FDB mutation with decoy preservation, audit outcome and cleanup.
The neighbour lane also runs a capability-free preview that must leave the
stale entry unchanged and an exact VRF neighbour replacement with a decoy.
Cancellation uses the actual terminate HTTP handler; expiry exercises the
controller's terminal reconciliation and verifies Job/Pod/Lease removal.
Expiry uses an original 60-second requested duration so slow CI API round trips
can finish activation before the unchanged deadline; cleanup waits are bounded.
The kexec lane (`NODE_MAINTENANCE_KIND_ACTION=kexec`) stages a disposable
recovery bundle on the Kind node: validation must succeed without capabilities,
cordon or reboot, a wrong kernel digest must fail closed, and an execution
request for the control-plane Node must be refused before any cordon. A real
kexec needs a disposable worker VM and is not part of CI.
CI runs neighbour, FDB and kexec acceptance in independent disposable-cluster
lanes; the default local command runs neighbour and FDB.
OIDC middleware and audit delivery are test fixtures, not a claim of live IdP,
production support or external recording validation. The script uses immutable Docker IDs for its Kind node, registry (including
anonymous volumes) and image cleanup; it never deletes a replacement by name.
Failed creates without provable ownership are left to runner recovery, not
removed by a guessed name.
Only the five API types exercised by this proof are installed; the independent
full CRD/schema and manifest CI gates still validate all generated contracts.
