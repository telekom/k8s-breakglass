<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# Session-scoped traffic mirroring

Status: implemented (opt-in per template). User documentation:
[Traffic mirroring](../traffic-mirroring.md).

## Problem

Operators sometimes need to see the traffic of one workload or one host
interface while an incident is live: dropped connections on a secondary
Multus or SR-IOV interface, MultiNetworkPolicy behaviour, asymmetric routing.
Today that means a privileged shell on the node and hand-made `tc` or
`tcpdump` state, which is neither approved, audited nor reliably removed.

The feature must:

- mirror only an allowlisted interface of an allowlisted Pod or Node;
- deliver the copy to a capture container that belongs to the session;
- be approved like the other typed executors and audited (started,
  stopped, failed);
- leave no kernel state behind after the session, after a controller
  restart, or after a crashed helper;
- need no CNI-specific CRD.

## Design

### Mechanism

The controller creates one **mirror Pod** per session in the fixed executor
namespace (`breakglass-node-maintenance`) on the source Node:

```
 source network namespace                     mirror Pod network namespace
 (target Pod, or the Node for host mode)
 ┌──────────────────────────────┐             ┌──────────────────────────┐
 │ eth0 / net1 (clsact)         │             │                          │
 │  ingress ─┐  basic match-all │   veth      │  bgmirror0 ──> tcpdump   │
 │  egress  ─┴─ mirred mirror ─>│ bgm<12hex> ═══ (capture container,     │
 │             cookie <op>      │  tbf limit  │   NET_RAW only)          │
 └──────────────────────────────┘             └──────────────────────────┘
```

- The `mirror` container (hostPID, `NET_ADMIN`, `SYS_ADMIN`, `SYS_PTRACE`,
  AppArmor unconfined, seccomp `RuntimeDefault`, read-only root) finds the
  source network namespace from the Pod UID in `/proc/*/cgroup` (PID 1 for a
  Node), checks that the namespace owns the approved Pod IP and is not the
  host namespace, creates a veth pair with the peer in its own Pod, puts a
  `tbf` on the mirror device (`maxBandwidthMbps`; excess copies are dropped,
  the original traffic is never shaped), adds `clsact` if absent and one
  `basic` (no ematch, so match-all) filter per direction with
  `action mirred egress mirror dev bgm… cookie <operation>`. The agent also
  receives the absolute approved expiry: it refuses to attach after it and
  detaches itself, with verification, when it is reached.
- The `capture` container (only `NET_RAW`) waits for the peer and runs
  `tcpdump -p -n -l -e -s snapLength -c maxPackets -- filter` under a
  `timeout` that ends at the approved expiry. The filter is
  a template field passed as one argument, never through a shell.
- Session participants may read the capture container's logs unless the
  template or binding sets `allowedPodOperations.logs: false`; exec, attach
  and port-forward stay denied (`AllowedPodOperations` and a UID-fenced
  `AllowedPods` entry).

The `basic` classifier is used because `cls_matchall` is missing from some
VM kernels and `u32` hash tables are shared between the clsact ingress and
egress hooks, which makes per-hook ownership ambiguous. Teardown deletes only
the exact filter handles whose action carries the operation cookie, so a
foreign filter added at the same preference survives.

Because the mechanism is plain `tc` in the source network namespace, it works
for the primary interface, Multus secondary interfaces and kernel-bound
SR-IOV VFs alike. DPDK-bound VFs and offloaded traffic that never enters the
kernel datapath are not visible; this is documented as a limitation.

A CNI-specific path (Cilium Hubble, OVS port mirroring) was considered and
rejected for the first version: it would need a pluggable interface and CNI
CRDs, while `tc` already covers every CNI that hands packets to the kernel.

### API

`DebugSessionTemplate.spec.trafficMirror` (opt-in per template):

| Field | Meaning |
| --- | --- |
| `image` | Digest-pinned image with `ip`, `tc`, `nsenter`, `tcpdump` (the `network-debug` utility). |
| `allowedSources[]` | Exactly one of `pod {namespace, matchLabels}` or `node {matchLabels}`, plus `interfaces[]`. |
| `direction` | `ingress`, `egress` or `both` (default). |
| `filter` | tcpdump expression, restricted character set, at most 256 characters. |
| `snapLength`, `maxPackets`, `maxBandwidthMbps` | Capture and mirror bounds (defaults 256, 10000, 10). |

The template must satisfy the fixed-executor contract already used by
node maintenance and hotfixes: `targetNamespace: breakglass-node-maintenance`,
explicit approvers without auto-approval, blocked self-approval, an explicit
`maxDuration` (at most one hour), no renewal, no Pod template, scheduling,
terminal sharing or recording. Only required, create-before and
delete-after auxiliary resources (for example a per-session
PolicyException) are allowed.

`DebugSession.spec.trafficMirror` is the requester's source:
`{podNamespace, podName, interface}` or `{nodeName, interface}`. The REST API
resolves the live Pod and Node, checks namespace, labels and interface
against the allowlist, rejects host-network Pods and records `podUID`,
`nodeName` and `nodeUID` in the request before the session exists, so the
approver approves exact incarnations. Activation re-reads the source and
fails closed if any identity, label or the interface changed.

`DebugSession.status.trafficMirror` holds `operationID`, `state`
(`pending`, `mirroring`, `failed`, `stopped`), `createAttempted`, `podUID`,
`teardownVerified`, `stopAudited` and `released`.

### Lifecycle and crash safety

1. **Approval.** Mirror sessions always require an independent approver,
   regardless of `blockSelfApproval` defaults, like the other typed executors.
2. **Start.** Before any target write the controller installs the cleanup
   finalizer, emits the durable `debug_session.traffic_mirror.started` receipt
   and persists the inventory, then `createAttempted`, then creates the Pod.
   The receipt and markers have deterministic IDs, so retries never duplicate.
3. **Active.** The controller marks `mirroring` once the agent's readiness
   probe reports the attach, and fails the session (with
   `debug_session.traffic_mirror.failed`) when the agent exits or the Pod
   disappears or changes identity.
4. **End.** On expiry, termination, failure or deletion the controller
   deletes the mirror Pod; a deleted session that is still active is first
   made terminal so the teardown can record its progress. The agent traps
   `SIGTERM` and detaches. Independently the agent and the capture stop at
   the absolute approved expiry, and `activeDeadlineSeconds` is a backstop,
   so mirroring ends on time even while the controller is down.
5. **Verified teardown.** Whenever `createAttempted` is set, the controller
   then runs a teardown Pod on the same Node. It deletes only filters whose
   action cookie is the operation's, deletes the mirror device and an empty
   `clsact`, and exits successfully only after re-reading that none remain.
   Every inspection must succeed: a namespace or `tc` read error fails the
   teardown instead of counting as absence. A failed teardown Pod is
   replaced; the session keeps its finalizer and reports `CleanupFailed`
   until the teardown succeeds. A Node that was deleted and registered again
   is torn down like the original (it may be the same kernel). A Node that
   is gone cannot be verified, so cleanup stays unresolved until an operator
   confirms the host is gone and removes the finalizer.
6. **Release.** After `debug_session.traffic_mirror.stopped` the teardown
   Pod and auxiliary resources are removed and `released` is set.

All state is keyed by the operation ID derived from the session UID, so a
controller restart at any step resumes from the durable status. A killed
agent (`SIGKILL`, OOM) cannot trap: its filters keep mirroring into a device
that disappears with the Pod, which the kernel treats as a no-op, until the
teardown Pod removes them.

### Global switch

`--disable-traffic-mirror` (`BREAKGLASS_DISABLE_TRAFFIC_MIRROR`) refuses new
mirror requests in the API and new activations in the controller. Cleanup of
existing mirrors is unaffected.

### Captures and the artifact store

The diagnostic artifact backend accepts only its allowlisted recipes
(`system-summary.v1`, `crashdump-collection.v1`), so captures are not
uploaded yet: the capture is the bounded decoded tcpdump output in the
capture container log. A `traffic-capture.v1` recipe that writes a pcap ring
buffer and uploads it through the existing one-time upload token is the
follow-up; it needs no change to the mirror executor.

## Testing

- Unit tests cover template, request and session validation, the rendered
  Pod security contract, idempotent deploy, failure detection, the verified
  teardown sequence, foreign Pods and replaced Nodes.
- `hack/traffic-mirror-kind.sh` (workflow `Traffic mirror controller`)
  runs on a GitHub-hosted `ubuntu-24.04` Kind cluster with the real API
  handler and controller: requests outside the allowlist are refused, a Pod
  mirror shows target traffic but no decoy traffic in the capture log,
  survives a controller restart and is removed on terminate; a Node mirror is
  removed at expiry; a `SIGKILL`ed agent leaves filters that cleanup removes.
  After each session the test inspects the source network namespace on the
  Kind node and asserts that no filter with the cookie, no mirror device and
  no `mirred` action remain.
