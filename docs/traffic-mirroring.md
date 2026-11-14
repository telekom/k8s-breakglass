<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# Traffic mirroring

A `trafficMirror` template lets an approved debug session copy the traffic of
one allowlisted interface of one Pod or Node into a capture container of the
session. The controller attaches and removes the mirror itself; requesters
choose only the source. Design background:
[proposal](proposals/traffic-mirroring.md).

Traffic mirroring is opt-in per template and can be disabled for the whole
controller with `--disable-traffic-mirror`.

## Operator prerequisites

- Provision the target-cluster namespace `breakglass-node-maintenance` (shared
  with the other fixed executors). Its admission policy must admit the Pod
  contract below; with Pod Security Admission the agent and teardown Pods
  need the `privileged` level. With Kyverno, add a required, create-before,
  delete-after per-session PolicyException as an auxiliary resource of the
  template.
- The ClusterConfig credential of the target cluster must be allowed to
  create, get and delete `pods` and `networking.k8s.io/networkpolicies` in
  `breakglass-node-maintenance`, and to get `pods` in the source namespaces
  and `nodes`.
- The CNI must enforce NetworkPolicy. Otherwise the per-operation deny-all
  policy has no effect and the capture Pod is not isolated on the Pod
  network; the controller cannot detect this, so verify it before enabling
  a mirror template.
- Use an image with `ip`, `tc`, `nsenter`, `timeout` and `tcpdump`, pinned
  by digest, for example the [network-debug](network-debug-image.md) utility.
- The source Node kernel needs `sch_ingress` (`clsact`), `cls_basic`,
  `act_mirred`, `act_gact` (drop), `sch_tbf` and `veth`. Nodes booted with
  `ipv6.disable=1` are supported.

## Template

```yaml
apiVersion: breakglass.t-caas.telekom.com/v1alpha1
kind: DebugSessionTemplate
metadata:
  name: mirror-shop-cart
spec:
  displayName: Mirror cart Pod traffic
  targetNamespace: breakglass-node-maintenance   # required
  allowed:
    groups: [sre]
    clusters: [prod-*]
  approvers:
    groups: [network-leads]                      # required, no autoApproveFor
  constraints:
    maxDuration: 30m                             # required, at most 1h, no renewal
    defaultDuration: 15m
  trafficMirror:
    image: ghcr.io/telekom/k8s-breakglass/utils/network-debug@sha256:<digest>
    allowedSources:
      - pod:
          namespace: shop
          matchLabels: {app: cart}
        interfaces: [eth0, net1]                 # net1: Multus or SR-IOV
      - node:
          matchLabels: {node-role.kubernetes.io/edge: ""}
        interfaces: [bond0]
    direction: both                              # ingress | egress | both
    filter: "tcp port 8080"                      # tcpdump expression
    snapLength: 256
    maxPackets: 10000
    maxBandwidthMbps: 10
```

| Field | Default | Meaning |
| --- | --- | --- |
| `image` | — | Digest-pinned image; never chosen by the requester. |
| `allowedSources[].pod` | — | Pods in one exact namespace whose labels all match (1–8 labels). The executor namespace is refused. |
| `allowedSources[].node` | — | Nodes whose labels all match; empty labels allow every Node. |
| `allowedSources[].interfaces` | — | 1–8 exact interface names of that source. |
| `direction` | `both` | Hooks that are mirrored. |
| `filter` | empty (all) | tcpdump expression, letters, digits, spaces and `.:/()!&\|=<>[]-` only, at most 256 characters. |
| `snapLength` | 256 | Captured bytes per packet (64–65535). |
| `maxPackets` | 10000 | The capture stops after this many packets (1–1000000). |
| `maxBandwidthMbps` | 10 | Token bucket on the mirror device (1–1000). Excess copies are dropped; the source traffic is never shaped. |
| `capturePayload` | `false` | `false` prints packet headers only (`tcpdump -q`, at most 96 bytes captured per packet). `true` restores protocol decoding (for example HTTP request lines) and `snapLength`. |

The template is a fixed executor: no Pod template, scheduling, terminal
sharing, recording or renewal, explicit approvers and blocked self-approval.
Typed executors are not rendered by the `debug-session-catalogue` chart;
manage these templates directly.

## Request

```bash
curl -X POST "$BREAKGLASS/api/debugSessions" -d '{
  "templateRef": "mirror-shop-cart",
  "cluster": "prod-eu-1",
  "requestedDuration": "15m",
  "reason": "INC-1234 dropped connections on net1",
  "trafficMirror": {"podNamespace": "shop", "podName": "cart-7d9f", "interface": "net1"}
}'
```

A Node source uses `{"nodeName": "edge-3", "interface": "bond0"}`. The API
resolves the live source, checks it against the allowlist and records
`podUID`, `nodeName` and `nodeUID` in `spec.trafficMirror` before approval;
a Pod that uses the host network must be requested as its Node. Generic
workload inputs (scheduling, node selectors, extra values, participants) are
refused. Sessions cannot be renewed.

After approval the controller re-reads the source and starts only if the Pod
and Node are the approved incarnations and still allowlisted. Then:

```bash
kubectl -n breakglass-node-maintenance logs -f <status.trafficMirror.operationID>-capture
```

Exec, attach and port-forward into the mirror Pods stay denied. Log access is
granted unless the template or binding sets `allowedPodOperations.logs: false`.

## Pod contract

Each session runs two Pods on the source Node, plus a teardown Pod at the
end:

| Pod | Host namespaces | Privileges | Purpose |
| --- | --- | --- | --- |
| `<operationID>-capture` | none | `NET_RAW`, `SETUID`, `SETGID`; tcpdump drops to `nobody` after opening its socket; runtime AppArmor and seccomp profiles; read-only root; no privilege escalation | Receives the mirrored copies on `bgmirror0` and runs `tcpdump`. The only Pod participants may read. |
| `<operationID>` (agent) | `hostPID` | root, `NET_ADMIN`, `SYS_ADMIN`, `SYS_PTRACE`, AppArmor unconfined, seccomp `RuntimeDefault`, read-only root, no privilege escalation | Enters the source namespace, attaches the mirror, moves the capture end of the veth into the capture Pod, detaches on `SIGTERM` or at expiry. Never captures. |
| `<operationID>-teardown` | `hostPID` | as the agent | Removes and verifies the operation's state after the session. |

The capture Pod is created first; the controller creates the agent only
after the capture Pod runs, and passes its UID and IP so the agent can find
exactly that namespace. Because the capture has no `hostPID`, a compromised
tcpdump cannot see or signal host processes. No Pod has the host network or
a service account token; all run with `restartPolicy: Never`, CPU and memory
limits, and the absolute approved expiry (`activeDeadlineSeconds` is a
backstop).

The mirror devices are no path into the source: neither end has an IPv4 or
IPv6 address, ARP is off, and every frame sent from the capture side is
dropped at the source-side device. A per-operation deny-all NetworkPolicy
isolates all three Pods on the Pod network.

## Capture logs are sensitive

The capture log contains the source's addresses, ports and timing, and with
`capturePayload: true` decoded protocol content such as URLs, query tokens
or plain-text credentials.

- Readers: session participants through the `log` subresource (unless
  `logs: false`), and anyone with `get` on `pods/log` in
  `breakglass-node-maintenance`. Keep that RBAC to platform operators.
- Retention: the log lives in the kubelet container log of the capture Pod
  and is removed with the Pod at cleanup. Copies made by node log shippers
  follow their own retention.
- Exclude `breakglass-node-maintenance` from log shipping, or restrict its
  index to the audiences above, before enabling a mirror template.

## Cleanup

On expiry, termination, failure or deletion the controller deletes the
agent and capture Pods (the agent detaches), then runs a teardown Pod on the Node that
removes only `tc` filters carrying the session's action cookie, from every
link of the source network namespace, and the mirror device (the `clsact`
qdisc stays), and succeeds only after verifying that none remain;
an inspection error is a failure, never proof of absence. The
session keeps its finalizer and the `CleanupFailed` condition until that
verification succeeds, which also covers a controller restart and a crashed
agent. A Node that was deleted and registered again is torn down like the
original. If the Node is gone, the teardown cannot be verified: confirm that
the host was reprovisioned, then remove the finalizer
`breakglass.t-caas.telekom.com/node-maintenance-cleanup` by hand. The same
applies when the source Pod still runs but none of its namespaces owns the
approved Pod IP any more: the teardown cannot prove that the old filters are
gone, so an operator inspects the Node (`tc filter show dev <interface>
ingress|egress` in the Pod's namespace, looking for the session's cookie)
before removing the finalizer.

## Audit

| Event | When |
| --- | --- |
| `debug_session.traffic_mirror.started` | After approval, before any Pod is created. |
| `debug_session.traffic_mirror.failed` | The agent or the capture failed, or one of their Pods disappeared or changed. |
| `debug_session.traffic_mirror.stopped` | After the teardown was verified. |

Each event carries the session and operation IDs, approver, Node and Pod
UIDs, interface, direction, filter and image. Mirror sessions require a
synchronous durable audit sink.

## Limitations

- Only traffic that passes the kernel datapath of the interface is visible:
  DPDK-bound SR-IOV VFs and hardware-offloaded flows are not mirrored.
- Packets are mirrored by a tc clsact filter in the source network
  namespace, so ingress copies are taken before netfilter there
  (MultiNetworkPolicy, host firewall). For a Pod source, egress copies are
  also taken before host-side Cilium or Calico policy, which runs outside the
  Pod's namespace. The capture can therefore contain packets that policy
  drops afterwards.
- A tcx program, or a tc filter at a lower preference, that returns a verdict
  on the same hook ends classification before the mirror filter, which then
  sees none of those packets. Cilium and Calico eBPF programs on Node
  devices do this, so a Node source can capture nothing. The mirror itself
  uses the `continue` action and never hides packets from later filters.
  `Ready` and the `mirroring` state mean that the mirror is attached, not
  that it observes packets.
- A renamed or re-created source interface fails the session: the mirror
  agent checks the interface index and hardware address while it runs, and
  teardown removes the operation's filters from every link of the namespace.
  A failed teardown keeps its reason in `status.trafficMirror.teardownResult`
  and the `CleanupFailed` condition.
- Captures are the decoded `tcpdump` output in the capture container log.
  Uploading pcaps to the [diagnostic artifact store](diagnostic-artifacts.md)
  is planned as a separate recipe.
- One filter preference per operation is derived from the session UID; if a
  foreign filter already uses it on the interface, the session fails closed.
- The session fails when the capture exits with an error (for example an
  invalid filter expression).
