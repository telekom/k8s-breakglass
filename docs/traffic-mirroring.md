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
  with the other fixed executors). Its admission policy must admit the mirror
  Pod contract below; with Pod Security Admission that is the `privileged`
  level. With Kyverno, add a required, create-before, delete-after
  per-session PolicyException as an auxiliary resource of the template.
- Use an image with `ip`, `tc`, `nsenter` and `tcpdump`, pinned by digest,
  for example the [network-debug](network-debug-image.md) utility.
- The source Node kernel needs `sch_ingress`/`clsact`, `cls_basic`,
  `act_mirred`, `sch_tbf` and `veth`.

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
kubectl -n breakglass-node-maintenance logs -f <status.trafficMirror.operationID> -c capture
```

Exec, attach and port-forward into the mirror Pod stay denied. Log access is
granted unless the template or binding sets `allowedPodOperations.logs: false`.

## Mirror Pod contract

| Container | Privileges | Purpose |
| --- | --- | --- |
| `mirror` | root, `NET_ADMIN`, `SYS_ADMIN`, `SYS_PTRACE`, AppArmor unconfined, seccomp `RuntimeDefault`, read-only root, no privilege escalation | Enters the source network namespace, attaches the mirror, detaches on `SIGTERM`. |
| `capture` | root, only `NET_RAW`, read-only root, no privilege escalation | `tcpdump` on the mirror device. |

The Pod uses `hostPID` (to find the source network namespace) but not the
host network, has no service account token, runs on the source Node with
`restartPolicy: Never`. Both containers receive the absolute approved expiry
and stop at it on their own; `activeDeadlineSeconds` is a backstop.

## Cleanup

On expiry, termination, failure or deletion the controller deletes the
mirror Pod (the agent detaches), then runs a teardown Pod on the Node that
removes only `tc` filters carrying the session's action cookie, the mirror
device (the `clsact` qdisc stays), and succeeds only after verifying that none
remain; an inspection error is a failure, never proof of absence. The
session keeps its finalizer and the `CleanupFailed` condition until that
verification succeeds, which also covers a controller restart and a crashed
agent. A Node that was deleted and registered again is torn down like the
original. If the Node is gone, the teardown cannot be verified: confirm that
the host was reprovisioned, then remove the finalizer
`breakglass.t-caas.telekom.com/node-maintenance-cleanup` by hand.

## Audit

| Event | When |
| --- | --- |
| `debug_session.traffic_mirror.started` | After approval, before the mirror Pod is created. |
| `debug_session.traffic_mirror.failed` | The agent exited or the mirror Pod disappeared or changed. |
| `debug_session.traffic_mirror.stopped` | After the teardown was verified. |

Each event carries the session and operation IDs, approver, Node and Pod
UIDs, interface, direction, filter and image. Mirror sessions require a
synchronous durable audit sink.

## Limitations

- Only traffic that passes the kernel datapath of the interface is visible:
  DPDK-bound SR-IOV VFs and hardware-offloaded flows are not mirrored.
- Captures are the decoded `tcpdump` output in the capture container log.
  Uploading pcaps to the [diagnostic artifact store](diagnostic-artifacts.md)
  is planned as a separate recipe.
- One filter preference per operation is derived from the session UID; if a
  foreign filter already uses it on the interface, the session fails closed.
- The session fails when the capture exits with an error (for example an
  invalid filter expression).
