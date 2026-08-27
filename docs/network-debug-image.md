<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# Network debug image runbook

The image inherits the runtime toolset from the immutable
`ghcr.io/nicolaka/netshoot:v0.16@sha256:b09d9b21381f47a79b3cbcb30da25266dc17186ea00ae65e99fdc51396f48e70`
manifest. Netshoot provides the overlapping network commands used below; this
project adds the bounded `net-debug`/`net-report` contract, selected-pod
capture, pinned `pwru`, and the local runbook/docs. The base is not reinstalled
or independently APK-pinned in this image.

Use the network-debug utility image when a connectivity problem must be
observed from the same network namespace as a workload or node. Start with
`net-report`, then narrow the investigation to one question: name resolution,
route selection, transport connectivity, packet capture, or kernel path.
The image is advertised under the shared `network-diagnostics` intent; that
intent identifies the diagnostic workflow and does not grant Kubernetes API
permissions or authorize network mutation.

The image also contains `pod-netns-capture`, a non-interactive primitive for a
server-owned selected-pod capture Job. It accepts an immutable Pod UID plus
bounded capture fields, discovers the exact pod cgroup through host procfs,
rejects ambiguous or unknown runtime layouts, opens and revalidates the network
namespace against PID reuse, enters it once, and invokes a fixed no-shell
`tcpdump -p` command. It never uses a CRI socket or host path and emits only
capture metadata and SHA-256; the pcap remains on the Job's protected
`emptyDir`.

## Suggested sequence

1. Run `net-report` and save the output to a protected incident location.
2. Check DNS with `dig +short`, route selection with `ip route get ADDRESS`,
   and transport reachability with `nc -vz HOST PORT` or `curl -v`.
3. Capture only the required interface and filter with the bounded helper:
   `net-debug capture --interface eth0 --duration 30 --packets 1000
   --snaplen 128 --filter 'host ADDRESS and port PORT' --output capture.pcap`.
4. If the packet is not visible at the expected kernel hook, check the host
   prerequisites and run `net-debug trace --duration 30 --events 1000
   --filter 'skb mark 0' --output trace.log`.
5. Remove captures after the incident retention period; packet data can contain
   credentials and personal data.

## Safety and permissions

The image is root because `tcpdump` and `pwru` need kernel access. The
image-owned capture requires `CAP_NET_RAW`; the trace helper additionally
requires explicit BPF/PERFMON, NET_ADMIN, and SYS_RESOURCE
capabilities, read-only debugfs, tracefs, and securityfs/LSM mounts, and a
kernel with BTF. Follow the target
cluster's Pod Security policy. Never copy a
capture to a public tracker without redaction.

The image contains no `kubectl`, credentials, or kubeconfig. Keep
`automountServiceAccountToken: false` for ordinary network diagnostics; any
deployment-specific API access is external to this image contract.

The image runs as UID 0 to support packet capture and eBPF tools. A workload
or DebugSession using it must isolate the network namespace and grant only the
capabilities required for the selected operation (`NET_RAW`/`NET_ADMIN`, and
for `pwru`, the platform's approved BPF/perfmon permissions). Do not combine
this image with host networking or broad write-capable service-account RBAC
unless the incident approval explicitly requires it. The shell is an operator
tool, not a bounded repair API: commands such as `ip route`, `ip link`, and
`ethtool` can mutate a shared namespace. Use the dedicated node-maintenance
repair workflow for allowlisted repairs.

The selected-pod helper is a separate privilege profile: `hostPID: true`,
`hostNetwork: false`, and only `SYS_ADMIN`, `SYS_PTRACE`, and `NET_RAW` after
dropping all capabilities. Those powers are valid only in the short-lived,
server-owned Job with no service-account token, host path, or runtime socket.
They must not be added to the generic interactive network-debug profile.

The repository's `config/samples/debug-pod-template-network.yaml` shows the
same image in a `DebugPodTemplate`; replace its version tag with the reviewed
final manifest digest before applying it to a cluster.

## Reproducible evidence

`net-report` sorts interfaces, routes, rules, DNS servers, and tool names. It
omits timestamps, hostnames, and random IDs, making two reports easy to diff.
Runtime values are still expected to change with network namespace state. Keep
the image tag and final manifest digest alongside any evidence; image tags are
human-readable selectors, while the digest is the reproducible artifact.

See [`utils/network-debug/README.md`](../utils/network-debug/README.md) for the
tool lock record, license notices, and BuildKit SBOM/provenance commands.

## Release integration proofs

The image has a fail-closed integration harness at
[`utils/network-debug/tests/integration.sh`](../utils/network-debug/tests/integration.sh).
It generates disposable HTTP traffic, verifies the shipped connectivity, DNS,
TLS, socket, and routing helpers, reads a real tcpdump pcap in the Docker
fixture, then repeats a bounded capture in a host-network Kubernetes pod with
only `CAP_NET_RAW`, no host PID, and no privileged mode. It observes generated
packets with `pwru`, and runs selected-pod and host-namespace capture in
disposable Kind resources. Missing BTF/BPF/PERFMON, Docker capabilities, or
Kind support emits an actionable
`REQUIREMENT:` message and fails the dedicated compatible-runner job rather
than reporting a partial pass. The operation and prerequisite contract is
tracked in [`tool-contract.yaml`](../utils/network-debug/tests/tool-contract.yaml).

Selected-pod capture has a separate Linux/kind workflow. It creates target and
decoy traffic pods on one disposable node, passes only the target Pod UID to a
host-PID/non-host-network capture Job, proves the pcap contains target traffic
and excludes the decoy, and then checks exact namespace, Job, kind node,
container, and temporary-directory cleanup. Required setns, capabilities, or
recognized cgroup facilities are never skipped silently.

Built-in documentation remains at `/usr/share/breakglass/runbooks/upstream/network-debug/`. A downstream
deployment may read-only mount an optional digest-pinned runbook bundle at
`/usr/share/breakglass/runbooks/internal`, with an optional `INDEX.md`. The image does not hardcode,
source, or execute bundle content; immutable workload wiring and admission are
external boundaries.
