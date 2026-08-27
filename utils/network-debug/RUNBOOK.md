<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: CC-BY-4.0
-->

# Network-debug runbook

The runtime is inherited from the immutable netshoot v0.16 multi-architecture
manifest. Its overlapping network tools are retained as shipped by netshoot;
this image adds only the bounded `net-debug`/`net-report` contract, selected-
pod capture, pinned `pwru`, and the documentation mounted under
`/usr/share/breakglass/runbooks/upstream/network-debug`.

Use `net-report` for a deterministic overview, then invoke only the helper
needed for the incident. `net-debug --help` and `net-debug tools` list the
supported commands; `curl`, `nc`, `dig`, `ip`, `ss`, `tcpdump`, `mtr`, and the
pinned `pwru` tool is available for approved host-namespace tracing.

Join only the target pod or node network namespace. Grant the minimum
capabilities required by the selected operation; never use blanket privilege
by default. For a bounded capture use, for example,
`net-debug capture --interface eth0 --duration 30 --packets 1000 --snaplen 128
--filter 'tcp port 443' --output capture.pcap`. The helper uses a fixed exec
argv, disables promiscuous mode, rejects unsafe interface/filter/output input,
and writes only a new file below `/work`.

For a kernel trace, use `net-debug trace --duration 30 --events 1000
--filter 'skb mark 0' --output trace.log` from a host network namespace with
the required BTF, debugfs, tracefs, securityfs/LSM, BPF/PERFMON,
NET_ADMIN, and SYS_RESOURCE prerequisites. The helper fails closed
when any prerequisite is absent; its host-trace context drops `NET_RAW` and
does not add privileged or SYS_ADMIN fallbacks. Save pcaps and reports only to an approved mount, redact
addresses and payloads, and remove the session when the investigation is
complete. The trace workload must set both `hostNetwork: true` and
`hostPID: true`; the helper independently compares `/proc/self/ns/net` with
`/proc/1/ns/net` before starting `pwru`.

Path, capability, and namespace override environment variables exist only for
hermetic image tests. They are controller-owned implementation details and
must not be exposed as DebugSession request fields.

Built-in runbooks remain at `/usr/share/breakglass/runbooks/upstream/network-debug/`. A downstream
deployment may read-only mount an optional digest-pinned bundle at
`/usr/share/breakglass/runbooks/internal`, with `INDEX.md` as its optional entry point. The image
never hardcodes, sources, or executes that bundle.

## Server-owned selected-pod capture

Do not expose `pod-netns-capture` through an interactive template or pass
requester-authored commands to it. It exists for the bounded server-owned
`network-diagnostics` pod-capture Job. Resolve the selected Pod immediately
before Job creation and pass its immutable lowercase UID, not its mutable name,
PID, namespace, or node. A representative image-side invocation is:

```console
pod-netns-capture \
  --pod-uid 12345678-1234-4abc-8def-1234567890ab \
  --interface any --duration 30 --count 1000 --snaplen 128 \
  --filter 'tcp port 443' --output capture.pcap
```

Run it only in a one-shot Job with `hostPID: true`, `hostNetwork: false`,
`automountServiceAccountToken: false`, a root-owned `emptyDir` at `/work`, a
mode of `0700` on that directory, a read-only root filesystem, and all
capabilities dropped before adding
`SYS_ADMIN`, `SYS_PTRACE`, and `NET_RAW`. Do not mount a host path, containerd,
CRI-O, or Docker socket. Delete the Job and evidence volume through the normal
session cleanup path even after failure or interruption.

The helper deliberately refuses unfamiliar cgroup roots/runtime scope names,
ambiguous namespace inodes, target churn, output replacement, and excessive
evidence. A failure saying the cgroup/runtime layout is unsupported is a
platform compatibility finding—not permission to add fuzzy UID matching or a
CRI socket. Validate a new runtime layout with real `/proc/PID/cgroup` fixtures
and the target-versus-decoy Linux workflow before allowlisting it.

The real-tool proof sends `SIGINT` to `pwru`, waits up to 15 seconds for the
container to exit, and then reconciles asynchronous BPF detachment for up to
5 additional seconds. Configure the primary and settle bounds with
`NETWORK_DEBUG_PWRU_STOP_TIMEOUT_SECONDS` and
`NETWORK_DEBUG_PWRU_STOP_SETTLE_SECONDS`; a still-running container is a
failed proof and is cleaned up only when its invocation ownership is verified.
