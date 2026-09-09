<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: CC-BY-4.0
-->

# Network-debug runbook

The runtime is inherited from the immutable netshoot v0.16 multi-architecture
manifest. Its overlapping network tools are retained as shipped by netshoot;
this image adds only the bounded `net-debug`/`net-report` contract, approved
ephemeral pod capture, pinned `pwru`, and the documentation mounted under
`/usr/share/breakglass/runbooks/upstream/network-debug`.

The inherited Alpine package set is taken exactly from the digest-pinned
netshoot base. This Dockerfile does not run `apk upgrade` or add a separate
repository, so weekly rolling rebuilds do not silently refresh that package
layer. Update the reviewed base digest when security fixes are needed, then
scan the exact resulting digest before publication.

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
NET_ADMIN, SYS_RESOURCE, and SYS_PTRACE prerequisites. SYS_PTRACE is used
only to read `/proc/1/ns/net` for the host-PID identity check. The helper fails closed
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

Selected-pod capture is an approved controller operation. Resolve the selected
Pod immediately before use, then append one fixed ephemeral container through
the Kubernetes `ephemeralcontainers` subresource. Do not expose an interactive
helper or accept requester-authored commands, PIDs, pod names, nodes,
capabilities, mounts, or output paths. The ephemeral container targets the
selected Pod's existing application container and runs bounded `tcpdump` in
that Pod network namespace; it never uses host PID/network namespaces,
cgroup inference, host paths, or a CRI/runtime socket.

The admitted Pod must retain `hostNetwork: false`, `hostPID: false`,
`automountServiceAccountToken: false`, exactly one owner-only `emptyDir` at
`/work`, `privileged: false`, `allowPrivilegeEscalation: false`, and
`readOnlyRootFilesystem: true`. Drop all capabilities and add only `NET_RAW`.
Verify the admitted ephemeral-container object, capture target-versus-decoy
traffic in a real Linux/kind test, and delete the selected and decoy Pods with
absence checks even after failure or interruption.

The real-tool proof runs `pwru --backend kprobe` with a native event-line bound
and an independent regular-file size bound. An owned `setsid` process group
receives SIGINT at the trace duration and forces SIGKILL after the bounded
`NETWORK_DEBUG_PWRU_STOP_TIMEOUT_SECONDS` grace period (15 seconds by default).
A still-running container is a failed proof and is cleaned up only when its
invocation ownership is verified.
If KILL is required, the wrapper accepts the controlled stop only after pwru
has logged attach, signal, and detach lifecycle records without an error-level
diagnostic and the bounded output contains packet tuples; missing lifecycle or
empty output remains a failure.
