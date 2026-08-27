<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# Network Debug Utility Image

`network-debug` is a generic toolbox for investigating connectivity from a
Kubernetes pod or node network namespace. It inherits the runtime toolset from
the immutable multi-architecture `ghcr.io/nicolaka/netshoot:v0.16` manifest and
adds a bounded command/report contract, `pwru`,
and the local runbook/docs. It is free of cluster names, cloud credentials,
private registries, and organization-specific assumptions. The image is
published for `linux/amd64` and `linux/arm64`.

The pinned netshoot release already provides every overlapping command used by
this contract: `bash`, `bind-tools` (`dig`, `host`, `nslookup`), `busybox-extras`,
`curl`, `ethtool`, `iproute2` (`ip`, `ss`), `iputils` (`ping`, `tracepath`),
`jq`, `mtr`, `netcat-openbsd`, `tcpdump`, and the `util-linux` helpers used by
the proofs. We deliberately do not reinstall or independently pin those
packages. The upstream netshoot package set is part of the digest-pinned base;
the additions are listed in [`IMAGE-METADATA.yaml`](./IMAGE-METADATA.yaml).

## Included capabilities

- Connectivity: `curl`, `nc`, `ping`, `tracepath`, `traceroute`, `mtr`, DNS
  lookup (`dig`, `host`, `nslookup`), and HTTP/TLS inspection.
- Interfaces and routing: `ip`, `ss`, `ethtool`, policy routing, and socket
  state inspection.
- Capture: `tcpdump` (including pcap output to a mounted directory).
- Server-owned selected-pod capture: an approved ephemeral container injected
  into the selected Pod, sharing only that Pod's network namespace and running
  bounded `tcpdump` with `NET_RAW`.
- Kernel packet tracing: the pinned `pwru` release on kernels with BPF/BTF and
  the capabilities described by `pwru --help`. `pwru` is present for both
  supported architectures; kernel support is evaluated at runtime.

`net-debug capture` is the image-owned bounded capture contract. It accepts
only `any` or a conservative IFNAMSIZ-safe interface name, limits duration to
1–300 seconds, packets to 10,000, snaplen to 64–256 bytes, and filters to 256
characters. The filter is compiled by libpcap before capture. Evidence is
written only to a new file below `/work`; the command prints deterministic
metadata (count, size, and SHA-256), never packet payloads. For example:

```console
/work # net-debug capture --interface eth0 --duration 30 --packets 1000 \
  --snaplen 128 --filter 'host 192.0.2.10 and port 443' --output capture.pcap
```

`net-debug trace` is the bounded host-network-namespace `pwru` wrapper. It
limits duration to 60 seconds and evidence to 10,000 lines, runs pwru in an
owned `setsid` process group, sends SIGINT at the duration deadline, and forces
KILL after the bounded grace period. It
refuses to run unless BTF, debugfs, tracefs, securityfs/LSM, and the required BPF/PERFMON,
NET_ADMIN, SYS_RESOURCE, and SYS_PTRACE capabilities are available. SYS_PTRACE
is limited to the kernel-enforced host-PID namespace identity check. It never
uses privileged, SYS_ADMIN, or capability fallbacks.
The trace workload must use `hostNetwork: true` and `hostPID: true`; the
wrapper verifies that its network namespace is the host init namespace through
`/proc/1/ns/net` before starting `pwru`.

The image runs as root because packet capture and eBPF tracing require kernel
access. Grant only the network namespace and Linux capabilities needed for the
specific investigation. Do not add `privileged: true` by default.

The `NETWORK_DEBUG_*` path, capability, and namespace overrides are test-only
injection points. They are not requester inputs; production DebugSessions use
controller-owned fixed paths and capability settings.

## Optional downstream runbooks

Built-in documentation is image-owned at `/usr/share/breakglass/runbooks/upstream/network-debug/`. A
deployment may additionally mount a read-only, digest-pinned downstream bundle
at `/usr/share/breakglass/runbooks/internal`, with an optional
`/usr/share/breakglass/runbooks/internal/INDEX.md`. The
image does not hardcode, source, or execute bundle content; that wiring is an
external immutable-template and admission-control responsibility.

## Usage

The default command opens a POSIX shell. The interactive shell displays a
short, neutral MOTD. Helpers are deterministic and do not include timestamps,
hostnames, or command history:

```console
$ docker run --rm -it --net=container:app ghcr.io/telekom/k8s-breakglass/utils/network-debug:0.1.0
/work # net-debug --help
/work # net-report
/work # net-debug capture --interface any --duration 30 --packets 1000 \
  --snaplen 128 --filter 'tcp' --output capture.pcap
```

For a Kubernetes ephemeral container, use the image through the platform's
normal debug-session controls and review the required `CAP_NET_RAW`,
`CAP_NET_ADMIN`, and BPF permissions with the cluster security team. A minimal
pod example is deliberately omitted so this image remains portable across
Kubernetes distributions and admission policies.

## Reproducibility and supply chain

The netshoot runtime and Go build image are pinned by immutable OCI manifest
digests. The netshoot v0.16 release is the source of the inherited runtime
packages; `pwru` is downloaded for each architecture with a checksum.
`versions.env` is the
human-readable lock record and the image carries OCI version, revision,
creation, source, license, and base-digest labels. The multi-architecture Make
target enables BuildKit SBOM and SLSA provenance attestations; signing is
performed by the publishing pipeline, not by a Dockerfile secret.

The image contains `/licenses/Apache-2.0.txt` and
`/licenses/THIRD_PARTY.md`. Alpine package licenses remain attributable to
Alpine Linux and are listed in the SBOM. Before redistribution, inspect the
generated SBOM and sign the final manifest digest with the approved policy.

## Local checks

```console
make -C utils/network-debug test
make -C utils/network-debug build
make -C utils/network-debug build-multiarch
# Linux only: disposable Docker + kind integration proofs
make -C utils/network-debug integration
make -C utils/network-debug pod-capture-integration
```

The integration target is intentionally fail-closed. It generates loopback
HTTP traffic and proves curl, netcat, DNS, TLS, ping, tracepath, traceroute,
mtr, ethtool, routing, sockets, deterministic reporting, and tcpdump capture.
It then runs `pwru` against that traffic in a host-network namespace with
explicit BPF/PERFMON capabilities. A missing Docker capability, Linux BTF/BPF
support, kind cluster, or StorageClass prints a `REQUIREMENT:` diagnostic and
fails; it does not silently skip a proof. When only the kernel tracing
prerequisites are unavailable, all userspace and packet-capture proofs still
run before the final fail-closed `pwru` requirement. See
[`tests/tool-contract.yaml`](./tests/tool-contract.yaml) for the machine-readable
operation and prerequisite contract.

The integration target creates and owns a uniquely named disposable kind
cluster, including its kubeconfig and namespace. It loads the image into that
cluster and proves bounded `tcpdump` against
generated HTTP traffic in a host-network pod using only `NET_RAW` (never
`privileged`, and without host PID). The pod is deleted and its absence is
checked before the host-trace proof. It never reads or mutates the caller's
kubeconfig. The generated name is preflight-checked; a failed
bootstrap cleans only that attempted name and any matching labeled node
containers, while a pre-existing name is rejected. The dedicated CI job runs
this target on a Linux runner with Docker and kind.

Selected-pod capture is performed by an approved controller injecting a
short-lived ephemeral container into the selected Pod through the Kubernetes
`ephemeralcontainers` subresource. Requesters never provide commands, PIDs,
pod names, nodes, or raw argv.

The selected-pod operation is an API-level controller action, not an image-side
helper. The controller resolves the selected Pod, appends one ephemeral
container through the `ephemeralcontainers` subresource, and supplies the fixed
image-owned command and bounds. The admitted object must retain
`hostNetwork: false`, `hostPID: false`, token automount disabled, one exact
`emptyDir` mounted at `/work`, `privileged: false`, no privilege escalation,
`readOnlyRootFilesystem: true`, and only `NET_RAW` after dropping `ALL`.
Requesters cannot provide pod names, PIDs, nodes, commands, capabilities,
mounts, or output paths. The container captures generated traffic in the
selected Pod network namespace and proves a same-cluster decoy is not visible;
the Linux/kind workflow then deletes both Pods and verifies namespace/cluster
cleanup.

The host trace remains a separate host-network/host-PID operation. Its wrapper
executes the pinned `pwru --backend kprobe` with a native event-line bound into
a private regular staging file, applies an independent kernel file-size bound,
and runs it under an owned process-group watchdog with bounded INT-to-KILL
shutdown.
Only after the process exits does it no-clobber publish the file below `/work`.
This avoids FIFO startup/shutdown deadlocks while preserving real packet-tuple
evidence and exact cleanup. Missing BTF, tracing filesystems, capabilities, or
host namespace identity remains a fail-closed result; no SYS_ADMIN or
privileged fallback is permitted.
The `pwru` portion requires readable `/sys/kernel/btf/vmlinux`, debugfs,
tracefs, securityfs, and BPF/PERFMON support. Local macOS/Windows Docker Desktop or a
non-kind Kubernetes context is not a substitute for that job.

Graceful `pwru` shutdown is bounded by `NETWORK_DEBUG_PWRU_STOP_TIMEOUT_SECONDS`
(15 seconds by default) after the primary duration. The wrapper sends INT via
the process-group watchdog and then forces KILL at that deadline; a still-running
container is removed only after the run-ownership checks.

`build-multiarch` writes a local OCI archive and never pushes a mutable tag.
Publish the reviewed manifest, resolve its immutable digest, then run
`make sbom IMAGE=... DIGEST=... SBOM=...` and
`make sign IMAGE=... DIGEST=...`. Set `IMAGE`, `VERSION`, `VCS_REF`, and
`BUILD_DATE` explicitly in release automation. `IMAGE-METADATA.yaml` records
the shared `network-diagnostics` intent and the expected attestation policy.
