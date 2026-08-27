<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# Network Debug Utility Image

`network-debug` is a generic toolbox for investigating connectivity from a
Kubernetes pod or node network namespace. It inherits the runtime toolset from
the immutable multi-architecture `ghcr.io/nicolaka/netshoot:v0.16` manifest and
adds a bounded command/report contract, `pod-netns-capture`, `pwru`,
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
- Server-owned selected-pod capture: `pod-netns-capture`, which resolves an
  immutable Pod UID through host procfs without a CRI socket and enters only an
  exact, unambiguous pod network namespace before bounded `tcpdump` execution.
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
limits duration to 60 seconds and evidence to 10,000 lines, sends SIGINT, and
waits through a separate bounded BPF-detach settle window. It refuses to run
unless BTF, debugfs, tracefs, securityfs/LSM, and the required BPF/PERFMON,
NET_ADMIN, and SYS_RESOURCE capabilities are available. It never
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

`pod-netns-capture` is an image-owned primitive for a later server-owned
`network-diagnostics` pod-capture variant. It is not an interactive command
surface and does not make the current generic kubectl-debug API safe for
selected-pod capture. The future dispatcher must supply the immutable target
Pod UID itself; requesters must never supply a PID, pod name, node, executable,
or raw argv.

The helper accepts only `--pod-uid`, `--interface`, `--duration`, `--count`,
`--snaplen`, `--filter`, and `--output`. Duration is 1–300 seconds, packet
count is 1–10,000, snaplen is 64–256 bytes, filters are printable ASCII up to
256 bytes, interfaces are IFNAMSIZ-safe, and output is a new safe filename
below `/work`. It uses `tcpdump -p` through a literal argv (no shell), applies
an `RLIMIT_FSIZE` derived from the pcap record bound, validates the resulting
pcap, and prints only deterministic metadata, byte count, and SHA-256—not
packet contents.

The intended one-shot Job has `hostPID: true`, `hostNetwork: false`, no host
path or CRI socket, a protected `emptyDir` at `/work`, and exactly
`SYS_ADMIN`, `SYS_PTRACE`, and `NET_RAW` added after dropping all capabilities.
The helper rejects a caller in the host network namespace or with a visible
runtime socket. It scans numeric `/proc/*/cgroup` entries for exact dashed,
underscore-escaped, or `\\x2d`-escaped Pod UID components in recognized
cgroupfs/systemd Kubernetes layouts for containerd, CRI-O, or Docker. Unknown
layouts, UID substrings/confusables, mixed runtime clues, target disappearance,
or multiple network namespace inodes fail closed. A bounded leading run of
kernel-rendered `..` components is accepted for host PIDs viewed from a private
cgroup namespace; embedded traversal is rejected. The helper opens the
namespace FD before final process start-time/cgroup revalidation, calls
`setns` once, and then starts the fixed tcpdump command.

The dedicated Linux/kind behavioral workflow captures target-versus-decoy
traffic and verifies exact Job, namespace, cluster, container, and temporary
directory cleanup. Missing host PID visibility, setns/capability support, or a
recognized CRI cgroup layout is a failed requirement; macOS and Docker Desktop
cannot run this behavioral proof. Unit and fuzz tests use an adversarial fake
proc tree and remain platform-independent.
The `pwru` portion requires readable `/sys/kernel/btf/vmlinux`, debugfs,
tracefs, securityfs, and BPF/PERFMON support. Local macOS/Windows Docker Desktop or a
non-kind Kubernetes context is not a substitute for that job.

Graceful `pwru` shutdown is bounded by `NETWORK_DEBUG_PWRU_STOP_TIMEOUT_SECONDS`
(15 seconds by default) plus a separate
`NETWORK_DEBUG_PWRU_STOP_SETTLE_SECONDS` reconciliation window (5 seconds by
default). The second window covers asynchronous BPF detachment at the primary
deadline; a container that is still running when it expires fails the proof and
is removed only after the run-ownership checks.

`build-multiarch` writes a local OCI archive and never pushes a mutable tag.
Publish the reviewed manifest, resolve its immutable digest, then run
`make sbom IMAGE=... DIGEST=... SBOM=...` and
`make sign IMAGE=... DIGEST=...`. Set `IMAGE`, `VERSION`, `VCS_REF`, and
`BUILD_DATE` explicitly in release automation. `IMAGE-METADATA.yaml` records
the shared `network-diagnostics` intent and the expected attestation policy.
