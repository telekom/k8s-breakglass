<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# Network Debug Utility Image

`network-debug` is a generic, standalone toolbox for investigating connectivity
from a Kubernetes pod or node network namespace. It is intentionally free of
cluster names, cloud credentials, private registries, and organization-specific
assumptions. The image is published as a multi-architecture artifact for
`linux/amd64` and `linux/arm64`.

## Included capabilities

- Connectivity: `curl`, `nc`, `ping`, `tracepath`, `traceroute`, `mtr`, DNS
  lookup (`dig`, `host`, `nslookup`), and HTTP/TLS inspection.
- Interfaces and routing: `ip`, `ss`, `ethtool`, policy routing, and socket
  state inspection.
- Capture: `tcpdump` (including pcap output to a mounted directory).
- Kubernetes storage diagnostics: the pinned `kubestr` release, where the
  cluster API and the required RBAC are available.
- Kernel packet tracing: the pinned `pwru` release on kernels with BPF/BTF and
  the capabilities described by `pwru --help`. `pwru` is present for both
  supported architectures; kernel support is evaluated at runtime.

The image runs as root because packet capture and eBPF tracing require kernel
access. Grant only the network namespace and Linux capabilities needed for the
specific investigation. Do not add `privileged: true` by default.

## Usage

The default command opens a POSIX shell. The interactive shell displays a
short, neutral MOTD. Helpers are deterministic and do not include timestamps,
hostnames, or command history:

```console
$ docker run --rm -it --net=container:app ghcr.io/telekom/k8s-breakglass/network-debug:0.1.0
/work # net-debug --help
/work # net-report
/work # tcpdump -ni any -w /work/capture.pcap
```

For a Kubernetes ephemeral container, use the image through the platform's
normal debug-session controls and review the required `CAP_NET_RAW`,
`CAP_NET_ADMIN`, and BPF permissions with the cluster security team. A minimal
pod example is deliberately omitted so this image remains portable across
Kubernetes distributions and admission policies.

## Reproducibility and supply chain

The runtime and Go build images are pinned by immutable OCI manifest digest.
kubestr and pwru are built from exact upstream release tags. `versions.env`
is the human-readable lock record and the image carries OCI version, revision,
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
```

The integration target is intentionally fail-closed. It generates loopback
HTTP traffic and proves curl, netcat, DNS, TLS, ping, tracepath, traceroute,
mtr, ethtool, routing, sockets, deterministic reporting, and tcpdump capture.
It then runs `pwru` against that traffic in an ephemeral network namespace with
explicit BPF/PERFMON capabilities and executes `kubestr fio` with a pinned, disposable fio fixture
image against a uniquely named disposable StorageClass in a kind cluster. It never reuses a
production namespace or PVC. A missing Docker capability, Linux BTF/BPF
support, kind cluster, or StorageClass prints a `REQUIREMENT:` diagnostic and
fails; it does not silently skip a proof. When only the kernel tracing
prerequisites are unavailable, all userspace, packet-capture, and `kubestr`
proofs still run before the final fail-closed `pwru` requirement. See
[`tests/tool-contract.yaml`](./tests/tool-contract.yaml) for the machine-readable
operation and prerequisite contract.

The integration target creates and owns a uniquely named disposable kind
cluster, including its kubeconfig, storage class, PV, namespace, and PVC. It
never reads or mutates the caller's kubeconfig. The dedicated CI job runs this
target on a Linux runner with Docker and kind.
The `pwru` portion requires readable `/sys/kernel/btf/vmlinux`, debugfs,
tracefs, securityfs, and BPF/PERFMON support. Local macOS/Windows Docker Desktop or a
non-kind Kubernetes context is not a substitute for that job.

`build-multiarch` writes a local OCI archive and never pushes a mutable tag.
Publish the reviewed manifest, resolve its immutable digest, then run
`make sbom IMAGE=... DIGEST=... SBOM=...` and
`make sign IMAGE=... DIGEST=...`. Set `IMAGE`, `VERSION`, `VCS_REF`, and
`BUILD_DATE` explicitly in release automation. `IMAGE-METADATA.yaml` records
the shared `network-diagnostics` intent and the expected attestation policy.
