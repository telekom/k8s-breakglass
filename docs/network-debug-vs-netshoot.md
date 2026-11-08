<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# Network-debug and Netshoot tool parity

This page compares the breakglass
[network-debug utility image](network-debug-image.md) with
[nicolaka/netshoot](https://github.com/nicolaka/netshoot). It answers one
question: can network-debug replace Netshoot in DebugSession and
DebugPodTemplate profiles, and what is missing?

PSA reference: R65-DEBUG.

## Images compared

| | network-debug | Netshoot |
|---|---|---|
| Reference | `ghcr.io/telekom/k8s-breakglass/utils/network-debug:v0.3.0-rc.20` | `nicolaka/netshoot:latest` = `ghcr.io/nicolaka/netshoot:v0.16` |
| Index digest | `sha256:6522f2a12a4e20cf606a9bc6ee1c46ef0ad9543b2baa5ce897319f6995ecd687` | `sha256:b09d9b21381f47a79b3cbcb30da25266dc17186ea00ae65e99fdc51396f48e70` |
| Base | Netshoot v0.16 (same digest), packages upgraded from Alpine 3.24 | Alpine 3.24.1 with Alpine edge repositories |
| Alpine release file | 3.24.4 | 3.24.1 |

network-debug is built `FROM` the same Netshoot v0.16 digest. Its Dockerfile
upgrades the inherited packages, adds `pwru` and the `net-debug`/`net-report`
helpers, and deletes the five statically linked binaries that Netshoot
downloads into `/usr/local/bin` (`calicoctl`, `ctop`, `fortio`, `grpcurl`,
`termshark`). Every Alpine package that Netshoot installs is still present.

## Method

Inspected on 2026-11-07, `linux/amd64` manifests:

```bash
docker run --rm --platform linux/amd64 --entrypoint sh IMAGE@DIGEST \
  -c 'for c in tcpdump dig ...; do command -v "$c"; apk info -q --who-owns "$(command -v "$c")"; done'
docker run --rm --platform linux/amd64 --entrypoint sh IMAGE@DIGEST -c 'apk list --installed PACKAGE'
trivy image --platform linux/amd64 --scanners vuln IMAGE@DIGEST   # Trivy 0.76.2
cosign verify IMAGE@DIGEST \
  --certificate-identity-regexp '^https://github.com/telekom/k8s-breakglass/\.github/workflows/release\.yml@' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com
```

Versions are the Alpine package versions (`apk list --installed`) or, for
binaries outside apk, the binary's own version output. The tool list is the
"Included Tools" section of the Netshoot v0.16 README plus the common commands
that those packages provide.

## Tool matrix

Legend: "yes"/"no" is presence of the command on `PATH`. A version that
differs between the images is in bold.

### Packet capture and traffic analysis

| Tool (command) | network-debug | Netshoot | Version (network-debug / Netshoot) | Notes |
|---|---|---|---|---|
| tcpdump | yes | yes | 4.99.6-r1 | `net-debug capture` wraps it with bounds |
| tshark, dumpcap | yes | yes | **4.6.9-r0 / 4.6.6-r0** | |
| termshark | no | yes | – / v2.4.0 | TUI over tshark; removed in network-debug |
| ngrep | yes | yes | 1.49.0-r0 | |
| iftop | yes | yes | 1.0_pre4-r0 | |
| iptraf-ng | yes | yes | 1.2.2-r0 | |
| netcat (`nc`, OpenBSD) | yes | yes | 1.234.1-r0 | |
| socat | yes | yes | 1.8.1.3-r0 | |
| conntrack | yes | yes | conntrack-tools 1.4.9-r0 | |
| nft | yes | yes | nftables 1.1.6-r1 | |
| pwru | yes | no | v1.0.12 / – | eBPF packet tracing; network-debug only |

### DNS

| Tool (command) | network-debug | Netshoot | Version (network-debug / Netshoot) | Notes |
|---|---|---|---|---|
| dig, nslookup, host | yes | yes | bind-tools **9.20.30-r0 / 9.20.23-r0** | |
| drill | yes | yes | 1.8.4-r1 | |

### Performance and path

| Tool (command) | network-debug | Netshoot | Version (network-debug / Netshoot) | Notes |
|---|---|---|---|---|
| iperf | yes | yes | 2.2.1-r0 | |
| iperf3 | yes | yes | 3.21-r0 | |
| mtr | yes | yes | 0.96-r2 | |
| trippy (`trip`) | yes | yes | 0.13.0-r0 | |
| fping | yes | yes | 5.5-r0 | |
| ping, arping, tracepath | yes | yes | iputils 20250605-r2 | |
| traceroute | yes | yes | busybox 1.38.0-r1 | |
| tcptraceroute | yes | yes | 1.5_beta7-r4 | |
| speedtest-cli | yes | yes | 2.1.3-r8 | Needs Internet egress |
| ethtool | yes | yes | 7.0-r0 | |

### Security and scanning

| Tool (command) | network-debug | Netshoot | Version (network-debug / Netshoot) | Notes |
|---|---|---|---|---|
| nmap | yes | yes | 7.99-r0 | |
| nping | yes | yes | nmap-nping 7.99-r0 | |
| openssl | yes | yes | **3.5.9-r0 / 3.5.7-r0** | |
| scapy | yes | yes | 2.7.0-r1 | |
| dhcping | yes | yes | 1.2-r3 | |

### HTTP, gRPC and SMTP

| Tool (command) | network-debug | Netshoot | Version (network-debug / Netshoot) | Notes |
|---|---|---|---|---|
| curl | yes | yes | **8.23.0-r0 / 8.21.0-r0** | |
| httpie (`http`) | yes | yes | 3.2.4-r2 | |
| grpcurl | no | yes | – / v1.9.3 | Removed in network-debug |
| fortio | no | yes | – / 1.75.2 | Removed in network-debug |
| websocat | yes | yes | 1.14.1-r0 | |
| swaks | yes | yes | 20240103.0-r0 | |
| ab | yes | yes | apache2-utils **2.4.69-r0 / 2.4.68-r0** | |

### Routing and interfaces

| Tool (command) | network-debug | Netshoot | Version (network-debug / Netshoot) | Notes |
|---|---|---|---|---|
| ip, ss, bridge | yes | yes | iproute2 7.1.0-r0 | |
| brctl | yes | yes | bridge-utils 1.7.1-r2 | |
| ipset | yes | yes | 7.24-r0 | |
| iptables, ip6tables | yes | yes | 1.8.13-r0 | |
| ipvsadm | yes | yes | 1.31-r3 | |

### Kubernetes and Calico

| Tool (command) | network-debug | Netshoot | Version (network-debug / Netshoot) | Notes |
|---|---|---|---|---|
| calicoctl | no | yes | – / v3.32.1 | Removed in network-debug |
| ctop | no | yes | – / 0.7.7 (Go 1.18) | Removed in network-debug |

### Debug, tracing and routing daemons

| Tool (command) | network-debug | Netshoot | Version (network-debug / Netshoot) | Notes |
|---|---|---|---|---|
| strace | yes | yes | 6.19-r1 | |
| ltrace | yes | yes | 0.7.3-r6 | |
| snmpget, snmpwalk | yes | yes | net-snmp-tools 5.9.5.2-r1 | |
| bird, birdc | yes | yes | **3.2.4-r0 / 3.2.2-r0** | |

### Shell and utilities

| Tool (command) | network-debug | Netshoot | Version (network-debug / Netshoot) | Notes |
|---|---|---|---|---|
| bash | yes | yes | 5.3.9-r1 | |
| zsh | yes | yes | 5.9-r7 | Netshoot default `CMD`, with oh-my-zsh in `/root`; network-debug has no oh-my-zsh |
| jq | yes | yes | 1.8.2-r0 | |
| vim | yes | yes | **9.2.1202-r0 / 9.2.0747-r0** | |
| git | yes | yes | 2.54.0-r0 | |
| ssh | yes | yes | openssh **10.3_p1-r2 / 10.3_p1-r0** | |
| python3 | yes | yes | **3.14.10-r1 / 3.14.5-r2** | |
| file | yes | yes | 5.47-r2 | |
| net-debug, net-report | yes | no | v0.3.0-rc.20 / – | Bounded capture/trace wrapper and deterministic report |

## Gaps for breakglass debugging

network-debug has every Netshoot tool that a typical breakglass network
investigation uses: DNS (`dig`, `drill`), routing (`ip`, `ss`), transport
(`nc`, `curl`, `socat`, `openssl s_client`), capture (`tcpdump`, `tshark`),
netfilter and kube-proxy state (`iptables`, `nft`, `conntrack`, `ipvsadm`) and
throughput (`iperf3`). It adds kernel-path tracing with `pwru`.

The five missing tools, by relevance:

| Tool | Relevance | Workaround in network-debug |
|---|---|---|
| grpcurl | Medium. gRPC health checks and service probing (`grpc.health.v1`) are a common Kubernetes question that `curl` cannot answer. | None for gRPC reflection or health RPCs; `curl --http2` only checks the transport. |
| fortio | Low. Load testing is not a breakglass activity and can harm a degraded service. | `ab`, `iperf3`. |
| termshark | Low. A TUI over tshark. | `tshark` with display filters, or copy the pcap off and open it in Wireshark. |
| calicoctl | Low. Only useful on Calico clusters, must match the cluster's Calico version and needs Calico datastore credentials that a debug pod must not carry. | `kubectl get` on the Calico CRDs from the operator workstation. |
| ctop | None. Needs the Docker socket; Kubernetes nodes run containerd. | `crictl` on the node; not a network tool. |

## Security posture

| | network-debug | Netshoot |
|---|---|---|
| Signature | Keyless Cosign signature from the k8s-breakglass `release.yml` workflow; `cosign verify` succeeds | None (`cosign verify`: no signatures found) |
| SBOM | SPDX attestation (BuildKit and Cosign) | None |
| Provenance | SLSA v1 provenance (BuildKit and Cosign) | SLSA v1 provenance (BuildKit) |
| User | `0:0` (root) | `root` |
| Default command | `net-debug shell` | `zsh` |
| Capability contract | Declared per operation in `IMAGE-METADATA.yaml` (`NET_RAW` for Pod capture; `NET_ADMIN`, `BPF`, `PERFMON`, ... for host tracing) | None |
| Version pinning | Base and build images pinned by digest; edge repositories removed; Alpine packages are upgraded to the current 3.24 stable at build time, not pinned | Alpine 3.24 and edge repositories; packages not pinned |
| Trivy, all severities | 0 | 1,095 |
| Trivy, CRITICAL / HIGH | 0 / 0 | 13 / 497 |
| Trivy, MEDIUM / LOW / UNKNOWN | 0 / 0 / 0 | 428 / 148 / 9 |
| Trivy findings with a fixed version | 0 | 1,092 |

Netshoot findings split into 535 in Alpine packages and 560 in the five static
Go binaries (`ctop` 183, `termshark` 183, `grpcurl` 113, `calicoctl` 41,
`fortio` 40). Ten of the 13 CRITICAL findings are old Go standard libraries in those
binaries (`ctop` and `termshark` are built with Go 1.18). Removing the binaries and upgrading
the Alpine packages is why network-debug reported zero on the inspection date.
The counts are a snapshot of the Trivy database on 2026-11-07; new advisories
change them, so rescan before relying on them.

Both images default to UID 0. That default is not a tool requirement. Live
capture with `tcpdump` needs `NET_RAW` (root or the equivalent effective
capability), host tracing with `pwru` needs the capabilities listed under
`operationCapabilities` in `utils/network-debug/IMAGE-METADATA.yaml`, and
offline work such as reading a pcap or DNS and HTTP probes needs neither. The
[network-debug runbook](network-debug-image.md#safety-and-permissions) lists
the requirements per operation. A DebugSession profile should keep
`allowPrivilegeEscalation: false`, drop `ALL` and add back only the
capabilities of the selected operation, whichever image it uses. It does not
need extra privilege just because the image default is root.

## Recommendation

This section is a recommendation from the comparison above, not a
committed plan or a change made by this page.

In our assessment, network-debug can replace Netshoot in debug profiles today for DNS, routing,
transport, capture, netfilter and throughput investigations. To cover the
remaining realistic gap, add one tool:

- **grpcurl**, built from source with the pinned Go builder, as `pwru` already
  is, so that it does not bring back the CVEs of the upstream release binary.

Do not add `fortio`, `termshark`, `calicoctl` or `ctop`: they have no
breakglass use case that the image does not already cover, and they were the
source of half of Netshoot's findings.

After grpcurl is in a released image, switch the Netshoot references in
`config/samples/` (`debug_pod_templates.yaml`,
`debug-pod-template-comprehensive.yaml`, `debug_session_templates.yaml`,
`debug-session-template-comprehensive.yaml`,
`debug_session_template_namespace_selectors.yaml`) to the network-debug
digest. This page adds no tools.

The `inheritedRuntimeTools` and `inheritedCommands` lists in
`utils/network-debug/IMAGE-METADATA.yaml` name a subset of what the image
contains. All other Netshoot packages are also inherited, as the matrix shows.
