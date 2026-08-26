<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# Network debug image runbook

Use the network-debug utility image when a connectivity problem must be
observed from the same network namespace as a workload or node. Start with
`net-report`, then narrow the investigation to one question: name resolution,
route selection, transport connectivity, packet capture, or kernel path.

## Suggested sequence

1. Run `net-report` and save the output to a protected incident location.
2. Check DNS with `dig +short`, route selection with `ip route get ADDRESS`,
   and transport reachability with `nc -vz HOST PORT` or `curl -v`.
3. Capture only the required interface and filter:
   `tcpdump -ni eth0 -s 128 -w /work/capture.pcap 'host ADDRESS and port PORT'`.
4. If the packet is not visible at the expected kernel hook, check the host
   kernel requirements with `pwru --help` and run a narrowly scoped filter.
5. Remove captures after the incident retention period; packet data can contain
   credentials and personal data.

## Safety and permissions

The image is root because `tcpdump` and `pwru` need kernel access. Prefer an
ephemeral container with only `CAP_NET_RAW` and `CAP_NET_ADMIN`; eBPF tracing
may additionally require BPF/perfmon permissions, a mounted debugfs, and a
kernel with BTF. Follow the target cluster's Pod Security policy. Never copy a
capture to a public tracker without redaction.

`kubestr` talks to the Kubernetes API and may create short-lived diagnostic
resources for its selected command. Use a read-only service account unless a
specific kubestr check documents a narrower write permission. The image itself
does not contain `kubectl`, credentials, or a kubeconfig.

## Reproducible evidence

`net-report` sorts interfaces, routes, rules, DNS servers, and tool names. It
omits timestamps, hostnames, and random IDs, making two reports easy to diff.
Runtime values are still expected to change with network namespace state. Keep
the image tag and final manifest digest alongside any evidence; image tags are
human-readable selectors, while the digest is the reproducible artifact.

See [`utils/network-debug/README.md`](../utils/network-debug/README.md) for the
tool lock record, license notices, and BuildKit SBOM/provenance commands.
