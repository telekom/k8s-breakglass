<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# Network-debug image instructions

The image owns the `pod-netns-capture` security boundary. Keep it independent
of controller/chart request fields: the later server-owned workload may pass
only an immutable Pod UID and the documented bounded capture parameters.

- Never accept a PID, pod name, namespace, node name, tcpdump executable, raw
  argv, proc root, output directory, or capability override from the caller.
- Keep procfs matching exact and fail closed for unknown cgroup/runtime layouts,
  confusable UID substrings, unsupported container scopes, target churn, and
  multiple network namespace inodes. Private cgroup namespaces may contribute
  only the bounded leading `..` run covered by adversarial tests.
- Open the selected network namespace before the final process start-time and
  cgroup revalidation. Keep the single `setns` call and literal no-shell
  tcpdump argv (`-p`) reviewable.
- Do not mount or inspect CRI sockets. The intended pod has `hostPID: true`,
  `hostNetwork: false`, an `emptyDir` at `/work`, and only `SYS_ADMIN`,
  `SYS_PTRACE`, and `NET_RAW` for this operation.
- Keep capture duration, packet count, snaplen, filter, output filename, and
  file size bounded. Successful stdout is metadata/hash only, never packets.
- Run the fake-proc unit/fuzz corpus and the separate Linux/kind behavioral
  workflow. Kernel/capability/cgroup prerequisites must fail loudly, not skip.
