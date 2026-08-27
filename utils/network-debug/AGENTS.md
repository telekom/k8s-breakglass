<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
-->

# Network-debug image instructions

Selected-pod capture is an approved controller operation that injects a
bounded ephemeral container into the selected Pod. Keep it independent of
requester-authored commands and fields.

- Never accept a PID, pod name, namespace, node name, executable, raw argv,
  output directory, or capability override from the caller.
- The ephemeral capture must target the approved Pod/container through the
  Kubernetes subresource, use `hostPID: false` and `hostNetwork: false`, and
  add only `NET_RAW` after dropping all capabilities.
- Do not mount or inspect host paths, cgroup trees, or CRI sockets. Use one
  exact `emptyDir` evidence mount and verify `privileged: false`, token
  automount disabled, and no runtime socket mounts after admission.
- Keep capture duration, packet count, snaplen, filter, output filename, and
  file size bounded. Successful stdout is metadata/hash only, never packets.
- Run the fake-proc unit/fuzz corpus and the separate Linux/kind behavioral
  workflow. Kernel/capability/cgroup prerequisites must fail loudly, not skip.
