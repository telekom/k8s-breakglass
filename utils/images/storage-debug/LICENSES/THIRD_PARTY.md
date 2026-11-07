<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: CC-BY-4.0
-->

# Third-party notices

The runtime packages `fio` and `ioping` are installed from the repositories of
the digest-pinned Alpine 3.24 base. The installed versions are recorded in
`/usr/share/breakglass/installed-packages` and the image SBOM.

The image also redistributes `kubestr` under Apache-2.0, built from the module
version selected by `kubestr/go.mod` and authenticated by `kubestr/go.sum`
(recorded in `/usr/share/breakglass/kubestr-build-info`). Its source is
<https://github.com/kastenhq/kubestr>.

The final multi-architecture image is published with SPDX SBOM and provenance
attestations. Inspect those attestations for the complete transitive license
inventory.
