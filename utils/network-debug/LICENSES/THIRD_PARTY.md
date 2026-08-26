# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

# Third-party notices

This image redistributes the following Apache-2.0 projects as statically built
executables. Their source, release tag, and license are recorded in
`/usr/share/network-debug/versions.env` and in the image SBOM:

| Tool | Release | Source | License |
| --- | --- | --- | --- |
| kubestr | v0.4.49 | <https://github.com/kastenhq/kubestr> | Apache-2.0 |
| pwru | v1.0.12 | <https://github.com/cilium/pwru> | Apache-2.0 |

The runtime utilities are Alpine Linux packages from the digest-pinned Alpine
3.24 repositories. Their upstream license metadata is available from Alpine's
package index. This image does not bundle proprietary or internal tooling.
