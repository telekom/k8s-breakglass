# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

# Third-party notices

The runtime is inherited from the immutable `ghcr.io/nicolaka/netshoot:v0.16`
manifest. netshoot's upstream package set (including its transitive Alpine
dependencies and their licenses) remains attributable to that image and is
represented in the final image SBOM. See the [netshoot source
repository](https://github.com/nicolaka/netshoot) and its Apache-2.0 license.

This image additionally redistributes the following Apache-2.0 projects as
statically built executables. Their source, release tag, and license are
recorded in `/usr/share/breakglass/runbooks/upstream/network-debug/versions.env` and in the image SBOM:

| Tool | Release | Source | License |
| --- | --- | --- | --- |
| pwru | v1.0.12 | <https://github.com/cilium/pwru> | Apache-2.0 |

The helper scripts and documentation are original project files under the
Apache-2.0 or CC-BY-4.0 headers shown in those files. This image does not
bundle proprietary or internal tooling.

`pod-netns-capture` is project-owned Apache-2.0 Go code. It uses only the Go
standard library and therefore adds no external Go module dependency; the
pinned Go builder remains recorded in `versions.env` and the generated SBOM.
