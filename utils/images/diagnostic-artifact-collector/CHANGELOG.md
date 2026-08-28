# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: CC-BY-4.0

# Changelog

All notable changes to this image are documented here.

## [Unreleased]

### Added

- Added immutable crashdump-collection.v1 and system-summary.v1 recipes.
- Added bounded archive, manifest, private output, and uploader hand-off
  contract with behavioral rejection of injected commands and unsafe source
  filesystem entries.

### Fixed

- Added a strict 30-second crashdump enumeration deadline, exact bounded
  failure diagnostics, and TERM-then-KILL process-group cleanup for `find`
  batches and descendants.
- Hardened uploads against symlink swaps, non-private files, empty bearer
  tokens, URL queries, and archive mutations during transfer.
- Rejected oversized signed PAX extension lengths before native-index
  conversion and retained the active no-follow archive-opening path.
- Raised the uploader tar-member envelope to cover all bounded collector source
  entries, fixed archive members, and one long-name extension per source path.
- Added the pinned builder CA bundle for verified HTTPS uploads and documented
  the mixed runtime identity/network boundary.
- Added source inode/size and copied-size checks, normalized bounded inputs in
  manifests, and a 480 MiB crashdump source ceiling below the 512 MiB archive
  ceiling.
- Enforced controller-provided archive caps and bounded upload timeouts in both
  collection and upload paths.
- Enforced recipe-specific archive ceilings (16 MiB for summaries and 512 MiB
  for crashdumps), fail-closed pipeline execution, exact ready-marker content,
  URL ForceQuery rejection, and bounded crashdump candidate/path traversal.
- Added descriptor-relative, no-follow, single-link safe copy with mount
  confinement and before/after content hashes; nested source mounts now fail
  closed.
- Pinned uploader trust to the image CA bundle, ignored ambient CA/proxy
  overrides, and enforced private manifest recipe ceilings and transfer hashes.
- Aligned built-in and optional internal documentation with the shared
  root-owned, read-only runbook mount contract.
