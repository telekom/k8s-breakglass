#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

release_workflow="${1:-.github/workflows/release.yml}"
failures=0

if [ ! -f "${release_workflow}" ]; then
  echo "::error file=${release_workflow}::release workflow not found" >&2
  exit 1
fi

deny_pattern() {
  local pattern="$1"
  local description="$2"

  if grep -nE -- "${pattern}" "${release_workflow}"; then
    echo "::error file=${release_workflow}::${description}" >&2
    failures=$((failures + 1))
  fi
}

require_pattern() {
  local pattern="$1"
  local description="$2"

  if ! grep -qE -- "${pattern}" "${release_workflow}"; then
    echo "::error file=${release_workflow}::${description}" >&2
    failures=$((failures + 1))
  fi
}

deny_pattern '--raw[[:space:]]*\|[[:space:]]*sha256sum' \
  "release provenance must not hash raw manifest JSON to derive the signed digest"
deny_pattern 'RAW_MANIFEST_DIGEST' \
  "release provenance must not keep a raw-manifest digest fallback"
deny_pattern 'Digest cross-check mismatch' \
  "release digest mismatches must fail instead of warning"
deny_pattern 'DIGEST="\$\{RAW_MANIFEST_DIGEST\}"' \
  "release provenance must not sign or attest a computed raw-manifest digest"
deny_pattern 'github\.run_started_at' \
  "github.run_started_at is not a valid GitHub Actions context property"

require_pattern 'docker buildx imagetools inspect "\$\{IMG\}"' \
  "release workflow must inspect the pushed image through the registry"
require_pattern 'Digest:\[\[:space:\]\]\+sha256:\[0-9a-f\]\{64\}' \
  "release workflow must parse a strict sha256 registry Digest line"
require_pattern 'Could not determine registry digest' \
  "release workflow must fail when the registry digest cannot be determined"
require_pattern 'subject-digest: \$\{\{ steps\.inspect\.outputs\.digest \}\}' \
  "release provenance attestation must use the inspected registry digest output"

if [ "${failures}" -ne 0 ]; then
  exit 1
fi

echo "Release provenance workflow guard passed"
