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
deny_pattern 'helm show chart .*([[:space:]]*2>[[:space:]]*/dev/null|>[[:space:]]*/dev/null[[:space:]]*2>&1)' \
  "Helm chart publishing must not suppress remote chart lookup errors"
deny_pattern 'CHART_(VERSION|APP_VERSION)="\$\(helm show chart' \
  "release workflow must capture packaged Helm chart metadata once before extracting fields"
deny_pattern 'grep -Eiq .*no such' \
  "Helm chart missing classifier must not treat DNS/network no-such-host errors as chart-not-present"
deny_pattern 'already present in GHCR; skipping push' \
  "Helm chart publishing must not skip existing chart versions without checking appVersion"

require_pattern 'docker buildx imagetools inspect "\$\{IMG\}"' \
  "release workflow must inspect the pushed image through the registry"
require_pattern 'Digest:\[\[:space:\]\][+]sha256:\[0-9a-f\][{]64[}]' \
  "release workflow must parse a strict sha256 registry Digest line"
require_pattern 'Could not determine registry digest' \
  "release workflow must fail when the registry digest cannot be determined"
require_pattern 'subject-digest: \$\{\{ steps\.inspect\.outputs\.digest \}\}' \
  "release provenance attestation must use the inspected registry digest output"
require_pattern 'CHART_APP_VERSION=' \
  "release workflow must read the packaged Helm chart appVersion"
require_pattern 'CHART_METADATA="\$\(helm show chart "\$\{CHART_PACKAGE\}"\)"' \
  "release workflow must capture packaged Helm chart metadata once"
require_pattern '\[ "\$\{CHART_APP_VERSION\}" != "\$\{RELEASE_TAG\}" \]' \
  "release workflow must fail when packaged Helm chart appVersion does not match the release tag"
require_pattern 'REMOTE_APP_VERSION=' \
  "release workflow must read the remote Helm chart appVersion before skipping an existing chart version"
require_pattern 'Failed to determine remote escalation-config:\$\{CHART_VERSION\} appVersion from GHCR metadata' \
  "release workflow must fail clearly when remote chart metadata lacks appVersion"
require_pattern 'REMOTE_CHART_LOOKUP_STATUS=' \
  "release workflow must preserve the remote chart lookup exit status"
require_pattern 'Failed to inspect existing escalation-config' \
  "release workflow must fail real remote chart lookup errors before publishing"
require_pattern 'grep -Eiq.*manifest unknown' \
  "release workflow must classify Helm/GHCR missing-chart errors without broad network-error matches"
require_pattern '\[ "\$\{REMOTE_APP_VERSION\}" = "\$\{CHART_APP_VERSION\}" \]' \
  "release workflow must skip chart publication only when remote and packaged appVersion match"
require_pattern 'Bump charts/escalation-config/Chart.yaml version before releasing' \
  "release workflow must fail clearly when a chart version already exists with a different appVersion"

if [ "${failures}" -ne 0 ]; then
  exit 1
fi

echo "Release provenance workflow guard passed"
