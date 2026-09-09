#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail

[[ $# == 2 || $# == 4 ]] || { echo 'usage: verify-utility-publication.sh IMAGE INDEX_DIGEST [SMOKE_COMMAND SMOKE_OUTPUT]' >&2; exit 2; }
image="$1"; digest="$2"; smoke_command="${3:-}"; smoke_output="${4:-}"
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
repo="${GITHUB_REPOSITORY:?}"; sha="${GITHUB_SHA:?}"; ref="${GITHUB_REF:?}"; workflow_ref="${GITHUB_WORKFLOW_REF:?}"
identity="https://github.com/${workflow_ref}"
[[ "${workflow_ref}" == "${repo}/.github/workflows/utility-release.yml@${ref}" ]] || { echo 'unexpected utility workflow identity' >&2; exit 1; }

required_tools=(jq docker cosign gh timeout)
for required_tool in "${required_tools[@]}"; do
  command -v "${required_tool}" >/dev/null 2>&1 || { echo "${required_tool} is required for utility publication verification" >&2; exit 2; }
done

subjects="$("${root}/hack/utility-publication.sh" platform-subjects "${image}" "${digest}")"
amd64_subject="$(sed -n 's/^amd64_subject=//p' <<<"${subjects}")"
arm64_subject="$(sed -n 's/^arm64_subject=//p' <<<"${subjects}")"
index_subject="${image}@${digest}"

for signed_subject in "${index_subject}" "${amd64_subject}" "${arm64_subject}"; do
  timeout 5m cosign verify "${signed_subject}" --certificate-identity="${identity}" \
    --certificate-oidc-issuer=https://token.actions.githubusercontent.com >/dev/null
done
for sbom_subject in "${amd64_subject}" "${arm64_subject}"; do
  timeout 5m cosign verify-attestation "${sbom_subject}" --type spdxjson \
    --certificate-identity="${identity}" \
    --certificate-oidc-issuer=https://token.actions.githubusercontent.com >/dev/null
done
for provenance_subject in "${index_subject}" "${amd64_subject}" "${arm64_subject}"; do
  timeout 5m gh attestation verify "oci://${provenance_subject}" --repo "${repo}" \
    --signer-workflow "${repo}/.github/workflows/utility-release.yml" \
    --signer-digest "${sha}" --source-digest "${sha}" --source-ref "${ref}" >/dev/null
done
for pair in "linux/amd64=${amd64_subject}" "linux/arm64=${arm64_subject}"; do
  platform="${pair%%=*}"; subject="${pair#*=}"
  timeout 10m docker pull --platform "${platform}" "${subject}" >/dev/null
  [[ "$(docker image inspect --format '{{.Os}}/{{.Architecture}}' "${subject}")" == "${platform}" ]] || { echo "wrong pulled platform for ${subject}" >&2; exit 1; }
done

# Pulling and inspecting a digest proves identity only. When a smoke contract
# is supplied, execute it against each exact platform subject before a tag is
# assigned. Keep the command/output contract data-driven from the image
# inventory and never substitute a mutable tag.
if [[ -n "${smoke_command}" || -n "${smoke_output}" ]]; then
  [[ -n "${smoke_command}" && -n "${smoke_output}" ]] || { echo 'smoke command and expected output must be supplied together' >&2; exit 2; }
  command -v jq >/dev/null 2>&1 || { echo 'jq is required for the smoke command contract' >&2; exit 2; }
  smoke_args=()
  while IFS= read -r -d '' argument; do smoke_args+=("${argument}"); done < <(jq -j '.[] + "\u0000"' <<<"${smoke_command}")
  [[ "${#smoke_args[@]}" -gt 0 ]] || { echo 'smoke command must contain at least one argument' >&2; exit 2; }
  for pair in "linux/amd64=${amd64_subject}" "linux/arm64=${arm64_subject}"; do
    platform="${pair%%=*}"; subject="${pair#*=}"
    smoke_log="${RUNNER_TEMP:-/tmp}/utility-smoke-${platform##*/}.log"
    timeout 5m docker run --rm --platform "${platform}" "${subject}" "${smoke_args[@]}" >"${smoke_log}" 2>&1 || {
      cat "${smoke_log}" >&2
      echo "exact published digest smoke failed for ${platform}" >&2
      exit 1
    }
    grep -F -- "${smoke_output}" "${smoke_log}" >/dev/null || {
      cat "${smoke_log}" >&2
      echo "exact published digest smoke output mismatch for ${platform}" >&2
      exit 1
    }
  done
fi
