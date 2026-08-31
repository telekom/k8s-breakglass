#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

refs_dir="${1:?utility reference directory is required}"
output_file="${2:?release values output file is required}"

shopt -s nullglob
refs=("${refs_dir}"/*.ref)
[ "${#refs[@]}" -gt 0 ] || {
  echo "No utility release references found in ${refs_dir}" >&2
  exit 1
}

tmp_file="$(mktemp)"
trap 'rm -f "${tmp_file}"' EXIT
printf 'images:\n' >"${tmp_file}"
seen_names=""
for ref in "${refs[@]}"; do
  IFS='|' read -r name repository digest signature sbom provenance remainder <"${ref}"
  [ -z "${remainder:-}" ] || { echo "Malformed utility release reference: ${ref}" >&2; exit 1; }
  [ -n "${name}" ] || { echo "Utility release reference has no name: ${ref}" >&2; exit 1; }
  [[ "${name}" =~ ^[a-z-]+$ ]] || { echo "Invalid utility release name: ${name}" >&2; exit 1; }
  case "|${seen_names}|" in
    *"|${name}|"*) echo "Duplicate utility release reference: ${name}" >&2; exit 1 ;;
  esac
  seen_names="${seen_names}|${name}"
  [[ "${repository}" == ghcr.io/telekom/k8s-breakglass/* ]] || {
    echo "Unexpected utility repository: ${repository}" >&2
    exit 1
  }
  [[ "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo "Invalid utility digest for ${name}: ${digest}" >&2
    exit 1
  }
  [ "${signature:-}" = verified ] && [ "${sbom:-}" = verified ] && [ "${provenance:-}" = verified ] || {
    echo "Missing verified signature, SBOM, or provenance evidence for ${name}" >&2
    exit 1
  }
  case "${name}" in
    workload|network|storage) key="${name}" ;;
    node)
      key=nodeRecovery
      printf '  networkRepair:\n    repository: "%s"\n    digest: "%s"\n' "${repository}" "${digest}" >>"${tmp_file}"
      ;;
    diagnostic-artifact-collector) key=diagnosticArtifactCollector ;;
    *) echo "Unexpected utility release record: ${name}" >&2; exit 1 ;;
  esac
  printf '  %s:\n    repository: "%s"\n    digest: "%s"\n' "${key}" "${repository}" "${digest}" >>"${tmp_file}"
done

ruby -ryaml -e '
  values = YAML.safe_load(File.read(ARGV.fetch(0)), aliases: false)
  expected = %w[workload network storage networkRepair nodeRecovery diagnosticArtifactCollector].sort
  actual = values.fetch("images").keys.sort
  abort("release image set mismatch: #{actual.inspect}") unless actual == expected
' "${tmp_file}"
mv "${tmp_file}" "${output_file}"
trap - EXIT
