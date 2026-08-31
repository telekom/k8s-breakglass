#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

# Resolve the catalogue's public utility tags once, before release preparation,
# and transfer only the resulting immutable manifest digests to that job.
# Consumers of this directory must never fall back to the mutable chart tags.

set -Eeuo pipefail

values_file="${1:?catalogue values file is required}"
output_dir="${2:?release reference directory is required}"

[[ -f "${values_file}" ]] || { echo "catalogue values file is missing: ${values_file}" >&2; exit 1; }
command -v ruby >/dev/null 2>&1 || { echo "ruby is required" >&2; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "docker is required" >&2; exit 1; }
command -v cosign >/dev/null 2>&1 || { echo "cosign is required" >&2; exit 1; }

identity_regexp="${SUPPLY_CHAIN_IDENTITY_REGEXP:-https://github.com/telekom/k8s-breakglass/.github/workflows/.*}"
oidc_issuer="${SUPPLY_CHAIN_OIDC_ISSUER:-https://token.actions.githubusercontent.com}"

records=()
while IFS= read -r record; do
  records+=("${record}")
done < <(ruby -ryaml -e '
  values = YAML.safe_load(File.read(ARGV.fetch(0)), aliases: false) || {}
  images = values.fetch("images")
  %w[workload network storage networkRepair diagnosticArtifactCollector].each do |key|
    image = images.fetch(key)
    repository = image.fetch("repository").to_s
    tag = image.fetch("tag", "").to_s
    digest = image.fetch("digest", "").to_s
    abort("#{key} repository must use the canonical GHCR path") unless repository.start_with?("ghcr.io/telekom/k8s-breakglass/") && repository !~ /[[:space:]@]/
    abort("#{key} must specify either a tag or digest") if tag.empty? && digest.empty?
    abort("#{key} cannot specify both tag and digest") unless tag.empty? || digest.empty?
    abort("#{key} digest is not immutable") unless digest.empty? || digest.match?(/\Asha256:[0-9a-f]{64}\z/)
    abort("#{key} tag contains unsafe characters") unless tag.empty? || tag.match?(/\A[0-9A-Za-z._-]+\z/)
    name = {"networkRepair" => "node", "diagnosticArtifactCollector" => "diagnostic-artifact-collector"}.fetch(key, key)
    puts [name, repository, tag, digest].join("|")
  end
' "${values_file}")

[ "${#records[@]}" -eq 5 ] || { echo "expected five public utility image records" >&2; exit 1; }
mkdir -p "${output_dir}"
tmp_dir="$(mktemp -d "${output_dir}.tmp.XXXXXX")"
trap 'rm -rf "${tmp_dir}"' EXIT

for record in "${records[@]}"; do
  IFS='|' read -r name repository tag digest <<<"${record}"
  if [[ -z "${digest}" ]]; then
    digests=()
    while IFS= read -r resolved_digest; do
      digests+=("${resolved_digest}")
    done < <(docker buildx imagetools inspect "${repository}:${tag}" | awk '/^Digest:[[:space:]]+sha256:[0-9a-f]{64}$/ { print $2 }')
    [ "${#digests[@]}" -eq 1 ] || {
      echo "expected exactly one manifest digest for ${repository}:${tag}" >&2
      exit 1
    }
    digest="${digests[0]}"
  fi
  [[ "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]] || {
    echo "resolved non-immutable digest for ${name}: ${digest}" >&2
    exit 1
  }
  subject="${repository}@${digest}"
  cosign verify "${subject}" \
    --certificate-identity-regexp="${identity_regexp}" \
    --certificate-oidc-issuer="${oidc_issuer}" >/dev/null
  cosign verify-attestation "${subject}" --type spdxjson \
    --certificate-identity-regexp="${identity_regexp}" \
    --certificate-oidc-issuer="${oidc_issuer}" >/dev/null
  cosign verify-attestation "${subject}" --type slsaprovenance1 \
    --certificate-identity-regexp="${identity_regexp}" \
    --certificate-oidc-issuer="${oidc_issuer}" >/dev/null
  printf '%s|%s|%s|verified|verified|verified\n' "${name}" "${repository}" "${digest}" >"${tmp_dir}/${name}.ref"
  chmod 600 "${tmp_dir}/${name}.ref"
done

# Replace the destination only after every reference has passed validation.
rm -f "${output_dir}"/*.ref
mv "${tmp_dir}"/*.ref "${output_dir}/"
trap - EXIT
