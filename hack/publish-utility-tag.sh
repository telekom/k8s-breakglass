#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail

die() { printf 'utility tag publication: %s\n' "$*" >&2; exit 1; }

[[ $# == 3 ]] || die 'usage: publish-utility-tag.sh IMAGE TAG DIGEST'
image="$1"; tag="$2"; digest="$3"
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
stable_manifest_dir=

"${root}/hack/utility-release-contract.sh" subject "${image}" "${digest}" >/dev/null ||
	die 'invalid utility image subject'
verify_script="${root}/hack/verify-utility-publication.sh"
[[ -x "${verify_script}" ]] || die "verification script is not executable: ${verify_script}"

publish_stable_tag_create_only() {
	local repository token_json bearer media_type status
	command -v curl >/dev/null 2>&1 || die 'curl is required for create-only stable tag publication'
	command -v jq >/dev/null 2>&1 || die 'jq is required for create-only stable tag publication'
	[[ "${image}" =~ ^ghcr\.io/(.+)$ ]] || die 'stable tag publication only supports GHCR images'
	repository="${BASH_REMATCH[1]}"
	token="${GH_TOKEN:-${GITHUB_TOKEN:-}}"
	[[ -n "${token}" && -n "${GITHUB_ACTOR:-}" ]] || die 'GH_TOKEN/GITHUB_TOKEN and GITHUB_ACTOR are required for create-only stable tag publication'
	stable_manifest_dir="$(mktemp -d "${RUNNER_TEMP:-/tmp}/utility-tag-manifest.XXXXXX")"
	trap 'if [[ -n "${stable_manifest_dir:-}" ]]; then rm -rf -- "${stable_manifest_dir}"; fi' EXIT
	token_json="$(curl --fail --silent --show-error --connect-timeout 10 --max-time 60 \
		--user "${GITHUB_ACTOR}:${token}" --get \
		--data-urlencode 'service=ghcr.io' \
		--data-urlencode "scope=repository:${repository}:pull,push" \
		https://ghcr.io/token)" || die 'could not obtain GHCR registry token'
	bearer="$(jq -er '.token // .access_token // empty' <<<"${token_json}")" || die 'GHCR token response did not contain a bearer token'
	curl --fail --silent --show-error --connect-timeout 10 --max-time 60 \
		-H "Authorization: Bearer ${bearer}" \
		-H 'Accept: application/vnd.oci.image.index.v1+json, application/vnd.docker.distribution.manifest.list.v2+json' \
		-D "${stable_manifest_dir}/headers" \
		-o "${stable_manifest_dir}/manifest" \
		"https://ghcr.io/v2/${repository}/manifests/${digest}" || die 'could not read the immutable manifest for create-only publication'
	[ -s "${stable_manifest_dir}/manifest" ] || die 'registry returned an empty immutable manifest'
	media_type="$(awk 'BEGIN {IGNORECASE=1} /^Content-Type:/ {sub(/^[^:]*:[[:space:]]*/, ""); sub(/[[:space:]]*;.*$/, ""); print; exit}' "${stable_manifest_dir}/headers")"
	[[ "${media_type}" == application/vnd.oci.image.index.v1+json || "${media_type}" == application/vnd.docker.distribution.manifest.list.v2+json ]] || die "registry returned unsupported manifest media type: ${media_type:-empty}"
	status="$(curl --silent --show-error --connect-timeout 10 --max-time 60 \
		-X PUT -H "Authorization: Bearer ${bearer}" -H "Content-Type: ${media_type}" \
		-H 'If-None-Match: *' --data-binary "@${stable_manifest_dir}/manifest" \
		-o /dev/null -w '%{http_code}' \
		"https://ghcr.io/v2/${repository}/manifests/${tag}")" || die 'create-only stable tag request failed'
	[[ "${status}" == 201 ]] || die "registry did not accept create-only stable tag publication (HTTP ${status})"
}

# Check a stable tag before the potentially long verification stage. This
# makes an occupied release tag fail fast on macOS and CI while retaining the
# same create-only check immediately before the mutation below.
stable_tag=false
if [[ "${tag}" != nightly && "${tag}" != rolling ]]; then
	stable_tag=true
	state="$(timeout 1m "${root}/hack/utility-publication.sh" tag-state "${image}" "${tag}")"
	[[ "${state}" == missing ]] || die "refusing to overwrite existing utility tag ${image}:${tag} (state: ${state})"
fi

# The digest-only publication is the staging area. Full signature, SBOM,
# provenance, platform, and pull verification must succeed before a release-
# matched tag is ever created.
timeout 60m "${verify_script}" "${image}" "${digest}"

# Mutable channels intentionally skip the collision check, but still pass the
# same pre-tag verification above and the post-write binding check below.
if [[ "${stable_tag}" == true ]]; then
	publish_stable_tag_create_only
else
	subject="${image}@${digest}"
	timeout 5m docker buildx imagetools create --tag "${image}:${tag}" "${subject}"
fi
for attempt in $(seq 1 30); do
	if timeout 1m "${root}/hack/utility-publication.sh" require-tag "${image}" "${tag}" "${digest}"; then
		exit 0
	fi
	echo "Final tag verification attempt ${attempt}/30"
	sleep 2
done
die 'final tag did not remain bound to the attested digest'
