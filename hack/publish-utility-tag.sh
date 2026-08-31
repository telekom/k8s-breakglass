#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail

die() { printf 'utility tag publication: %s\n' "$*" >&2; exit 1; }

[[ $# == 3 ]] || die 'usage: publish-utility-tag.sh IMAGE TAG DIGEST'
image="$1"; tag="$2"; digest="$3"
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
"${root}/hack/utility-release-contract.sh" subject "${image}" "${digest}" >/dev/null ||
	die 'invalid utility image subject'
verify_script="${root}/hack/verify-utility-publication.sh"
[[ -x "${verify_script}" ]] || die "verification script is not executable: ${verify_script}"

# OCI Distribution defines manifest PUT by a tag as an assignment operation;
# it does not define an If-None-Match/create-only contract. GHCR therefore
# cannot provide the atomic stable-tag reservation this helper would need.
# Release builds use a unique dev-<commit>-<run>-<attempt> tag, or one of the
# intentionally mutable channels, and every consumer is given the digest.
if [[ "${tag}" != nightly && "${tag}" != rolling && ! "${tag}" =~ ^dev-[0-9a-f]{40}-[0-9]+-[0-9]+$ ]]; then
	die "stable release tags are not assigned; publish a unique dev tag and consume ${image}@${digest}"
fi

# The digest-only publication is the staging area. Full signature, SBOM,
# provenance, platform, and pull verification must succeed before a release-
# matched tag is ever created.
timeout 60m "${verify_script}" "${image}" "${digest}"

subject="${image}@${digest}"
timeout 5m docker buildx imagetools create --tag "${image}:${tag}" "${subject}"
attempt_limit=${UTILITY_TAG_VERIFY_ATTEMPTS:-30}
retry_delay=${UTILITY_TAG_VERIFY_DELAY_SECONDS:-2}
[[ "${attempt_limit}" =~ ^[0-9]+$ && "${retry_delay}" =~ ^[0-9]+$ ]] ||
	die 'tag verification retry settings must be non-negative integers'
[[ "${attempt_limit}" -gt 0 ]] || die 'tag verification requires at least one attempt'
for attempt in $(seq 1 "${attempt_limit}"); do
	if timeout 1m "${root}/hack/utility-publication.sh" require-tag "${image}" "${tag}" "${digest}"; then
		exit 0
	fi
	echo "Final tag verification attempt ${attempt}/${attempt_limit}"
	sleep "${retry_delay}"
done
die 'final tag did not remain bound to the attested digest'
