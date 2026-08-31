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

# The digest-only publication is the staging area. Full signature, SBOM,
# provenance, platform, and pull verification must succeed before a release-
# matched tag is ever created.
timeout 60m "${verify_script}" "${image}" "${digest}"

# Keep the stable-tag collision check immediately adjacent to the mutation.
# Mutable channels intentionally skip this check, but still pass the same
# pre-tag verification above and the post-write binding check below.
if [[ "${tag}" != nightly && "${tag}" != rolling ]]; then
	state="$(timeout 1m "${root}/hack/utility-publication.sh" tag-state "${image}" "${tag}")"
	[[ "${state}" == missing ]] || die "refusing to overwrite existing utility tag ${image}:${tag} (state: ${state})"
fi

subject="${image}@${digest}"
timeout 5m docker buildx imagetools create --tag "${image}:${tag}" "${subject}"
for attempt in $(seq 1 30); do
	if timeout 1m "${root}/hack/utility-publication.sh" require-tag "${image}" "${tag}" "${digest}"; then
		exit 0
	fi
	echo "Final tag verification attempt ${attempt}/30"
	sleep 2
done
die 'final tag did not remain bound to the attested digest'
