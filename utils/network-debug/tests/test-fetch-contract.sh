#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
dockerfile="${root}/Dockerfile"
versions="${root}/versions.env"

grep -F 'COPY tools/fetch.go /src/fetch.go' "${dockerfile}" >/dev/null
grep -F 'verified-fetch' "${dockerfile}" >/dev/null
if grep -F 'git clone' "${dockerfile}" >/dev/null; then
	printf '%s\n' 'network-debug Dockerfile must not clone mutable source' >&2
	exit 1
fi
if grep -E 'PWRU_VERSION\}/|PWRU_VERSION=v' "${dockerfile}" >/dev/null && \
	! grep -F 'PWRU_SHA256_AMD64=' "${dockerfile}" >/dev/null; then
	printf '%s\n' 'network-debug release asset is missing an immutable digest' >&2
	exit 1
fi
for digest in PWRU_ASSET_SHA256_AMD64 PWRU_ASSET_SHA256_ARM64; do
	value="$(awk -F= -v key="${digest}" '$1 == key { print $2 }' "${versions}")"
	[[ "${value}" =~ ^[0-9a-f]{64}$ ]] || {
		printf 'invalid %s in versions.env\n' "${digest}" >&2
		exit 1
	}
	docker_arg="PWRU_${digest#PWRU_ASSET_}"
	grep -F "ARG ${docker_arg}=${value}" "${dockerfile}" >/dev/null || {
		printf '%s is not synchronized with Dockerfile\n' "${digest}" >&2
		exit 1
	}
done
grep -F 'PWRU_BUILD_POLICY=https-only-github-release-asset-at-pinned-sha256' "${versions}" >/dev/null
base_alpine_version="$(awk -F= '$1 == "BASE_ALPINE_VERSION" { print $2 }' "${versions}")"
grep -F "ARG NETSHOOT_ALPINE_VERSION=${base_alpine_version}" "${dockerfile}" >/dev/null
[[ "${base_alpine_version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
	printf '%s\n' 'netshoot Alpine compatibility version is invalid' >&2
	exit 1
}

printf '%s\n' 'network-debug immutable fetch contract passed'
