#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
dockerfile="${root}/Dockerfile"
versions="${root}/versions.env"

grep -F "go mod download -json \"github.com/cilium/pwru@\${PWRU_VERSION}\"" "${dockerfile}" >/dev/null
grep -F "make VERSION=\"\${PWRU_VERSION}\"" "${dockerfile}" >/dev/null
grep -F 'mkdir -p /src/pwru /out' "${dockerfile}" >/dev/null || {
	printf '%s\n' 'network-debug Dockerfile must create its source and output directories' >&2
	exit 1
}
module_sum="$(sed -n 's/^PWRU_MODULE_SUM=//p' "${versions}")"
[[ "${module_sum}" =~ ^h1:[A-Za-z0-9+/]+=+$ ]] || {
	printf '%s\n' 'invalid PWRU_MODULE_SUM in versions.env' >&2
	exit 1
}
grep -F "ARG PWRU_MODULE_SUM=${module_sum}" "${dockerfile}" >/dev/null || {
	printf '%s\n' 'PWRU_MODULE_SUM is not synchronized with Dockerfile' >&2
	exit 1
}
commit="$(awk -F= '$1 == "PWRU_COMMIT" { print $2 }' "${versions}")"
[[ "${commit}" =~ ^[0-9a-f]{40}$ ]] || {
	printf '%s\n' 'invalid PWRU_COMMIT in versions.env' >&2
	exit 1
}
grep -F "ARG PWRU_COMMIT=${commit}" "${dockerfile}" >/dev/null || {
	printf '%s\n' 'PWRU_COMMIT is not synchronized with Dockerfile' >&2
	exit 1
}
grep -F 'PWRU_BUILD_POLICY=go-module-at-pinned-sum-built-with-pinned-toolchain' "${versions}" >/dev/null
base_alpine_version="$(awk -F= '$1 == "BASE_ALPINE_VERSION" { print $2 }' "${versions}")"
grep -F "ARG NETSHOOT_ALPINE_VERSION=${base_alpine_version}" "${dockerfile}" >/dev/null
[[ "${base_alpine_version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
	printf '%s\n' 'netshoot Alpine compatibility version is invalid' >&2
	exit 1
}

printf '%s\n' 'network-debug immutable source contract passed'
