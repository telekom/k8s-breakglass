#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
dockerfile="${root}/Dockerfile"
versions="${root}/versions.env"

tools_mod="${root}/pwru/go.mod"
tools_sum="${root}/pwru/go.sum"

fail() {
	printf '%s\n' "$1" >&2
	exit 1
}

# pwru and its module graph are owned by the Dependabot-tracked pwru/go.mod;
# go.sum is the integrity anchor for every module, including pwru itself.
grep -Fx 'tool github.com/cilium/pwru' "${tools_mod}" >/dev/null ||
	fail 'pwru/go.mod must declare pwru as a tool'
pwru_version="$(awk '$1 == "github.com/cilium/pwru" { print $2 }' "${tools_mod}")"
[[ "${pwru_version}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'pwru/go.mod must require a released pwru version'
grep -E "^github\.com/cilium/pwru ${pwru_version} h1:[A-Za-z0-9+/]+=+\$" "${tools_sum}" >/dev/null ||
	fail 'pwru/go.sum must authenticate the required pwru module'
x_net_version="$(awk '$1 == "golang.org/x/net" { print $2 }' "${tools_mod}")"
[[ "${x_net_version}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'pwru/go.mod must select golang.org/x/net'

grep -F 'COPY pwru/go.mod pwru/go.sum /src/tools/' "${dockerfile}" >/dev/null ||
	fail 'network-debug Dockerfile must build from pwru/go.mod and pwru/go.sum'
grep -F 'go mod edit -replace github.com/cilium/pwru=/src/pwru' "${dockerfile}" >/dev/null ||
	fail 'network-debug Dockerfile must build pwru against the tracked module graph'
grep -F "pwru.Version=\${pwru_version}" "${dockerfile}" >/dev/null
grep -F 'mkdir -p /src/pwru /out' "${dockerfile}" >/dev/null ||
	fail 'network-debug Dockerfile must create its output directory'
if grep -E 'ARG (PWRU_|X_NET_)|go (-C [^ ]+ )?get |go work |GOSUMDB=off|GONOSUMCHECK|GONOSUMDB|GOINSECURE|GOFLAGS=.*-mod=mod' "${dockerfile}" >/dev/null; then
	fail 'network-debug Dockerfile must not override or weaken the tracked pwru module graph'
fi
grep -F 'PWRU_BUILD_POLICY=go-module-from-tracked-go-sum-built-with-pinned-toolchain' "${versions}" >/dev/null
base_alpine_version="$(awk -F= '$1 == "BASE_ALPINE_VERSION" { print $2 }' "${versions}")"
grep -F "ARG NETSHOOT_ALPINE_VERSION=${base_alpine_version}" "${dockerfile}" >/dev/null
[[ "${base_alpine_version}" =~ ^[0-9]+\.[0-9]+$ ]] || {
	printf '%s\n' 'netshoot Alpine release series is invalid' >&2
	exit 1
}

printf '%s\n' 'network-debug immutable source contract passed'
