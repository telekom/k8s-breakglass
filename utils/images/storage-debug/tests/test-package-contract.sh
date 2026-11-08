#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

# Package contract: the digest-pinned base (Dependabot docker) and
# kubestr/go.mod + go.sum (Dependabot gomod) are the only version inputs.
# Alpine package versions are not pinned; the installed set is recorded at
# build time instead.
set -Eeuo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
dockerfile="${root}/Dockerfile"
tools_mod="${root}/kubestr/go.mod"

fail() {
	printf '%s\n' "$1" >&2
	exit 1
}

grep -E '^FROM alpine:[0-9.]+@sha256:[0-9a-f]{64}$' "${dockerfile}" >/dev/null ||
	fail 'storage-debug runtime base must be digest-pinned'
grep -F 'apk upgrade --no-cache' "${dockerfile}" >/dev/null ||
	fail 'storage-debug must refresh the inherited package set from the base release'
grep -F 'apk add --no-cache fio ioping' "${dockerfile}" >/dev/null ||
	fail 'storage-debug must install fio and ioping'
if grep -E 'apk add[^&]*=|ARG [A-Z0-9_]+_VERSION=' "${dockerfile}" >/dev/null; then
	fail 'storage-debug must not pin package or Go module versions outside Dependabot-tracked manifests'
fi
if grep -F -- '--repository' "${dockerfile}" >/dev/null; then
	fail 'storage-debug must not force a separate package repository'
fi
grep -F 'apk list --installed --no-network > /usr/share/breakglass/installed-packages' "${dockerfile}" >/dev/null ||
	fail 'storage-debug must record the installed package versions'

grep -Fx 'tool github.com/kastenhq/kubestr' "${tools_mod}" >/dev/null ||
	fail 'kubestr/go.mod must declare kubestr as a tool'
kubestr_version="$(awk '$1 == "github.com/kastenhq/kubestr" { print $2 }' "${tools_mod}")"
[[ "${kubestr_version}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || fail 'kubestr/go.mod must require a released kubestr version'
grep -E "^github\.com/kastenhq/kubestr ${kubestr_version} h1:" "${root}/kubestr/go.sum" >/dev/null ||
	fail 'kubestr/go.sum must authenticate the required kubestr module'
grep -F 'COPY kubestr/go.mod kubestr/go.sum /src/tools/' "${dockerfile}" >/dev/null ||
	fail 'storage-debug must build kubestr from the tracked module lock'
grep -F 'go mod edit -replace github.com/kastenhq/kubestr=/src/kubestr' "${dockerfile}" >/dev/null ||
	fail 'storage-debug must build kubestr against the tracked module graph'
if grep -E 'go (-C [^ ]+ )?get |go work |GOSUMDB=off|GONOSUMCHECK|GONOSUMDB|GOINSECURE|-mod=mod' "${dockerfile}" >/dev/null; then
	fail 'storage-debug must not override or weaken the tracked kubestr module graph'
fi
printf '%s\n' 'storage-debug package contract passed'
