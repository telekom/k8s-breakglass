#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
dockerfile="${root}/Dockerfile"

grep -F "\"fio=\${FIO_VERSION}\"" "${dockerfile}" >/dev/null
grep -F "\"ioping=\${IOPING_VERSION}\"" "${dockerfile}" >/dev/null
if grep -F 'apk upgrade' "${dockerfile}" >/dev/null; then
	printf '%s\n' 'storage-debug must not upgrade the inherited package set' >&2
	exit 1
fi
if grep -F -- '--repository https://dl-cdn.alpinelinux.org/alpine/v3.24/' "${dockerfile}" >/dev/null; then
	printf '%s\n' 'storage-debug must not force a release repository' >&2
	exit 1
fi

for module in NET CRYPTO TEXT; do
	version="$(awk -F= -v key="X_${module}_VERSION" '$1 == key { print $2 }' "${root}/versions.env")"
	[[ "${version}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]
	grep -Fx "ARG X_${module}_VERSION=${version}" "${dockerfile}" >/dev/null
	lower="$(printf '%s' "${module}" | tr '[:upper:]' '[:lower:]')"
	grep -F "golang.org/x/${lower}@\${X_${module}_VERSION}" "${dockerfile}" >/dev/null
done
printf '%s\n' 'storage-debug exact package contract passed'
