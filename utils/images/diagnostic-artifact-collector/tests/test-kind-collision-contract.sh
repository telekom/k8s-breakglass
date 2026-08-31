#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

script="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)/tests/kind-collision.sh"
grep -F "alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b" "${script}" >/dev/null
if grep -E 'docker (pull|tag) alpine:3\.24([[:space:]]|$)' "${script}" >/dev/null; then
	printf '%s\n' 'collision proof uses an unpinned Alpine reference' >&2
	exit 1
fi
printf '%s\n' 'Kind collision image reference contract passed'
