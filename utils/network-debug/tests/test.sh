#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -eu

root=$(cd -- "$(dirname -- "$0")/.." && pwd)

grep -Eq '^FROM alpine:3\.24@sha256:[0-9a-f]{64} AS runtime$' "$root/Dockerfile"
grep -Eq '^FROM golang:1\.27@sha256:[0-9a-f]{64} AS tools$' "$root/Dockerfile"
if grep -En '(:|@)latest([[:space:]]|$)' "$root/Dockerfile" "$root/versions.env"; then
	exit 1
fi
grep -q 'KUBESTR_VERSION=v0.4.49' "$root/versions.env"
grep -q 'KUBESTR_COMMIT=01940ed37be9a0c7a70d80cd26c648eaa11e5174' "$root/versions.env"
grep -q 'PWRU_VERSION=v1.0.12' "$root/versions.env"
grep -Eq '^PWRU_SHA256_(AMD64|ARM64)=[0-9a-f]{64}$' "$root/versions.env"
grep -q 'intent: network-diagnostics' "$root/IMAGE-METADATA.yaml"
grep -q 'io.telekom.breakglass.intent="network-diagnostics"' "$root/Dockerfile"

if grep -Eq -- '--push|docker push' "$root/Makefile"; then
	printf '%s\n' 'multi-arch build must not push a mutable tag' >&2
	exit 1
fi
grep -q 'cosign sign --yes' "$root/Makefile"
grep -q 'cosign attest --yes' "$root/Makefile"

for helper in net-debug net-report; do
	sh "$root/scripts/$helper" --help >/dev/null
done

version=$(NETWORK_DEBUG_VERSION=0.1.0 sh "$root/scripts/net-report" --version)
test "$version" = 'net-report 0.1.0'
intent=$(NETWORK_DEBUG_INTENT=network-diagnostics sh "$root/scripts/net-report" | sed -n '2p')
test "$intent" = 'intent network-diagnostics'

# No timestamp or random-id output: this check runs with a minimal PATH.
first=$(PATH=/usr/bin:/bin NETWORK_DEBUG_VERSION=test sh "$root/scripts/net-report" 2>/dev/null || true)
second=$(PATH=/usr/bin:/bin NETWORK_DEBUG_VERSION=test sh "$root/scripts/net-report" 2>/dev/null || true)
test "$first" = "$second"
echo 'network-debug image checks passed'
