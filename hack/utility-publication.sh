#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail

die() { printf 'utility publication: %s\n' "$*" >&2; exit 1; }
digest_re='^sha256:[0-9a-f]{64}$'

case "${1:-}" in
  tag-state)
    [[ $# == 3 ]] || die 'tag-state IMAGE TAG'
    if [[ "$3" == nightly || "$3" == rolling ]]; then printf '%s\n' mutable; exit 0; fi
    reference="$2:$3"; error="$(mktemp)"; trap 'rm -f "${error}"' EXIT
    if output="$(docker buildx imagetools inspect "${reference}" 2>"${error}")"; then
      digest="$(awk '/^Digest:[[:space:]]+sha256:[0-9a-f]{64}$/ {print $2; exit}' <<<"${output}")"
      [[ "${digest}" =~ $digest_re ]] || die "registry returned no strict digest for ${reference}"
      printf '%s\n' "${digest}"; exit 0
    fi
    if grep -Eqi 'manifest unknown|no such manifest|unexpected status[^:]*: 404 Not Found|status code 404' "${error}" || grep -Fqi "${reference}: not found" "${error}"; then printf '%s\n' missing; exit 0; fi
    printf 'registry lookup failed for %s:%s: ' "$2" "$3" >&2; cat "${error}" >&2; exit 1
    ;;
  require-tag)
    [[ $# == 4 && "$4" =~ $digest_re ]] || die 'require-tag IMAGE TAG DIGEST'
    output="$(docker buildx imagetools inspect "$2:$3")" || die "cannot resolve final tag $2:$3"
    actual="$(awk '/^Digest:[[:space:]]+sha256:[0-9a-f]{64}$/ {print $2; exit}' <<<"${output}")"
    [[ "${actual}" =~ $digest_re ]] || die "registry returned no strict digest for $2:$3"
    [[ "${actual}" == "$4" ]] || die "tag $2:$3 resolves to ${actual}, expected $4"
    ;;
  platform-subjects)
    [[ $# == 3 ]] || die 'platform-subjects IMAGE INDEX_DIGEST'
    [[ "$3" =~ $digest_re ]] || die 'invalid index digest'
    command -v jq >/dev/null 2>&1 || die 'jq is required'
    raw="$(docker buildx imagetools inspect --raw "$2@$3")"
    jq -e '[.manifests[] | select(.platform.os != "unknown") | [.platform.os,.platform.architecture]] | sort == [["linux","amd64"],["linux","arm64"]]' <<<"${raw}" >/dev/null || die 'index must contain exactly linux/amd64 and linux/arm64'
    for arch in amd64 arm64; do
      child="$(jq -er --arg arch "${arch}" '[.manifests[] | select(.platform.os=="linux" and .platform.architecture==$arch) | .digest] | if length==1 then .[0] else error("expected exactly one linux/"+$arch) end' <<<"${raw}")"
      [[ "${child}" =~ $digest_re ]] || die "invalid linux/${arch} digest"
      printf '%s=%s\n' "${arch}_digest" "${child}"
      printf '%s=%s@%s\n' "${arch}_subject" "$2" "${child}"
    done
    ;;
  *) die 'unknown command' ;;
esac
