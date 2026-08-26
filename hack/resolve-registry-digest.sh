#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

# Resolve a registry tag to an immutable digest. Every failed probe is
# retried, but only a successful probe containing a valid digest can return.
# This intentionally treats authentication, transport, and malformed output
# as failures; callers must never sign an unverified or guessed subject.

set -Eeuo pipefail

image_ref="${1:-}"
[[ -n "${image_ref}" && "${image_ref}" != -* && "${image_ref}" != *[[:space:]]* ]] || {
  echo "usage: $0 IMAGE[:TAG]" >&2
  exit 2
}

attempts="${REGISTRY_DIGEST_ATTEMPTS:-30}"
delay="${REGISTRY_DIGEST_DELAY_SECONDS:-10}"
[[ "${attempts}" =~ ^[1-9][0-9]*$ ]] || {
  echo "REGISTRY_DIGEST_ATTEMPTS must be a positive integer" >&2
  exit 2
}
(( attempts <= 60 )) || {
  echo "REGISTRY_DIGEST_ATTEMPTS must not exceed 60" >&2
  exit 2
}
[[ "${delay}" =~ ^[0-9]+([.][0-9]+)?$ ]] || {
  echo "REGISTRY_DIGEST_DELAY_SECONDS must be a non-negative number" >&2
  exit 2
}

for attempt in $(seq 1 "${attempts}"); do
  inspect_output="$(mktemp)"
  inspect_error="$(mktemp)"
  set +e
  docker buildx imagetools inspect "${image_ref}" >"${inspect_output}" 2>"${inspect_error}"
  inspect_status=$?
  set -e

  if [[ "${inspect_status}" -eq 0 ]]; then
    digest="$(awk '/^Digest:[[:space:]]+sha256:[0-9a-f]{64}$/ {print $2; exit}' "${inspect_output}")"
    if [[ "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]]; then
      rm -f "${inspect_output}" "${inspect_error}"
      printf '%s\n' "${digest}"
      exit 0
    fi
    echo "registry probe returned no valid digest on attempt ${attempt}/${attempts}" >&2
  else
    echo "registry digest probe failed on attempt ${attempt}/${attempts}" >&2
    cat "${inspect_error}" >&2
  fi
  rm -f "${inspect_output}" "${inspect_error}"
  if [[ "${attempt}" -lt "${attempts}" ]]; then
    sleep "${delay}"
  fi
done

echo "unable to resolve a valid immutable digest for ${image_ref}" >&2
exit 1
