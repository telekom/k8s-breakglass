#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

subject=""
digest=""
sha=""
build_type=""
builder_id=""
output=""
while [ "$#" -gt 0 ]; do
  case "$1" in
    --subject) subject="${2:?missing value for --subject}"; shift 2 ;;
    --digest) digest="${2:?missing value for --digest}"; shift 2 ;;
    --sha) sha="${2:?missing value for --sha}"; shift 2 ;;
    --build-type) build_type="${2:?missing value for --build-type}"; shift 2 ;;
    --builder-id) builder_id="${2:?missing value for --builder-id}"; shift 2 ;;
    --output) output="${2:?missing value for --output}"; shift 2 ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
done

[[ -n "${subject}" && "${subject}" != *[[:space:]]* && "${subject}" != *@* ]] || {
  echo "invalid attestation subject" >&2
  exit 2
}
[[ "${digest}" =~ ^sha256:[0-9a-f]{64}$ ]] || {
  echo "invalid subject digest" >&2
  exit 2
}
[[ "${sha}" =~ ^[0-9a-f]{40}$ ]] || {
  echo "invalid source commit SHA" >&2
  exit 2
}
[[ -n "${build_type}" && -n "${builder_id}" && -n "${output}" ]] || {
  echo "build type, builder ID, and output are required" >&2
  exit 2
}

# This is the SLSA v1 predicate body. cosign --predicate supplies the in-toto
# Statement envelope (including subject and predicateType); passing a complete
# Statement here would create a nested predicate.
jq -n \
  --arg build_type "${build_type}" \
  --arg source_sha "${sha}" \
  --arg builder_id "${builder_id}" \
  '{buildDefinition:{buildType:$build_type,externalParameters:{source:{uri:"https://github.com/telekom/k8s-breakglass",digest:{sha1:$source_sha}}},resolvedDependencies:[]},runDetails:{builder:{id:$builder_id}}}' \
  >"${output}"
