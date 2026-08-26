#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

# Validate the decoded statement emitted by Cosign for an SLSA v1
# attestation. With two arguments this validates a workflow-produced
# verify-attestation JSON document. With no arguments it creates local signed
# Cosign bundles and exercises valid, malformed, wrong-type, and wrong-subject
# cases, so the test proves the contract rather than searching source text.

set -Eeuo pipefail

decode_statement() {
  local document="$1"
  local output="$2"
  if jq -e 'type == "array" and length > 0 and .[0].payload' "${document}" >/dev/null 2>&1; then
    jq -r '.[0].payload' "${document}" | base64 --decode >"${output}"
  elif jq -e '.dsseEnvelope.payload' "${document}" >/dev/null 2>&1; then
    jq -r '.dsseEnvelope.payload' "${document}" | base64 --decode >"${output}"
  elif jq -e '.payload' "${document}" >/dev/null 2>&1; then
    jq -r '.payload' "${document}" | base64 --decode >"${output}"
  else
    jq -e . "${document}" >"${output}"
  fi
}

validate_statement() {
  local document="$1"
  local subject="$2"
  local statement
  local image="${subject%@*}"
  local digest="${subject##*@}"
  statement="$(mktemp)"
  decode_statement "${document}" "${statement}"
  if jq -e --arg image "${image}" --arg digest "${digest#sha256:}" '
    ._type == "https://in-toto.io/Statement/v0.1" and
    .predicateType == "https://slsa.dev/provenance/v1" and
    (.subject | type == "array" and length == 1) and
    .subject[0].name == $image and
    .subject[0].digest.sha256 == $digest and
    (.predicate | type == "object") and
    (.predicate.buildDefinition | type == "object") and
    (.predicate.buildDefinition.buildType | type == "string" and length > 0) and
    (.predicate.runDetails | type == "object") and
    (.predicate.runDetails.builder | type == "object") and
    (.predicate.runDetails.builder.id | type == "string" and length > 0)
  ' "${statement}" >/dev/null; then
    validation_status=0
  else
    validation_status=$?
  fi
  rm -f "${statement}"
  return "${validation_status}"
}

if [[ "$#" -eq 2 ]]; then
  validate_statement "$1" "$2"
  exit 0
fi
[[ "$#" -eq 0 ]] || { echo "usage: $0 [attestation-document subject]" >&2; exit 2; }

command -v cosign >/dev/null || { echo "cosign is required" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

test_dir="$(mktemp -d)"
trap 'rm -rf "${test_dir}"' EXIT
export COSIGN_PASSWORD=
export COSIGN_TLOG_UPLOAD=false
cosign generate-key-pair --output-key-prefix "${test_dir}/cosign" >/dev/null 2>&1

subject="registry.example.invalid/utility@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
jq -n '{buildDefinition:{buildType:"https://example.invalid/build"},runDetails:{builder:{id:"https://example.invalid/builder"}}}' \
  >"${test_dir}/valid-predicate.json"
jq -n '{buildDefinition:{buildType:"https://example.invalid/build"}}' \
  >"${test_dir}/malformed-predicate.json"

make_bundle() {
  local predicate="$1"
  local type="$2"
  local output="$3"
  cosign attest --use-signing-config=false --key "${test_dir}/cosign.key" \
    --no-upload --bundle "${output}" --type "${type}" --predicate "${predicate}" "${subject}" >/dev/null
}

make_bundle "${test_dir}/valid-predicate.json" slsaprovenance1 "${test_dir}/valid.bundle.json"
validate_statement "${test_dir}/valid.bundle.json" "${subject}"

make_bundle "${test_dir}/valid-predicate.json" slsaprovenance "${test_dir}/wrong-type.bundle.json"
if validate_statement "${test_dir}/wrong-type.bundle.json" "${subject}"; then
  echo "v0.2 SLSA statement was accepted as v1" >&2
  exit 1
fi

make_bundle "${test_dir}/malformed-predicate.json" slsaprovenance1 "${test_dir}/malformed.bundle.json"
if validate_statement "${test_dir}/malformed.bundle.json" "${subject}"; then
  echo "malformed SLSA predicate was accepted" >&2
  exit 1
fi

if validate_statement "${test_dir}/valid.bundle.json" "registry.example.invalid/other@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"; then
  echo "attestation for the wrong subject was accepted" >&2
  exit 1
fi

echo "SLSA provenance attestation behavior passed"
