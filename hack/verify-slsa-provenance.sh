#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

# Validate decoded Cosign output for an SLSA v1 attestation. The explicit
# expectation arguments make this suitable for release jobs: subject, source,
# commit, build type, and builder identity are all part of the contract. With
# no arguments, local signed bundles exercise positive and negative behavior.

set -Eeuo pipefail

decode_statement() {
  local document="$1"
  local output="$2"
  if jq -e 'type == "object" and (.dsseEnvelope.payload | type == "string")' "${document}" >/dev/null 2>&1; then
    jq -r '.dsseEnvelope.payload' "${document}" | base64 --decode >"${output}"
  elif jq -e 'type == "object" and (.payload | type == "string")' "${document}" >/dev/null 2>&1; then
    jq -r '.payload' "${document}" | base64 --decode >"${output}"
  else
    jq -e . "${document}" >"${output}"
  fi
}

validate_one() {
  local document="$1" subject="$2" expected_build_type="$3"
  local expected_source_uri="$4" expected_source_sha="$5" expected_builder_id="$6"
  local image="${subject%@*}" digest="${subject##*@}" statement
  statement="$(mktemp)"
  if ! decode_statement "${document}" "${statement}"; then
    rm -f "${statement}"
    return 1
  fi
  # The workflow invokes this verifier only after Cosign has cryptographically
  # restricted output to the exact certificate identity
  # https://github.com/${claims.job_workflow_ref} and SLSA type. A
  # GitHub-native attestation can still be present alongside our custom
  # statement; recognize only its documented Statement/v1 producer shape and
  # never use it as the custom statement being required below. The native
  # predicate's builder is the workflow identity, while its workflow
  # repository/path/ref and the Cosign certificate filter provide independent
  # checks of that identity.
  if jq -e \
    --arg image "${image}" \
    --arg digest "${digest}" \
    --arg source_uri "${expected_source_uri}" \
    --arg source_sha "${expected_source_sha}" \
    --arg workflow_identity "${expected_builder_id}" '
    ._type == "https://in-toto.io/Statement/v1" and
    .predicateType == "https://slsa.dev/provenance/v1" and
    (.subject | type == "array" and length == 1) and
    .subject[0].name == $image and
    (.subject[0].digest | type == "object") and
    .subject[0].digest.sha256 == ($digest | sub("^sha256:"; "")) and
    (.predicate.buildDefinition.buildType == "https://actions.github.io/buildtypes/workflow/v1" or
      .predicate.buildDefinition.buildType == "https://slsa-framework.github.io/github-actions-buildtypes/workflow/v1") and
    (.predicate.buildDefinition.externalParameters.workflow | type == "object") and
    .predicate.buildDefinition.externalParameters.workflow.repository == $source_uri and
    (($source_uri + "/" + .predicate.buildDefinition.externalParameters.workflow.path + "@" + .predicate.buildDefinition.externalParameters.workflow.ref) == $workflow_identity) and
    ([.predicate.buildDefinition.resolvedDependencies[]? |
      select(.digest.gitCommit == $source_sha and (.uri | startswith("git+" + $source_uri + "@")))] | length == 1) and
    .predicate.runDetails.builder.id == $workflow_identity
  ' "${statement}" >/dev/null; then
    rm -f "${statement}"
    return 2
  fi
  if jq -e \
    --arg image "${image}" \
    --arg digest "${digest#sha256:}" \
    --arg build_type "${expected_build_type}" \
    --arg source_uri "${expected_source_uri}" \
    --arg source_sha "${expected_source_sha}" \
    --arg builder_id "${expected_builder_id}" '
    ._type == "https://in-toto.io/Statement/v0.1" and
    .predicateType == "https://slsa.dev/provenance/v1" and
    (.subject | type == "array" and length == 1) and
    .subject[0].name == $image and
    (.subject[0].digest | type == "object") and
    .subject[0].digest.sha256 == $digest and
    (.predicate | type == "object") and
    (.predicate.buildDefinition | type == "object") and
    .predicate.buildDefinition.buildType == $build_type and
    (.predicate.buildDefinition.externalParameters | type == "object") and
    (.predicate.buildDefinition.externalParameters.source | type == "object") and
    .predicate.buildDefinition.externalParameters.source.uri == $source_uri and
    (.predicate.buildDefinition.externalParameters.source.digest | type == "object") and
    .predicate.buildDefinition.externalParameters.source.digest.sha1 == $source_sha and
    (.predicate.runDetails | type == "object") and
    (.predicate.runDetails.builder | type == "object") and
    .predicate.runDetails.builder.id == $builder_id
  ' "${statement}" >/dev/null; then
    rm -f "${statement}"
    return 0
  fi
  rm -f "${statement}"
  return 1
}

validate_document() {
  local document="$1" subject="$2" expected_build_type="$3"
  local expected_source_uri="$4" expected_source_sha="$5" expected_builder_id="$6"
  local require_native="${7:-false}"
  local count index element result custom_count=0 native_count=0
  [[ "${require_native}" == true || "${require_native}" == false ]] || return 2
  if jq -e 'type == "array"' "${document}" >/dev/null 2>&1; then
    count="$(jq 'length' "${document}")"
    [[ "${count}" -gt 0 ]] || return 1
    for ((index = 0; index < count; index++)); do
      element="$(mktemp)"
      jq ".[$index]" "${document}" >"${element}"
      if validate_one "${element}" "${subject}" "${expected_build_type}" \
        "${expected_source_uri}" "${expected_source_sha}" "${expected_builder_id}"; then
        custom_count=$((custom_count + 1))
      else
        result=$?
        [[ "${result}" -eq 2 ]] || {
          rm -f "${element}"
          return 1
        }
        native_count=$((native_count + 1))
      fi
      if [[ "${custom_count}" -gt 1 ]]; then
        rm -f "${element}"
        return 1
      fi
      if [[ "${native_count}" -gt 1 ]]; then
        rm -f "${element}"
        return 1
      fi
      rm -f "${element}"
    done
    [[ "${custom_count}" -eq 1 ]] || return 1
    [[ "${require_native}" != true || "${native_count}" -eq 1 ]] || return 1
    return 0
  fi
  if validate_one "${document}" "${subject}" "${expected_build_type}" \
    "${expected_source_uri}" "${expected_source_sha}" "${expected_builder_id}"; then
    return 0
  else
    result=$?
  fi
  [[ "${result}" -eq 2 ]] && return 1
  return "${result}"
}

if [[ "$#" -eq 6 || "$#" -eq 7 ]]; then
  validate_document "$@"
  exit 0
fi
[[ "$#" -eq 0 ]] || {
  echo "usage: $0 ATTESTATION-DOCUMENT SUBJECT BUILD-TYPE SOURCE-URI SOURCE-SHA BUILDER-ID [REQUIRE-NATIVE]" >&2
  exit 2
}

command -v cosign >/dev/null || { echo "cosign is required" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

test_dir="$(mktemp -d)"
trap 'rm -rf "${test_dir}"' EXIT
export COSIGN_PASSWORD=
export COSIGN_TLOG_UPLOAD=false
cosign generate-key-pair --output-key-prefix "${test_dir}/cosign" >/dev/null 2>&1

subject="registry.example.invalid/utility@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
build_type="https://github.com/telekom/k8s-breakglass/.github/workflows/utility-dev-publish.yml"
source_uri="https://github.com/telekom/k8s-breakglass"
source_sha="aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
builder_id="https://github.com/telekom/k8s-breakglass/.github/workflows/utility-dev-publish.yml@refs/heads/dev-images/test"
jq -n --arg build_type "${build_type}" --arg source_uri "${source_uri}" \
  --arg source_sha "${source_sha}" --arg builder_id "${builder_id}" \
  '{buildDefinition:{buildType:$build_type,externalParameters:{source:{uri:$source_uri,digest:{sha1:$source_sha}}},resolvedDependencies:[]},runDetails:{builder:{id:$builder_id}}}' \
  >"${test_dir}/valid-predicate.json"
jq -n --arg build_type "${build_type}" --arg source_uri "${source_uri}" \
  --arg source_sha "${source_sha}" \
  '{buildDefinition:{buildType:$build_type,externalParameters:{source:{uri:$source_uri,digest:{sha1:$source_sha}}},resolvedDependencies:[]}}' \
  >"${test_dir}/malformed-predicate.json"
jq -n --arg source_uri "${source_uri}" --arg source_sha "${source_sha}" \
  '{_type:"https://in-toto.io/Statement/v1",subject:[{name:"registry.example.invalid/utility",digest:{sha256:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}],predicateType:"https://slsa.dev/provenance/v1",predicate:{buildDefinition:{buildType:"https://actions.github.io/buildtypes/workflow/v1",externalParameters:{workflow:{repository:$source_uri,path:".github/workflows/utility-dev-publish.yml",ref:"refs/heads/dev-images/test"}},resolvedDependencies:[{uri:("git+" + $source_uri + "@refs/heads/dev-images/test"),digest:{gitCommit:$source_sha}}]},runDetails:{builder:{id:"https://github.com/telekom/k8s-breakglass/.github/workflows/utility-dev-publish.yml@refs/heads/dev-images/test"}}}}' \
  >"${test_dir}/github-predicate.json"
jq -n --arg source_uri "${source_uri}" --arg source_sha "${source_sha}" \
  '{_type:"https://in-toto.io/Statement/v1",subject:[{name:"registry.example.invalid/utility",digest:{sha256:"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"}}],predicateType:"https://slsa.dev/provenance/v1",predicate:{buildDefinition:{buildType:"https://actions.github.io/buildtypes/workflow/v1",externalParameters:{workflow:{repository:"https://example.invalid/other",path:".github/workflows/utility-dev-publish.yml",ref:"refs/heads/dev-images/test"}},resolvedDependencies:[{uri:("git+" + $source_uri + "@refs/heads/dev-images/test"),digest:{gitCommit:$source_sha}}]},runDetails:{builder:{id:"https://github.com/telekom/k8s-breakglass/.github/workflows/utility-dev-publish.yml@refs/heads/dev-images/test"}}}}' \
  >"${test_dir}/wrong-github-predicate.json"

make_bundle() {
  local predicate="$1" type="$2" output="$3"
  cosign attest --use-signing-config=false --key "${test_dir}/cosign.key" \
    --no-upload --bundle "${output}" --type "${type}" --predicate "${predicate}" "${subject}" >/dev/null
}

make_bundle "${test_dir}/valid-predicate.json" slsaprovenance1 "${test_dir}/valid.bundle.json"
validate_document "${test_dir}/valid.bundle.json" "${subject}" "${build_type}" \
  "${source_uri}" "${source_sha}" "${builder_id}"

make_bundle "${test_dir}/valid-predicate.json" slsaprovenance "${test_dir}/wrong-type.bundle.json"
if validate_document "${test_dir}/wrong-type.bundle.json" "${subject}" "${build_type}" \
  "${source_uri}" "${source_sha}" "${builder_id}"; then
  echo "v0.2 SLSA statement was accepted as v1" >&2
  exit 1
fi

make_bundle "${test_dir}/malformed-predicate.json" slsaprovenance1 "${test_dir}/malformed.bundle.json"
if validate_document "${test_dir}/malformed.bundle.json" "${subject}" "${build_type}" \
  "${source_uri}" "${source_sha}" "${builder_id}"; then
  echo "malformed SLSA predicate was accepted" >&2
  exit 1
fi

jq -s '.' "${test_dir}/valid.bundle.json" "${test_dir}/github-predicate.json" >"${test_dir}/valid-and-github.json"
validate_document "${test_dir}/valid-and-github.json" "${subject}" "${build_type}" \
  "${source_uri}" "${source_sha}" "${builder_id}" true
if validate_document "${test_dir}/github-predicate.json" "${subject}" "${build_type}" \
  "${source_uri}" "${source_sha}" "${builder_id}" true; then
  echo "GitHub-native attestation was incorrectly accepted as the custom statement" >&2
  exit 1
fi

jq -s '.' "${test_dir}/valid.bundle.json" "${test_dir}/wrong-github-predicate.json" >"${test_dir}/valid-and-wrong-github.json"
if validate_document "${test_dir}/valid-and-wrong-github.json" "${subject}" "${build_type}" \
  "${source_uri}" "${source_sha}" "${builder_id}" true; then
  echo "untrusted producer-shaped attestation was ignored" >&2
  exit 1
fi

jq -s '.' "${test_dir}/valid.bundle.json" "${test_dir}/github-predicate.json" \
  "${test_dir}/github-predicate.json" >"${test_dir}/duplicate-github.json"
if validate_document "${test_dir}/duplicate-github.json" "${subject}" "${build_type}" \
  "${source_uri}" "${source_sha}" "${builder_id}" true; then
  echo "duplicate GitHub-native attestations were accepted" >&2
  exit 1
fi

if validate_document "${test_dir}/valid.bundle.json" \
  "registry.example.invalid/other@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" \
  "${build_type}" "${source_uri}" "${source_sha}" "${builder_id}"; then
  echo "attestation for the wrong subject was accepted" >&2
  exit 1
fi

if validate_document "${test_dir}/valid.bundle.json" "${subject}" \
  "${build_type}" "${source_uri}" "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" "${builder_id}"; then
  echo "attestation for the wrong source commit was accepted" >&2
  exit 1
fi

if validate_document "${test_dir}/valid.bundle.json" "${subject}" \
  "${build_type}" "${source_uri}" "${source_sha}" "https://example.invalid/other-builder"; then
  echo "attestation for the wrong builder was accepted" >&2
  exit 1
fi

jq -s '.' "${test_dir}/valid.bundle.json" "${test_dir}/malformed.bundle.json" >"${test_dir}/mixed.json"
if validate_document "${test_dir}/mixed.json" "${subject}" "${build_type}" \
  "${source_uri}" "${source_sha}" "${builder_id}"; then
  echo "a malformed entry in a multi-attestation document was ignored" >&2
  exit 1
fi

echo "SLSA provenance attestation behavior passed"
