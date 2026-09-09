#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

# Behavioral test for the predicate body passed to cosign. The final object is
# assembled the same way cosign attest does it, so this checks the decoded
# subject, predicateType, and SLSA v1 predicate rather than source text.

set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
test_dir="$(mktemp -d)"
trap 'rm -rf "${test_dir}"' EXIT

subject="ghcr.io/example/debug-session-catalogue"
digest="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
sha="bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
bash "${script_dir}/generate-slsa-provenance.sh" \
  --subject "${subject}" --digest "${digest}" --sha "${sha}" \
  --build-type "https://github.com/telekom/k8s-breakglass/.github/workflows/release.yml" \
  --builder-id "https://github.com/example/run/123" --output "${test_dir}/predicate.json"

jq -e '
  type == "object" and
  (keys | sort) == ["buildDefinition", "runDetails"] and
  .buildDefinition.buildType == "https://github.com/telekom/k8s-breakglass/.github/workflows/release.yml" and
  .buildDefinition.externalParameters.source.digest.sha1 == "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" and
  .buildDefinition.resolvedDependencies == [] and
  .runDetails.builder.id == "https://github.com/example/run/123" and
  (has("subject") | not) and (has("predicateType") | not)
' "${test_dir}/predicate.json" >/dev/null

jq -n \
  --arg subject "${subject}" --arg digest "${digest#sha256:}" \
  --slurpfile predicate "${test_dir}/predicate.json" \
  '{_type:"https://in-toto.io/Statement/v1",subject:[{name:$subject,digest:{sha256:$digest}}],predicateType:"https://slsa.dev/provenance/v1",predicate:$predicate[0]}' \
  >"${test_dir}/statement.json"

jq -e '
  ._type == "https://in-toto.io/Statement/v1" and
  (.subject | length) == 1 and
  .subject[0].name == "ghcr.io/example/debug-session-catalogue" and
  .subject[0].digest.sha256 == "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" and
  .predicateType == "https://slsa.dev/provenance/v1" and
  (.predicate | type) == "object" and
  (.predicate | has("subject") | not) and
  .predicate.buildDefinition.buildType == "https://github.com/telekom/k8s-breakglass/.github/workflows/release.yml" and
  .predicate.runDetails.builder.id == "https://github.com/example/run/123"
' "${test_dir}/statement.json" >/dev/null

echo "SLSA provenance structure passed"
