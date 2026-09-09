#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

# Behavioral tests for the utility publication contract. These execute the
# matrix, tag, and digest-subject calculations and exercise rejection paths.
set -Eeuo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
contract="${root}/hack/utility-release-contract.sh"
utility_workflow="${root}/.github/workflows/utility-release.yml"

[[ -f "${root}/utils/node-maintenance/IMAGE-METADATA.yaml" ]] || {
	printf '%s\n' 'node-maintenance image metadata must use IMAGE-METADATA.yaml' >&2
	exit 1
}

expect_fail() {
	if "$@" >/dev/null 2>&1; then
		printf 'unexpected success: %s\n' "$*" >&2
		exit 1
	fi
}

actionlint_commit=03d0035246f3e81f36aed592ffb4bebf33a03106
grep -F "github.com/rhysd/actionlint/cmd/actionlint@${actionlint_commit} -ignore" "${utility_workflow}" >/dev/null || {
	printf '%s\n' 'utility workflow must pin actionlint to its verified v1.7.7 commit' >&2
	exit 1
}
if grep -E 'github.com/rhysd/actionlint/cmd/actionlint@v?1\.7\.7([[:space:]]|$)' "${utility_workflow}" >/dev/null; then
	printf '%s\n' 'utility workflow uses a mutable actionlint version reference' >&2
	exit 1
fi

matrix="$(UTILITY_IMAGE_PREFIX=ghcr.io/telekom/k8s-breakglass/utils "${contract}" matrix "${root}")"
jq -e '
	type == "array" and length > 0 and
	(map(.name) | length == (unique | length)) and
	(map(.file) | length == (unique | length)) and
	all(.[]; (.image | startswith("ghcr.io/telekom/k8s-breakglass/utils/")) and
		(.context | startswith("utils/")) and (.file | endswith("/Dockerfile")) and
		(.smokeCommand | length > 0) and (.smokeOutput | length > 0) and
		(.requiredChecks | length > 0))
' <<<"${matrix}" >/dev/null

[[ "$("${contract}" tag push v1.2.3)" == v1.2.3 ]]
[[ "$("${contract}" tag push v1.2.3-rc.4)" == v1.2.3-rc.4 ]]
[[ "$("${contract}" tag push v1.2.3-alpha-1.0A)" == v1.2.3-alpha-1.0A ]]
[[ "$("${contract}" tag schedule main)" == nightly ]]
expect_fail "${contract}" tag push latest
[[ "$("${contract}" tag workflow_dispatch main true)" == rolling ]]
expect_fail "${contract}" tag workflow_dispatch main false
expect_fail "${contract}" tag workflow_dispatch feature true
expect_fail "${contract}" tag push v01.2.3
expect_fail "${contract}" tag push v1.2.3-01
expect_fail "${contract}" tag push v1.2.3-rc..1
expect_fail "${contract}" tag push v1.2.3-rc.
expect_fail "${contract}" tag workflow_dispatch main

digest="sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
image=ghcr.io/telekom/k8s-breakglass/utils/workload-debug
[[ "$("${contract}" subject "${image}" "${digest}")" == "${image}@${digest}" ]]
expect_fail "${contract}" subject "${image}:v1.2.3" "${digest}"
expect_fail "${contract}" subject "${image}" sha256:bad
expect_fail "${contract}" subject ghcr.io/example/other/utils/workload-debug "${digest}"

# Explicit inventory supports both colocated and shared Makefile layouts while
# ignoring fixture Dockerfiles that are not publishable images.
fixture="$(mktemp -d)"
trap 'rm -rf "${fixture}"' EXIT HUP INT TERM
mkdir -p "${fixture}/hack" "${fixture}/utils/images/future-tool/tests/fixtures" "${fixture}/utils/images" "${fixture}/.github/workflows"
touch "${fixture}/.github/workflows/future-tool.yml"
touch "${fixture}/utils/images/future-tool/Dockerfile" "${fixture}/utils/images/future-tool/tests/fixtures/Dockerfile" "${fixture}/utils/images/Makefile"
printf '%s\n' '["Core CI"]' >"${fixture}/hack/release-required-checks.json"
printf '%s\n' '{"schemaVersion":1,"images":[{"name":"future-tool","context":"utils/images/future-tool","file":"utils/images/future-tool/Dockerfile","smokeCommand":["help"],"smokeOutput":"future help","requiredChecks":["Future behavior"],"behaviorWorkflows":[".github/workflows/future-tool.yml"]}]}' >"${fixture}/hack/utility-image-matrix.json"
future="$(UTILITY_IMAGE_PREFIX=ghcr.io/telekom/k8s-breakglass/utils "${contract}" matrix "${fixture}")"
jq -e 'length == 1 and .[0].name == "future-tool" and .[0].image == "ghcr.io/telekom/k8s-breakglass/utils/future-tool"' <<<"${future}" >/dev/null
checks="$("${contract}" required-checks "${fixture}")"
jq -e 'sort == ["Core CI","Future behavior"]' <<<"${checks}" >/dev/null
printf '%s\n' '{"schemaVersion":1,"images":[{"name":"future-tool","context":"utils/images/future-tool","file":"utils/images/future-tool/Dockerfile","smokeCommand":["help"],"smokeOutput":"future help","requiredChecks":["Future behavior"],"behaviorWorkflows":[".github/workflows/future-tool.yml"]},{"name":"future-tool","context":"utils/images/future-tool","file":"utils/images/future-tool/Dockerfile","smokeCommand":["help"],"smokeOutput":"future help","requiredChecks":["Future duplicate behavior"],"behaviorWorkflows":[".github/workflows/future-tool.yml"]}]}' >"${fixture}/hack/utility-image-matrix.json"
expect_fail "${contract}" matrix "${fixture}"
expect_fail env UTILITY_IMAGE_PREFIX=ghcr.io/example/acme/other-utils "${contract}" matrix "${fixture}"

printf '%s\n' 'utility release contract behavioral tests passed'
