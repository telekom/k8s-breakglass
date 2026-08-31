#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"; helper="${root}/hack/utility-publication.sh"
tmp="$(mktemp -d)"; trap 'rm -rf "${tmp}"' EXIT
mkdir -p "${tmp}/bin"
cat >"${tmp}/bin/docker" <<'EOF'
#!/usr/bin/env bash
if [[ "$*" == *"imagetools create --tag"* ]]; then
  if [[ -n "${TAG_CREATED_MARKER:-}" ]]; then touch "${TAG_CREATED_MARKER}"; fi
  printf '%s\n' "$*" >>"${DOCKER_CALL_LOG:?}"
  exit 0
fi
if [[ "$*" == *"imagetools inspect --raw"* ]]; then
  [[ "${VERIFY_FAILURE:-}" != platform ]] || exit 1
  if [[ "${VERIFY_FAILURE:-}" == platform_duplicate ]]; then
    printf '%s\n' '{"manifests":[{"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","platform":{"os":"linux","architecture":"amd64"}},{"digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","platform":{"os":"linux","architecture":"amd64"}}]}'
    exit 0
  fi
  if [[ "${DOCKER_MODE:-}" == duplicate ]]; then
    printf '%s\n' '{"manifests":[{"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","platform":{"os":"linux","architecture":"amd64"}},{"digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","platform":{"os":"linux","architecture":"amd64"}}]}'
    exit 0
  fi
  printf '%s\n' '{"manifests":[{"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","platform":{"os":"linux","architecture":"amd64"}},{"digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","platform":{"os":"linux","architecture":"arm64"}},{"digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","platform":{"os":"unknown","architecture":"unknown"}}]}'
  exit 0
fi
if [[ "${1:-}" == pull ]]; then
  [[ "${VERIFY_FAILURE:-}" != pull ]] || exit 1
  exit 0
fi
if [[ "${1:-} ${2:-}" == "image inspect" ]]; then
  if [[ "${VERIFY_FAILURE:-}" == architecture ]]; then
    echo linux/arm64
    exit 0
  fi
  count=0
  if [[ -n "${INSPECT_COUNT_FILE:-}" && -f "${INSPECT_COUNT_FILE}" ]]; then
    count="$(<"${INSPECT_COUNT_FILE}")"
  fi
  count=$((count + 1))
  if [[ -n "${INSPECT_COUNT_FILE:-}" ]]; then printf '%s\n' "${count}" >"${INSPECT_COUNT_FILE}"; fi
  [[ "${count}" == 1 ]] && echo linux/amd64 || echo linux/arm64
  exit 0
fi
if [[ "${1:-}" == run ]]; then
  printf '%s\n' "$*" >>"${DOCKER_RUN_LOG:?}"
  [[ "${SMOKE_FAILURE:-}" != true ]] || exit 1
  printf '%s\n' "${SMOKE_OUTPUT:-exact-smoke-ok}"
  exit 0
fi
case "${DOCKER_MODE:-}" in
exists) echo 'Digest: sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'; exit 0;;
missing)
  [[ -n "${TAG_CREATED_MARKER:-}" && -f "${TAG_CREATED_MARKER}" ]] || { echo 'manifest unknown' >&2; exit 1; }
  echo 'Digest: sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee'; exit 0;;
missing_plain) echo 'ghcr.io/telekom/k8s-breakglass/utils/test:v1.2.3: not found' >&2; exit 1;; network) echo 'dial tcp: lookup ghcr.io: no such host' >&2; exit 1;;
raw) printf '%s\n' '{"manifests":[{"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","platform":{"os":"linux","architecture":"amd64"}},{"digest":"sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","platform":{"os":"linux","architecture":"arm64"}},{"digest":"sha256:cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc","platform":{"os":"unknown","architecture":"unknown"}}]}';;
duplicate) printf '%s\n' '{"manifests":[{"digest":"sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","platform":{"os":"linux","architecture":"amd64"}},{"digest":"sha256:dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd","platform":{"os":"linux","architecture":"amd64"}}]}';;
esac
EOF
cat >"${tmp}/bin/curl" <<'EOF'
#!/usr/bin/env bash
if [[ "$*" == *"ghcr.io/token"* ]]; then
  printf '%s\n' '{"token":"fake-bearer"}'
  exit 0
fi
if [[ "$*" == *"-X PUT"* ]]; then
  [[ "${CONDITIONAL_TAG_FAILURE:-false}" != true ]] || { printf '%s\n' 'conditional request unsupported' >&2; exit 1; }
  [[ "$*" == *"If-None-Match: *"* ]]
  [[ -n "${TAG_CREATED_MARKER:-}" ]] && touch "${TAG_CREATED_MARKER}"
  printf '%s\n' 'conditional tag create' >>"${DOCKER_CALL_LOG:?}"
  printf '201'
  exit 0
fi
if [[ "$*" == *"ghcr.io/v2/"* ]]; then
  header_file= body_file=
  while [[ $# -gt 0 ]]; do
    case "$1" in
      -D) header_file="$2"; shift 2 ;;
      -o) body_file="$2"; shift 2 ;;
      *) shift ;;
    esac
  done
  printf 'Content-Type: application/vnd.oci.image.index.v1+json\n' >"${header_file:?}"
  printf '%s\n' '{"schemaVersion":2,"manifests":[]}' >"${body_file:?}"
  exit 0
fi
exit 1
EOF
cat >"${tmp}/bin/cosign" <<'EOF'
#!/usr/bin/env bash
[[ -z "${VERIFY_CALL_MARKER:-}" ]] || touch "${VERIFY_CALL_MARKER}"
[[ "$*" == *"--certificate-identity=https://github.com/o/r/.github/workflows/utility-release.yml@refs/tags/v1.2.3"* ]]
[[ "$*" != *"certificate-identity-regexp"* ]]
if [[ "${1:-}" == verify && "${VERIFY_FAILURE:-}" == signature ]]; then exit 1; fi
if [[ "${1:-}" == verify-attestation && "${VERIFY_FAILURE:-}" == sbom ]]; then exit 1; fi
exit 0
EOF
cat >"${tmp}/bin/gh" <<'EOF'
#!/usr/bin/env bash
[[ "${COMPETING_PROVENANCE:-false}" != true ]] || exit 1
[[ "${VERIFY_FAILURE:-}" != provenance ]] || exit 1
[[ "$*" == *"--signer-workflow o/r/.github/workflows/utility-release.yml"* ]]
[[ "$*" == *"--signer-digest eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"* ]]
[[ "$*" == *"--source-digest eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"* ]]
[[ "$*" == *"--source-ref refs/tags/v1.2.3"* ]]
EOF
cat >"${tmp}/bin/timeout" <<'EOF'
#!/bin/sh
# Keep this fixture independent of platform-specific GNU timeout process
# group behavior on macOS; every wrapped command is already deterministic.
case "${1:-}" in
  --foreground) shift ;;
esac
shift
exec "$@"
EOF
chmod +x "${tmp}/bin/docker"
chmod +x "${tmp}/bin/cosign" "${tmp}/bin/gh"
chmod +x "${tmp}/bin/curl"
chmod +x "${tmp}/bin/timeout"
export PATH="${tmp}/bin:${PATH}"
expect_fail() { if "$@" >/dev/null 2>&1; then echo "unexpected success: $*" >&2; exit 1; fi; }
[[ "$(DOCKER_MODE=missing "${helper}" tag-state ghcr.io/telekom/k8s-breakglass/utils/test v1.2.3)" == missing ]]
[[ "$(DOCKER_MODE=missing_plain "${helper}" tag-state ghcr.io/telekom/k8s-breakglass/utils/test v1.2.3)" == missing ]]
[[ "$(DOCKER_MODE=exists "${helper}" tag-state ghcr.io/telekom/k8s-breakglass/utils/test v1.2.3)" == sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee ]]
DOCKER_MODE=network expect_fail "${helper}" tag-state ghcr.io/telekom/k8s-breakglass/utils/test v1.2.3
[[ "$(DOCKER_MODE=exists "${helper}" tag-state ghcr.io/telekom/k8s-breakglass/utils/test nightly)" == mutable ]]
[[ "$(DOCKER_MODE=exists "${helper}" tag-state ghcr.io/telekom/k8s-breakglass/utils/test rolling)" == mutable ]]
DOCKER_MODE=exists "${helper}" require-tag ghcr.io/telekom/k8s-breakglass/utils/test nightly sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
DOCKER_MODE=exists "${helper}" require-tag ghcr.io/telekom/k8s-breakglass/utils/test rolling sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
DOCKER_MODE=exists expect_fail "${helper}" require-tag ghcr.io/telekom/k8s-breakglass/utils/test nightly sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff
subjects="$(DOCKER_MODE=raw "${helper}" platform-subjects ghcr.io/telekom/k8s-breakglass/utils/test sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee)"
grep -q '^amd64_subject=.*@sha256:a\{64\}$' <<<"${subjects}"
grep -q '^arm64_subject=.*@sha256:b\{64\}$' <<<"${subjects}"
DOCKER_MODE=duplicate expect_fail "${helper}" platform-subjects ghcr.io/telekom/k8s-breakglass/utils/test sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee

tag_helper="${root}/hack/publish-utility-tag.sh"
tag_digest=sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
docker_call_log="${tmp}/docker-calls"
inspect_count_file="${tmp}/inspect-count"
verify_env=(env DOCKER_MODE=exists GITHUB_REPOSITORY=o/r GITHUB_SHA=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee GITHUB_REF=refs/tags/v1.2.3 GITHUB_WORKFLOW_REF=o/r/.github/workflows/utility-release.yml@refs/tags/v1.2.3 GITHUB_ACTOR=github-actions INSPECT_COUNT_FILE="${inspect_count_file}" GH_TOKEN=fake-token)

assert_no_tag_mutation() {
	local failure="$1"
	rm -f "${docker_call_log}" "${inspect_count_file}"
	expect_fail env VERIFY_FAILURE="${failure}" DOCKER_CALL_LOG="${docker_call_log}" "${verify_env[@]}" "${tag_helper}" ghcr.io/telekom/k8s-breakglass/utils/test rolling "${tag_digest}"
	[[ ! -e "${docker_call_log}" ]]
}

# Every pre-tag verification class is independently fail-closed. The fake
# registry only records imagetools create, so these assertions detect an
# accidental tag mutation even when an earlier verification class succeeds.
for failure in signature sbom provenance platform platform_duplicate pull architecture; do
	assert_no_tag_mutation "${failure}"
done

# Successful verification permits the mutable rolling tag mutation, which the
# fake registry records separately from all read-only inspection calls.
rm -f "${docker_call_log}" "${inspect_count_file}"
"${verify_env[@]}" DOCKER_CALL_LOG="${docker_call_log}" "${tag_helper}" ghcr.io/telekom/k8s-breakglass/utils/test rolling "${tag_digest}"
grep -F 'imagetools create --tag ghcr.io/telekom/k8s-breakglass/utils/test:rolling ghcr.io/telekom/k8s-breakglass/utils/test@sha256:eeeeeeee' "${docker_call_log}" >/dev/null

# Stable tags must refuse an occupied tag without reaching the mutation, while
# a proven-missing stable tag may be created and then must remain bound.
rm -f "${docker_call_log}" "${inspect_count_file}"
occupied_verify_marker="${tmp}/occupied-verify"
rm -f "${occupied_verify_marker}"
expect_fail env VERIFY_CALL_MARKER="${occupied_verify_marker}" DOCKER_CALL_LOG="${docker_call_log}" "${verify_env[@]}" "${tag_helper}" ghcr.io/telekom/k8s-breakglass/utils/test v1.2.3 "${tag_digest}"
[[ ! -e "${docker_call_log}" ]]
[[ ! -e "${occupied_verify_marker}" ]]

stable_marker="${tmp}/stable-created"
rm -f "${docker_call_log}" "${inspect_count_file}" "${stable_marker}"
stable_env=(env DOCKER_MODE=missing TAG_CREATED_MARKER="${stable_marker}" GITHUB_REPOSITORY=o/r GITHUB_SHA=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee GITHUB_REF=refs/tags/v1.2.3 GITHUB_WORKFLOW_REF=o/r/.github/workflows/utility-release.yml@refs/tags/v1.2.3 GITHUB_ACTOR=github-actions GH_TOKEN=fake-token INSPECT_COUNT_FILE="${inspect_count_file}" DOCKER_CALL_LOG="${docker_call_log}")
"${stable_env[@]}" "${tag_helper}" ghcr.io/telekom/k8s-breakglass/utils/test v1.2.3 "${tag_digest}"
grep -F 'conditional tag create' "${docker_call_log}" >/dev/null
[[ -e "${stable_marker}" ]]

# A registry that rejects the conditional create must fail closed without
# assigning the stable tag.
rm -f "${docker_call_log}" "${inspect_count_file}" "${stable_marker}"
if CONDITIONAL_TAG_FAILURE=true "${stable_env[@]}" "${tag_helper}" ghcr.io/telekom/k8s-breakglass/utils/test v1.2.3 "${tag_digest}"; then
  echo 'stable publication unexpectedly accepted a non-conditional registry' >&2
  exit 1
fi
[[ ! -e "${stable_marker}" && ! -e "${docker_call_log}" ]]

# A partial matrix rerun may reuse a pre-existing version only after all exact
# source, workflow, signature, SBOM, platform, and pull checks succeed.
rm -f "${inspect_count_file}"
"${verify_env[@]}" "${root}/hack/verify-utility-publication.sh" ghcr.io/telekom/k8s-breakglass/utils/test sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee
# A release candidate is not considered verified merely because its manifest
# can be pulled: the exact immutable platform subjects must execute the
# declared smoke contract before a tag mutation. The fake records both run
# subjects so this remains behavioral rather than a script-shape assertion.
rm -f "${inspect_count_file}"
smoke_run_log="${tmp}/smoke-runs"
rm -f "${smoke_run_log}"
SMOKE_OUTPUT=exact-smoke-ok DOCKER_RUN_LOG="${smoke_run_log}" "${verify_env[@]}" \
  "${root}/hack/verify-utility-publication.sh" \
  ghcr.io/telekom/k8s-breakglass/utils/test \
  sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee \
  '["--help"]' exact-smoke-ok
grep -F -- 'ghcr.io/telekom/k8s-breakglass/utils/test@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa --help' "${smoke_run_log}" >/dev/null
grep -F -- 'ghcr.io/telekom/k8s-breakglass/utils/test@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb --help' "${smoke_run_log}" >/dev/null
newline_smoke_log="${tmp}/newline-smoke-runs"
rm -f "${newline_smoke_log}"
rm -f "${inspect_count_file}"
SMOKE_OUTPUT=line2 DOCKER_RUN_LOG="${newline_smoke_log}" "${verify_env[@]}" \
  "${root}/hack/verify-utility-publication.sh" \
  ghcr.io/telekom/k8s-breakglass/utils/test \
  sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee \
  '["/bin/sh","-c","printf '\''line1\\nline2\\n'\''"]' line2
grep -F -- '/bin/sh' "${newline_smoke_log}" >/dev/null
grep -F -- 'line1' "${newline_smoke_log}" >/dev/null
grep -F -- 'line2' "${newline_smoke_log}" >/dev/null
SMOKE_FAILURE=true DOCKER_RUN_LOG="${smoke_run_log}" expect_fail "${verify_env[@]}" \
  "${root}/hack/verify-utility-publication.sh" \
  ghcr.io/telekom/k8s-breakglass/utils/test \
  sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee \
  '["--help"]' exact-smoke-ok
# A competing provenance claim for the same tag/digest fails closed.
expect_fail env COMPETING_PROVENANCE=true "${verify_env[@]}" "${root}/hack/verify-utility-publication.sh" ghcr.io/telekom/k8s-breakglass/utils/test sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee

# Missing verifier dependencies fail with a clear preflight error before any
# registry or attestation operation is attempted.
missing_tool_output="${tmp}/missing-tool-output"
missing_path="${tmp}/missing-path"
mkdir -p "${missing_path}"
ln -s /bin/bash "${missing_path}/bash"
ln -s /bin/dirname "${missing_path}/dirname"
if PATH="${missing_path}" GITHUB_REPOSITORY=o/r GITHUB_SHA=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee GITHUB_REF=refs/tags/v1.2.3 GITHUB_WORKFLOW_REF=o/r/.github/workflows/utility-release.yml@refs/tags/v1.2.3 \
  "${root}/hack/verify-utility-publication.sh" ghcr.io/telekom/k8s-breakglass/utils/test sha256:eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee >"${missing_tool_output}" 2>&1; then
  echo 'verification unexpectedly succeeded without jq' >&2
  exit 1
fi
grep -F 'jq is required for utility publication verification' "${missing_tool_output}" >/dev/null

success_run='{"id":1,"app":{"slug":"github-actions"},"name":"Essential CI","status":"completed","conclusion":"success","details_url":"https://github.com/o/r/actions/runs/100/job/1"}'
release_run='{"id":2,"app":{"slug":"github-actions"},"name":"Utility release contract","status":"in_progress","conclusion":null,"details_url":"https://github.com/o/r/actions/runs/200/job/2"}'
check_runs="[${success_run},${release_run}]"
gate=(env GITHUB_REPOSITORY=o/r GITHUB_SHA=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee REQUIRED_CHECKS_JSON='["Essential CI"]' IGNORE_RELEASE_WORKFLOW_RUNS=true CHECK_RUN_IGNORED_RUN_IDS_JSON='["200"]')
CHECK_RUNS_JSON="${check_runs}" "${gate[@]}" "${root}/hack/verify-commit-check-runs.sh" >/dev/null
expect_fail env CHECK_RUNS_JSON="[${release_run}]" "${gate[@]}" "${root}/hack/verify-commit-check-runs.sh"
expect_fail env CHECK_RUNS_JSON="[${success_run/\"success\"/\"failure\"},${release_run}]" "${gate[@]}" "${root}/hack/verify-commit-check-runs.sh"
expect_fail env CHECK_RUNS_JSON="[${success_run/\"completed\"/\"in_progress\"},${release_run}]" "${gate[@]}" "${root}/hack/verify-commit-check-runs.sh"
expect_fail env CHECK_RUNS_JSON="${check_runs}" GITHUB_REPOSITORY=o/r GITHUB_SHA=eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee REQUIRED_CHECKS_JSON='["Essential CI"]' IGNORE_RELEASE_WORKFLOW_RUNS=true CHECK_RUN_IGNORED_RUN_IDS_JSON='[]' "${root}/hack/verify-commit-check-runs.sh"
echo 'utility publication behavioral tests passed'
