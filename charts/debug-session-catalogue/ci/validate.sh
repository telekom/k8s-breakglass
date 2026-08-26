#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

chart_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rendered="$(mktemp)"
custom_rendered="$(mktemp)"
all_rendered="$(mktemp)"
failure_output="$(mktemp)"
trap 'rm -f "${rendered}" "${custom_rendered}" "${all_rendered}" "${failure_output}" "${elevated_rendered:-}"' EXIT

fail() {
  echo "::error::debug-session-catalogue validation failed: $*" >&2
  exit 1
}

assert_count() {
  local file="$1" pattern="$2" expected="$3" description="$4" actual
  actual="$(awk -v pattern="${pattern}" '$0 ~ pattern { count++ } END { print count + 0 }' "${file}")"
  [[ "${actual}" == "${expected}" ]] || fail "${description}: expected ${expected}, got ${actual}"
}

assert_contains() {
  local file="$1" text="$2" description="$3"
  grep -Fq -- "${text}" "${file}" || fail "${description}: ${text}"
}

assert_not_contains() {
  local file="$1" text="$2" description="$3"
  if grep -Fq -- "${text}" "${file}"; then fail "${description}: ${text}"; fi
}

assert_block_contains() {
  local block="$1" text="$2" description="$3"
  grep -Fq -- "${text}" <<<"${block}" || fail "${description}: ${text}"
}

assert_block_not_contains() {
  local block="$1" text="$2" description="$3"
  if grep -Fq -- "${text}" <<<"${block}"; then fail "${description}: ${text}"; fi
}

expect_rejected() {
  local description="$1"
  shift
  if "$@" > /dev/null 2>"${failure_output}"; then
    fail "${description}: invalid input was accepted"
  fi
}

chart_name="$(helm show chart "${chart_dir}" | awk '$1 == "name:" { print $2; exit }')"
[[ -n "${chart_name}" ]] || fail "unable to determine chart name from Helm metadata"

helm lint "${chart_dir}" --strict --values "${chart_dir}/ci/test-values.yaml"
helm template debug-catalogue "${chart_dir}" \
  --values "${chart_dir}/ci/test-values.yaml" >"${rendered}"

assert_count "${rendered}" '^kind: DebugPodTemplate$' 2 "default pod template count"
assert_count "${rendered}" '^kind: DebugSessionTemplate$' 2 "default session template count"
assert_not_contains "${rendered}" 'hostNetwork: true' "default profiles must not use host networking"
assert_not_contains "${rendered}" 'privileged: true' "default profiles must not be privileged"
assert_not_contains "${rendered}" 'allowPrivilegeEscalation: true' "default profiles must not allow privilege escalation"

helm template debug-catalogue "${chart_dir}" \
  --values "${chart_dir}/ci/custom-profile-values.yaml" >"${custom_rendered}"
assert_contains "${custom_rendered}" 'catalogue-profile: "custom-readonly"' "custom readonly profile renders"
assert_contains "${custom_rendered}" 'catalogue-profile: "direct-image"' "direct image profile renders"
assert_contains "${custom_rendered}" 'image: "busybox:1.36.1"' "custom image override renders"
assert_not_contains "${custom_rendered}" 'hostPID: true' "custom profiles must not use host PID"
assert_not_contains "${custom_rendered}" 'privileged: true' "custom profiles must not be privileged"
assert_not_contains "${custom_rendered}" 'allowPrivilegeEscalation: true' "custom profiles must not allow privilege escalation"

helm template debug-catalogue "${chart_dir}" \
  --values "${chart_dir}/ci/all-enabled-values.yaml" >"${all_rendered}"
assert_count "${all_rendered}" '^kind: DebugPodTemplate$' 7 "all-enabled pod template count"
assert_count "${all_rendered}" '^kind: DebugSessionTemplate$' 7 "all-enabled session template count"
actual_intents="$(awk '/^kind: DebugSessionTemplate$/ { exit } /catalogue-intent:/ { value = $0; sub(/^.*catalogue-intent:[[:space:]]*"/, "", value); sub(/".*$/, "", value); print value }' "${all_rendered}" | paste -sd, -)"
[[ "${actual_intents}" == "workload-diagnostics,network-diagnostics,storage-diagnostics,dump-access,network-repair,node-recovery,cluster-validation" ]] || fail "all-enabled intent order is ${actual_intents}"

for intent in workload-diagnostics network-diagnostics storage-diagnostics dump-access network-repair node-recovery cluster-validation; do
  assert_count "${all_rendered}" "catalogue-intent: \"${intent}\"" 2 "${intent} intent annotation count"
  assert_count "${all_rendered}" "catalogue-profile: \"${intent}\"" 2 "${intent} profile annotation count"
  assert_count "${all_rendered}" "name: ${chart_name}-${intent}" 3 "${intent} object name count"
done
assert_contains "${all_rendered}" 'mountPath: /scratch' "workload scratch mount"
assert_contains "${all_rendered}" 'mountPath: /reports' "report mount"
assert_contains "${all_rendered}" 'mountPath: /input' "dump input mount"
assert_contains "${all_rendered}" 'mountPath: /output' "dump output mount"

# Restricted output is non-root, read-only, tokenless, and has no added caps.
for profile in workload-diagnostics storage-diagnostics cluster-validation; do
  block="$(awk -v marker="catalogue-profile: \"${profile}\"" 'index($0, marker) {capture=1} capture {print} capture && /^---$/ {exit}' "${all_rendered}")"
  assert_block_contains "${block}" 'runAsNonRoot: true' "${profile} must be non-root"
  assert_block_contains "${block}" 'seccompProfile:' "${profile} must set seccomp"
  assert_block_contains "${block}" 'type: RuntimeDefault' "${profile} must use RuntimeDefault seccomp"
  assert_block_contains "${block}" 'allowPrivilegeEscalation: false' "${profile} must disable privilege escalation"
  assert_block_contains "${block}" 'readOnlyRootFilesystem: true' "${profile} must use a read-only root filesystem"
  if [[ "${profile}" != cluster-validation ]]; then assert_block_contains "${block}" 'automountServiceAccountToken: false' "${profile} must not receive a service account token"; fi
  assert_block_not_contains "${block}" 'privileged: true' "${profile} must not be privileged"
done

# Node-capable profiles retain only their declared capabilities and never need
# full privileged mode. Cluster validation's API identity is explicit.
for profile in network-diagnostics network-repair node-recovery; do
  block="$(awk -v marker="catalogue-profile: \"${profile}\"" 'index($0, marker) {capture=1} capture {print} capture && /^---$/ {exit}' "${all_rendered}")"
  assert_block_contains "${block}" 'privileged: false' "${profile} must explicitly disable privileged mode"
  assert_block_contains "${block}" 'allowPrivilegeEscalation: false' "${profile} must disable privilege escalation"
  assert_block_contains "${block}" 'runAsUser: 0' "${profile} must run as root explicitly"
done
assert_count "${all_rendered}" '^    exec: false$' 2 "non-exec profile count"
cluster_block="$(awk -v marker='catalogue-profile: "cluster-validation"' 'index($0, marker) {capture=1} capture {print} capture && /^---$/ {exit}' "${all_rendered}")"
assert_block_contains "${cluster_block}" 'automountServiceAccountToken: true' "cluster validation must opt into a service account token"
assert_block_contains "${cluster_block}" 'serviceAccountName: "cluster-validator"' "cluster validation service account"

expect_rejected "duplicate profile names" helm template debug-catalogue "${chart_dir}" --values "${chart_dir}/ci/duplicate-profile-values.yaml"
expect_rejected "invalid profile names" helm template debug-catalogue "${chart_dir}" --values "${chart_dir}/ci/invalid-profile-values.yaml"
expect_rejected "legacy map-shaped profiles" helm template debug-catalogue "${chart_dir}" --values "${chart_dir}/ci/map-profile-values.yaml"
expect_rejected "missing image references" helm template debug-catalogue "${chart_dir}" --values "${chart_dir}/ci/missing-image-values.yaml"
expect_rejected "required-elevation profile without opt-in" helm template debug-catalogue "${chart_dir}" --values "${chart_dir}/ci/elevated-required-values.yaml"

expect_rejected "restricted hostPath volume override" helm template debug-catalogue "${chart_dir}" \
  --set-json 'profiles=[{"name":"hostpath","intent":"workload-diagnostics","displayName":"HostPath","description":"Sensitive volume test","enabled":true,"elevated":false,"imageKey":"workload","command":["sh"],"args":[],"pod":{"volumes":[{"name":"host","hostPath":{"path":"/"}}]}}]'

expect_rejected "restricted projected service-account-token override" helm template debug-catalogue "${chart_dir}" \
  --set-json 'profiles=[{"name":"projected-token","intent":"workload-diagnostics","displayName":"Projected token","description":"Sensitive volume test","enabled":true,"elevated":false,"imageKey":"workload","command":["sh"],"args":[],"pod":{"volumes":[{"name":"token","projected":{"sources":[{"serviceAccountToken":{"path":"token"}}]}}]}}]'

expect_rejected "restricted Secret volume override" helm template debug-catalogue "${chart_dir}" \
  --set-json 'profiles=[{"name":"secret-volume","intent":"workload-diagnostics","displayName":"Secret volume","description":"Sensitive volume test","enabled":true,"elevated":false,"imageKey":"workload","command":["sh"],"args":[],"pod":{"volumes":[{"name":"secret","secret":{"secretName":"sensitive"}}]}}]'

expect_rejected "restricted PVC volume override" helm template debug-catalogue "${chart_dir}" \
  --set-json 'profiles=[{"name":"pvc-volume","intent":"workload-diagnostics","displayName":"PVC volume","description":"Unbounded volume test","enabled":true,"elevated":false,"imageKey":"workload","command":["sh"],"args":[],"pod":{"volumes":[{"name":"claim","persistentVolumeClaim":{"claimName":"external"}}]}}]'

elevated_rendered="$(mktemp)"
trap 'rm -f "${rendered}" "${custom_rendered}" "${all_rendered}" "${failure_output}" "${elevated_rendered}"' EXIT
helm template debug-catalogue "${chart_dir}" \
  --set-json 'profiles=[{"name":"elevated-host","intent":"node-recovery","displayName":"Elevated host","description":"Explicit elevation test","enabled":true,"elevated":true,"preset":"elevated-node","imageKey":"nodeRecovery","command":["/usr/local/bin/node-maintenance"],"args":["node-recovery"],"pod":{"volumes":[{"name":"host","hostPath":{"path":"/var/lib/example","type":"Directory"}}]}}]' >"${elevated_rendered}"
assert_contains "${elevated_rendered}" 'hostPath:' "elevated profile hostPath"

expect_rejected "cluster-validation service account without token opt-in" helm template debug-catalogue "${chart_dir}" \
  --set-json 'profiles=[{"name":"cluster-validation","intent":"cluster-validation","displayName":"Cluster validation","description":"API identity test","enabled":true,"elevated":false,"imageKey":"clusterValidation","command":["/cluster-validator"],"args":[],"serviceAccountName":"cluster-validator"}]'

expect_rejected "unapproved capabilities" helm template debug-catalogue "${chart_dir}" \
  --set-json 'profiles=[{"name":"bad-cap","intent":"test","displayName":"Bad","description":"Bad","enabled":true,"elevated":false,"imageKey":"custom","command":["sh"],"args":[],"capabilities":["SYS_CHROOT"]}]'

helm template debug-catalogue "${chart_dir}" \
  --values "${chart_dir}/ci/elevated-optin-values.yaml" >/dev/null

echo "debug-session-catalogue validation passed"
