#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

chart_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rendered="$(mktemp)"
custom_rendered="$(mktemp)"
all_rendered="$(mktemp)"
failure_output="$(mktemp)"
digest_rendered="$(mktemp)"
elevated_rendered="$(mktemp)"
release_a_rendered="$(mktemp)"
release_b_rendered="$(mktemp)"
override_rendered="$(mktemp)"
duration_rendered=
trap 'rm -f "${rendered}" "${custom_rendered}" "${all_rendered}" "${failure_output}" "${digest_rendered}" "${elevated_rendered}" "${release_a_rendered}" "${release_b_rendered}" "${override_rendered}" "${duration_rendered}"' EXIT

fail() {
  echo "::error::debug-session-catalogue validation failed: $*" >&2
  exit 1
}

expect_rejected() {
  local description="$1"
  shift
  if "$@" > /dev/null 2>"${failure_output}"; then
    fail "${description}: invalid input was accepted"
  fi
}

validate_rendered() {
  ruby "${chart_dir}/ci/validate-rendered.rb" "$1" "$2"
}

helm lint "${chart_dir}" --strict --values "${chart_dir}/ci/test-values.yaml"
helm template debug-catalogue "${chart_dir}" \
  --values "${chart_dir}/ci/test-values.yaml" >"${rendered}"
validate_rendered default "${rendered}"

# Distinct Helm releases must not collide on default template names;
# fullnameOverride remains the explicit escape hatch for stable names.
helm template release-a "${chart_dir}" --values "${chart_dir}/ci/test-values.yaml" >"${release_a_rendered}"
helm template release-b "${chart_dir}" --values "${chart_dir}/ci/test-values.yaml" >"${release_b_rendered}"
release_a_name=$(yq -r 'select(.kind == "DebugPodTemplate") | .metadata.name' "${release_a_rendered}" | head -n 1)
release_b_name=$(yq -r 'select(.kind == "DebugPodTemplate") | .metadata.name' "${release_b_rendered}" | head -n 1)
[[ -n "${release_a_name}" && "${release_a_name}" != "${release_b_name}" ]] || fail "distinct Helm releases collided on default template name"
helm template release-override "${chart_dir}" --values "${chart_dir}/ci/test-values.yaml" \
  --set fullnameOverride=managed-catalogue >"${override_rendered}"
override_name=$(yq -r 'select(.kind == "DebugPodTemplate") | .metadata.name' "${override_rendered}" | head -n 1)
[[ "${override_name}" == managed-catalogue-workload-diagnostics ]] || fail "fullnameOverride was not preserved"

helm template debug-catalogue "${chart_dir}" \
  --values "${chart_dir}/ci/custom-profile-values.yaml" >"${custom_rendered}"
validate_rendered custom "${custom_rendered}"

helm template debug-catalogue "${chart_dir}" \
  --values "${chart_dir}/ci/all-enabled-values.yaml" >"${all_rendered}"
validate_rendered all "${all_rendered}"

# These are chart behavior checks: Helm must reject values that violate the
# schema or the template's security contract.
expect_rejected "duplicate profile names" helm template debug-catalogue "${chart_dir}" --values "${chart_dir}/ci/duplicate-profile-values.yaml"
expect_rejected "invalid profile names" helm template debug-catalogue "${chart_dir}" --values "${chart_dir}/ci/invalid-profile-values.yaml"
expect_rejected "legacy map-shaped profiles" helm template debug-catalogue "${chart_dir}" --values "${chart_dir}/ci/map-profile-values.yaml"
expect_rejected "missing image references" helm template debug-catalogue "${chart_dir}" --values "${chart_dir}/ci/missing-image-values.yaml"
expect_rejected "required-elevation profile without opt-in" helm template debug-catalogue "${chart_dir}" --values "${chart_dir}/ci/elevated-required-values.yaml"
expect_rejected "hostNetwork without elevation" helm template debug-catalogue "${chart_dir}" \
  --set-json 'profiles=[{"name":"unsafe-network","intent":"network-diagnostics","displayName":"Unsafe network","description":"Missing elevation","enabled":true,"elevated":false,"hostNetwork":true,"imageKey":"network","command":["sh"],"args":[]}]'

expect_rejected "hostNetwork on an unrelated intent" helm template debug-catalogue "${chart_dir}" \
  --set-json 'profiles=[{"name":"unsafe-network","intent":"dump-access","displayName":"Unsafe network","description":"Wrong intent","enabled":true,"elevated":true,"hostNetwork":true,"preset":"elevated-node","imageKey":"dumpAccess","command":["sh"],"args":[]}]'

expect_rejected "hostPID without hostNetwork" helm template debug-catalogue "${chart_dir}" \
  --set-json 'profiles=[{"name":"unsafe-pid","intent":"node-recovery","displayName":"Unsafe PID","description":"Missing host network","enabled":true,"elevated":true,"hostPID":true,"preset":"elevated-node","imageKey":"nodeRecovery","command":["sh"],"args":[]}]'

helm template debug-catalogue "${chart_dir}" \
  --set-json 'profiles=[{"name":"digest-image","intent":"workload-diagnostics","displayName":"Digest image","description":"Digest precedence test","enabled":true,"elevated":false,"command":["sh"],"args":[],"image":{"repository":"example.invalid/workload-debug","tag":"ignored","digest":"sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"}}]' >"${digest_rendered}"
validate_rendered digest "${digest_rendered}"

expect_rejected "image without tag or digest" helm template debug-catalogue "${chart_dir}" \
  --set-json 'profiles=[{"name":"incomplete-image","intent":"workload-diagnostics","displayName":"Incomplete image","description":"Missing immutable reference","enabled":true,"elevated":false,"command":["sh"],"args":[],"image":{"repository":"example.invalid/workload-debug"}}]'

expect_rejected "restricted hostPath volume override" helm template debug-catalogue "${chart_dir}" \
  --set-json 'profiles=[{"name":"hostpath","intent":"workload-diagnostics","displayName":"HostPath","description":"Sensitive volume test","enabled":true,"elevated":false,"imageKey":"workload","command":["sh"],"args":[],"pod":{"volumes":[{"name":"host","hostPath":{"path":"/"}}]}}]'

expect_rejected "restricted projected service-account-token override" helm template debug-catalogue "${chart_dir}" \
  --set-json 'profiles=[{"name":"projected-token","intent":"workload-diagnostics","displayName":"Projected token","description":"Sensitive volume test","enabled":true,"elevated":false,"imageKey":"workload","command":["sh"],"args":[],"pod":{"volumes":[{"name":"token","projected":{"sources":[{"serviceAccountToken":{"path":"token"}}]}}]}}]'

expect_rejected "environment Secret reference" helm template debug-catalogue "${chart_dir}" \
  --set-json 'profiles=[{"name":"secret-env","intent":"workload-diagnostics","displayName":"Secret environment","description":"Credential isolation test","enabled":true,"elevated":false,"imageKey":"workload","command":["sh"],"args":[],"pod":{"env":[{"name":"TOKEN","valueFrom":{"secretKeyRef":{"name":"credentials","key":"token"}}}]}}]'

expect_rejected "environment ConfigMap reference" helm template debug-catalogue "${chart_dir}" \
  --set-json 'profiles=[{"name":"config-env","intent":"workload-diagnostics","displayName":"Config environment","description":"Immutable catalogue test","enabled":true,"elevated":false,"imageKey":"workload","command":["sh"],"args":[],"pod":{"env":[{"name":"FLAGS","valueFrom":{"configMapKeyRef":{"name":"runtime-overrides","key":"flags"}}}]}}]'

expect_rejected "restricted Secret volume override" helm template debug-catalogue "${chart_dir}" \
  --set-json 'profiles=[{"name":"secret-volume","intent":"workload-diagnostics","displayName":"Secret volume","description":"Sensitive volume test","enabled":true,"elevated":false,"imageKey":"workload","command":["sh"],"args":[],"pod":{"volumes":[{"name":"secret","secret":{"secretName":"sensitive"}}]}}]'

expect_rejected "restricted PVC volume override" helm template debug-catalogue "${chart_dir}" \
  --set-json 'profiles=[{"name":"pvc-volume","intent":"workload-diagnostics","displayName":"PVC volume","description":"Unbounded volume test","enabled":true,"elevated":false,"imageKey":"workload","command":["sh"],"args":[],"pod":{"volumes":[{"name":"claim","persistentVolumeClaim":{"claimName":"external"}}]}}]'

expect_rejected "dump source without a read-only mount" helm template debug-catalogue "${chart_dir}" \
  --set-json 'profiles=[{"name":"dump-access","intent":"dump-access","displayName":"Dump access","description":"Read approved dump","enabled":true,"elevated":false,"imageKey":"dumpAccess","command":["/usr/local/bin/dump-reader"],"args":["copy","/input/fixture.dump"],"sourcePath":"/input/fixture.dump","allowExec":false,"pod":{"volumes":[{"name":"input","hostPath":{"path":"/var/lib/catalogue-fixtures/dumps","type":"Directory"}}]}}]'

expect_rejected "dump source without an explicit path" helm template debug-catalogue "${chart_dir}" \
  --set-json 'profiles=[{"name":"dump-access","intent":"dump-access","displayName":"Dump access","description":"Read approved dump","enabled":true,"elevated":false,"imageKey":"dumpAccess","command":["/usr/local/bin/dump-reader"],"args":["copy","/input/fixture.dump"],"allowExec":false,"pod":{"volumeMounts":[{"name":"input","mountPath":"/input","readOnly":true},{"name":"output","mountPath":"/output"}],"volumes":[{"name":"input","hostPath":{"path":"/var/lib/catalogue-fixtures/dumps","type":"Directory"}},{"name":"output","emptyDir":{"sizeLimit":"1Gi"}}]}}]'

helm template debug-catalogue "${chart_dir}" \
  --set-json 'profiles=[{"name":"elevated-host","intent":"node-recovery","displayName":"Elevated host","description":"Explicit elevation test","enabled":true,"elevated":true,"hostNetwork":true,"preset":"elevated-node","imageKey":"nodeRecovery","command":["/usr/local/bin/node-maintenance"],"args":["node-recovery"],"pod":{"volumes":[{"name":"host","hostPath":{"path":"/var/lib/example","type":"Directory"}}]}}]' >"${elevated_rendered}"
validate_rendered elevated "${elevated_rendered}"

expect_rejected "cluster-validation service account without token opt-in" helm template debug-catalogue "${chart_dir}" \
  --set-json 'profiles=[{"name":"cluster-validation","intent":"cluster-validation","displayName":"Cluster validation","description":"API identity test","enabled":true,"elevated":false,"imageKey":"clusterValidation","command":["/cluster-validator"],"args":[],"serviceAccountName":"cluster-validator"}]'

expect_rejected "unapproved capabilities" helm template debug-catalogue "${chart_dir}" \
  --set-json 'profiles=[{"name":"bad-cap","intent":"test","displayName":"Bad","description":"Bad","enabled":true,"elevated":false,"imageKey":"custom","command":["sh"],"args":[],"capabilities":["SYS_CHROOT"]}]'

helm template debug-catalogue "${chart_dir}" \
  --values "${chart_dir}/ci/elevated-optin-values.yaml" >/dev/null

duration_rendered="$(mktemp)"
helm template debug-catalogue "${chart_dir}" --values "${chart_dir}/ci/test-values.yaml" \
  --set defaultDuration=1h30m --set maxDuration=2h15m >"${duration_rendered}"
expect_rejected "malformed compound default duration" helm template debug-catalogue "${chart_dir}" \
  --values "${chart_dir}/ci/test-values.yaml" --set defaultDuration=1hm
expect_rejected "malformed compound max duration" helm template debug-catalogue "${chart_dir}" \
  --values "${chart_dir}/ci/test-values.yaml" --set maxDuration=1h30mm
rm -f "${duration_rendered}"

echo "debug-session-catalogue validation passed"
