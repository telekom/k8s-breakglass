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
trap 'rm -f "${rendered}" "${custom_rendered}" "${all_rendered}" "${failure_output}" "${digest_rendered}" "${elevated_rendered}"' EXIT

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

helm template debug-catalogue "${chart_dir}" \
  --set-json 'profiles=[{"name":"elevated-host","intent":"node-recovery","displayName":"Elevated host","description":"Explicit elevation test","enabled":true,"elevated":true,"preset":"elevated-node","imageKey":"nodeRecovery","command":["/usr/local/bin/node-maintenance"],"args":["node-recovery"],"pod":{"volumes":[{"name":"host","hostPath":{"path":"/var/lib/example","type":"Directory"}}]}}]' >"${elevated_rendered}"
validate_rendered elevated "${elevated_rendered}"

expect_rejected "cluster-validation service account without token opt-in" helm template debug-catalogue "${chart_dir}" \
  --set-json 'profiles=[{"name":"cluster-validation","intent":"cluster-validation","displayName":"Cluster validation","description":"API identity test","enabled":true,"elevated":false,"imageKey":"clusterValidation","command":["/cluster-validator"],"args":[],"serviceAccountName":"cluster-validator"}]'

expect_rejected "unapproved capabilities" helm template debug-catalogue "${chart_dir}" \
  --set-json 'profiles=[{"name":"bad-cap","intent":"test","displayName":"Bad","description":"Bad","enabled":true,"elevated":false,"imageKey":"custom","command":["sh"],"args":[],"capabilities":["SYS_CHROOT"]}]'

helm template debug-catalogue "${chart_dir}" \
  --values "${chart_dir}/ci/elevated-optin-values.yaml" >/dev/null

echo "debug-session-catalogue validation passed"
