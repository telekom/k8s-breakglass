#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

chart_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rendered="$(mktemp)"
custom_rendered="$(mktemp)"
all_rendered="$(mktemp)"
trap 'rm -f "${rendered}" "${custom_rendered}" "${all_rendered}"' EXIT

helm lint "${chart_dir}" --strict --values "${chart_dir}/ci/test-values.yaml"
helm template debug-catalogue "${chart_dir}" \
  --values "${chart_dir}/ci/test-values.yaml" >"${rendered}"

[[ "$(grep -c '^kind: DebugPodTemplate$' "${rendered}")" -eq 3 ]]
[[ "$(grep -c '^kind: DebugSessionTemplate$' "${rendered}")" -eq 3 ]]
if grep -q 'hostNetwork: true' "${rendered}"; then exit 1; fi
if grep -q 'privileged: true' "${rendered}"; then exit 1; fi
if grep -q 'allowPrivilegeEscalation: true' "${rendered}"; then exit 1; fi

helm template debug-catalogue "${chart_dir}" \
  --values "${chart_dir}/ci/custom-profile-values.yaml" >"${custom_rendered}"
grep -q 'catalogue-profile: "custom-readonly"' "${custom_rendered}"
grep -q 'catalogue-profile: "direct-image"' "${custom_rendered}"
grep -q 'image: "busybox:1.36.1"' "${custom_rendered}"
if grep -q 'hostPID: true' "${custom_rendered}"; then exit 1; fi
if grep -q 'privileged: true' "${custom_rendered}"; then exit 1; fi
if grep -q 'allowPrivilegeEscalation: true' "${custom_rendered}"; then exit 1; fi

helm template debug-catalogue "${chart_dir}" \
  --values "${chart_dir}/ci/all-enabled-values.yaml" >"${all_rendered}"
[[ "$(grep -c '^kind: DebugPodTemplate$' "${all_rendered}")" -eq 7 ]]
[[ "$(grep -c '^kind: DebugSessionTemplate$' "${all_rendered}")" -eq 7 ]]
actual_intents="$(grep 'catalogue-intent:' "${all_rendered}" | sed -E 's/.*catalogue-intent: "([^"]+)".*/\1/' | awk 'NR % 2 == 1' | paste -sd, -)"
[[ "${actual_intents}" == "workload-diagnostics,network-diagnostics,storage-diagnostics,dump-access,network-repair,node-recovery,cluster-validation" ]]

for intent in workload-diagnostics network-diagnostics storage-diagnostics dump-access network-repair node-recovery cluster-validation; do
  [[ "$(grep -c "catalogue-intent: \"${intent}\"" "${all_rendered}")" -eq 2 ]]
  [[ "$(grep -c "catalogue-profile: \"${intent}\"" "${all_rendered}")" -eq 2 ]]
  [[ "$(grep -c "name: debug-catalogue-${intent}" "${all_rendered}")" -eq 3 ]]
done
grep -q 'mountPath: /scratch' "${all_rendered}"
grep -q 'mountPath: /reports' "${all_rendered}"
grep -q 'mountPath: /input' "${all_rendered}"
grep -q 'mountPath: /output' "${all_rendered}"

# Restricted output is non-root, read-only, tokenless, and has no added caps.
for profile in workload-diagnostics storage-diagnostics cluster-validation; do
  block="$(awk -v marker="catalogue-profile: \"${profile}\"" 'index($0, marker) {capture=1} capture {print} capture && /^---$/ {exit}' "${all_rendered}")"
  grep -q 'runAsNonRoot: true' <<<"${block}"
  grep -q 'seccompProfile:' <<<"${block}"
  grep -q 'type: RuntimeDefault' <<<"${block}"
  grep -q 'allowPrivilegeEscalation: false' <<<"${block}"
  grep -q 'readOnlyRootFilesystem: true' <<<"${block}"
  grep -q 'automountServiceAccountToken: false' <<<"${block}" || [[ "${profile}" == cluster-validation ]]
  ! grep -q 'privileged: true' <<<"${block}"
done

# Node-capable profiles retain only their declared capabilities and never need
# full privileged mode. Cluster validation's API identity is explicit.
for profile in network-diagnostics network-repair node-recovery; do
  block="$(awk -v marker="catalogue-profile: \"${profile}\"" 'index($0, marker) {capture=1} capture {print} capture && /^---$/ {exit}' "${all_rendered}")"
  grep -q 'privileged: false' <<<"${block}"
  grep -q 'allowPrivilegeEscalation: false' <<<"${block}"
done
cluster_block="$(awk -v marker='catalogue-profile: "cluster-validation"' 'index($0, marker) {capture=1} capture {print} capture && /^---$/ {exit}' "${all_rendered}")"
grep -q 'automountServiceAccountToken: true' <<<"${cluster_block}"
grep -q 'serviceAccountName: "cluster-validator"' <<<"${cluster_block}"

if helm template debug-catalogue "${chart_dir}" \
  --values "${chart_dir}/ci/duplicate-profile-values.yaml" >/dev/null 2>&1; then
  echo "duplicate profile names must be rejected" >&2
  exit 1
fi
if helm template debug-catalogue "${chart_dir}" \
  --values "${chart_dir}/ci/invalid-profile-values.yaml" >/dev/null 2>&1; then
  echo "invalid profile names must be rejected" >&2
  exit 1
fi
if helm template debug-catalogue "${chart_dir}" \
  --values "${chart_dir}/ci/map-profile-values.yaml" >/dev/null 2>&1; then
  echo "legacy map-shaped profiles must be rejected" >&2
  exit 1
fi
if helm template debug-catalogue "${chart_dir}" \
  --values "${chart_dir}/ci/missing-image-values.yaml" >/dev/null 2>&1; then
  echo "missing image references must be rejected" >&2
  exit 1
fi
if helm template debug-catalogue "${chart_dir}" \
  --values "${chart_dir}/ci/elevated-required-values.yaml" >/dev/null 2>&1; then
  echo "required-elevation profile must require explicit elevated opt-in" >&2
  exit 1
fi

if helm template debug-catalogue "${chart_dir}" \
  --set-json 'profiles=[{"name":"hostpath","intent":"workload-diagnostics","displayName":"HostPath","description":"Sensitive volume test","enabled":true,"elevated":false,"imageKey":"workload","command":["sh"],"args":[],"pod":{"volumes":[{"name":"host","hostPath":{"path":"/"}}]}}]' >/dev/null 2>&1; then
  echo "restricted hostPath volume override must be rejected" >&2
  exit 1
fi

if helm template debug-catalogue "${chart_dir}" \
  --set-json 'profiles=[{"name":"projected-token","intent":"workload-diagnostics","displayName":"Projected token","description":"Sensitive volume test","enabled":true,"elevated":false,"imageKey":"workload","command":["sh"],"args":[],"pod":{"volumes":[{"name":"token","projected":{"sources":[{"serviceAccountToken":{"path":"token"}}]}}]}}]' >/dev/null 2>&1; then
  echo "restricted projected service-account-token override must be rejected" >&2
  exit 1
fi

elevated_rendered="$(mktemp)"
trap 'rm -f "${rendered}" "${custom_rendered}" "${all_rendered}" "${elevated_rendered}"' EXIT
helm template debug-catalogue "${chart_dir}" \
  --set-json 'profiles=[{"name":"elevated-host","intent":"node-recovery","displayName":"Elevated host","description":"Explicit elevation test","enabled":true,"elevated":true,"preset":"elevated-node","imageKey":"nodeRecovery","command":["/usr/local/bin/node-maintenance"],"args":["node-recovery"],"pod":{"volumes":[{"name":"host","hostPath":{"path":"/var/lib/example","type":"Directory"}}]}}]' >"${elevated_rendered}"
grep -q 'hostPath:' "${elevated_rendered}"

if helm template debug-catalogue "${chart_dir}" \
  --set-json 'profiles=[{"name":"cluster-validation","intent":"cluster-validation","displayName":"Cluster validation","description":"API identity test","enabled":true,"elevated":false,"imageKey":"clusterValidation","command":["/cluster-validator"],"args":[],"serviceAccountName":"cluster-validator"}]' >/dev/null 2>&1; then
  echo "cluster-validation service account must require explicit token opt-in" >&2
  exit 1
fi

if helm template debug-catalogue "${chart_dir}" \
  --set-json 'profiles=[{"name":"bad-cap","intent":"test","displayName":"Bad","description":"Bad","enabled":true,"elevated":false,"imageKey":"custom","command":["sh"],"args":[],"capabilities":["SYS_CHROOT"]}]' >/dev/null 2>&1; then
  echo "unapproved capabilities must be rejected" >&2
  exit 1
fi

helm template debug-catalogue "${chart_dir}" \
  --values "${chart_dir}/ci/elevated-optin-values.yaml" >/dev/null

echo "debug-session-catalogue validation passed"
