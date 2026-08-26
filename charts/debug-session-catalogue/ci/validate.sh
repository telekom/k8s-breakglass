#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

chart_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rendered="$(mktemp)"
custom_rendered="$(mktemp)"
trap 'rm -f "${rendered}" "${custom_rendered}"' EXIT

helm lint "${chart_dir}" --strict --values "${chart_dir}/ci/test-values.yaml"
helm template debug-catalogue "${chart_dir}" \
  --values "${chart_dir}/ci/test-values.yaml" >"${rendered}"

[[ "$(grep -c '^kind: DebugPodTemplate$' "${rendered}")" -eq 4 ]]
[[ "$(grep -c '^kind: DebugSessionTemplate$' "${rendered}")" -eq 4 ]]
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

helm template debug-catalogue "${chart_dir}" \
  --values "${chart_dir}/ci/elevated-optin-values.yaml" >/dev/null

echo "debug-session-catalogue validation passed"
