#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

chart_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
rendered="$(mktemp)"
trap 'rm -f "${rendered}"' EXIT

helm lint "${chart_dir}" --strict
helm template debug-catalogue "${chart_dir}" \
  --values "${chart_dir}/ci/test-values.yaml" >"${rendered}"

[[ "$(grep -c '^kind: DebugPodTemplate$' "${rendered}")" -eq 4 ]]
[[ "$(grep -c '^kind: DebugSessionTemplate$' "${rendered}")" -eq 4 ]]
! grep -q 'hostNetwork: true' "${rendered}"
! grep -q 'privileged: true' "${rendered}"

if helm template debug-catalogue "${chart_dir}" \
  --set 'profiles.dump-access.enabled=true' >/dev/null 2>&1; then
  echo "dump-access must require elevated: true" >&2
  exit 1
fi

helm template debug-catalogue "${chart_dir}" \
  --set 'profiles.dump-access.enabled=true' \
  --set 'profiles.dump-access.elevated=true' >/dev/null

echo "debug-session-catalogue validation passed"
