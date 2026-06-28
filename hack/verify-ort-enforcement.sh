#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

ort_fail_on_pattern="^[[:space:]]*fail-on:[[:space:]]*['\"]?issues,violations['\"]?([[:space:]]+#.*)?[[:space:]]*$"

verify_ort_workflow() {
  local ort_workflow="$1"

  if [ ! -f "${ort_workflow}" ]; then
    echo "::error file=${ort_workflow}::ORT workflow not found" >&2
    return 1
  fi

  if ! grep -qE -- "${ort_fail_on_pattern}" "${ort_workflow}"; then
    echo "::error file=${ort_workflow}::ORT workflow must set fail-on: 'issues,violations' so unresolved issues and policy violations fail CI" >&2
    return 1
  fi

  echo "ORT enforcement workflow guard passed"
}

run_self_test() {
  local tmp_dir
  tmp_dir="$(mktemp -d)"
  trap 'rm -rf "${tmp_dir}"' RETURN

  printf "%s\n" \
    "with:" \
    "  fail-on: 'issues,violations' # required" \
    >"${tmp_dir}/quoted.yml"
  verify_ort_workflow "${tmp_dir}/quoted.yml" >/dev/null

  printf "%s\n" \
    "with:" \
    "  fail-on: issues,violations" \
    >"${tmp_dir}/unquoted.yml"
  verify_ort_workflow "${tmp_dir}/unquoted.yml" >/dev/null

  printf "%s\n" \
    "with:" \
    "  # fail-on: 'issues,violations'" \
    >"${tmp_dir}/commented.yml"
  if verify_ort_workflow "${tmp_dir}/commented.yml" >/dev/null 2>&1; then
    echo "::error::ORT enforcement guard accepted a commented fail-on key" >&2
    exit 1
  fi

  echo "ORT enforcement workflow guard self-test passed"
}

if [ "${1:-}" = "--self-test" ]; then
  run_self_test
else
  verify_ort_workflow "${1:-.github/workflows/ort.yml}"
fi
