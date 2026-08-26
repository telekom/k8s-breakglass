#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

# Administrative preflight for the environment protection that gates
# development publication. Repository variables cannot prove environment
# protection settings; run this with a token that can read environments.

set -Eeuo pipefail

repository="${GH_REPO:-${GITHUB_REPOSITORY:-}}"
environment="${1:-}"
[[ "${repository}" =~ ^[^/[:space:]]+/[^/[:space:]]+$ ]] || {
  echo "GH_REPO must be owner/name (or set GITHUB_REPOSITORY)" >&2
  exit 2
}
[[ "${environment}" =~ ^[A-Za-z0-9_.-]+$ ]] || {
  echo "environment must contain only URL-safe name characters" >&2
  exit 2
}
command -v gh >/dev/null || { echo "gh is required" >&2; exit 2; }
command -v jq >/dev/null || { echo "jq is required" >&2; exit 2; }

error_file="$(mktemp)"
trap 'rm -f "${error_file}"' EXIT
if ! response="$(gh api "repos/${repository}/environments/${environment}" 2>"${error_file}")"; then
  echo "cannot read environment protection; an admin-readable GH_TOKEN is required" >&2
  cat "${error_file}" >&2
  exit 1
fi

if ! jq -e '
  [.protection_rules[]? | select(.type == "required_reviewers") |
    select((.reviewers | type == "array") and (.reviewers | length > 0) and
      (.prevent_self_review == true))] | length > 0
' <<<"${response}" >/dev/null; then
  echo "environment lacks non-empty required reviewers with self-review prevention" >&2
  exit 1
fi

echo "${repository}/${environment}: required reviewers and self-review prevention are enabled"
