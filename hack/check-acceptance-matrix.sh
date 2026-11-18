#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
#
# Fails when a row of the DebugSession acceptance matrix cites a test that no
# longer exists. References have the form `path/to/file_test.go::TestName`.
set -euo pipefail

matrix="${1:-docs/debug-session-acceptance-matrix.md}"
refs=$(grep -oE '[A-Za-z0-9_./-]+\.go::[A-Za-z0-9_]+' "$matrix" | sort -u || true)
if [ -z "$refs" ]; then
  echo "no test references found in $matrix" >&2
  exit 1
fi

missing=0
while IFS= read -r ref; do
  file="${ref%%::*}"
  name="${ref##*::}"
  if [ ! -f "$file" ]; then
    echo "$matrix: $ref: file not found" >&2
    missing=1
  elif ! grep -qE "^func ${name}\(" "$file"; then
    echo "$matrix: $ref: no such test function" >&2
    missing=1
  fi
done <<<"$refs"

[ "$missing" -eq 0 ] && echo "acceptance matrix: $(wc -l <<<"$refs" | tr -d ' ') test references verified"
exit "$missing"
