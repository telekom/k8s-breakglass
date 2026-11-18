#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
#
# Fails when a row of the DebugSession acceptance matrix cites a test that no
# longer exists. References have the form `path/to/file_test.go::TestName`,
# optionally followed by `(subtest "a", "b")`; cited subtest names must still
# appear in the cited file. Run from the repository root.
set -euo pipefail

matrix="${1:-docs/debug-session-acceptance-matrix.md}"
missing=0

# A malformed reference (e.g. a single colon) would otherwise be skipped silently.
malformed=$(grep -oE '[A-Za-z0-9_./-]+\.go:+[A-Za-z0-9_]+' "$matrix" | grep -vE '\.go::[A-Za-z0-9_]+$' || true)
if [ -n "$malformed" ]; then
  echo "$matrix: malformed test reference(s), use file.go::TestName:" >&2
  echo "$malformed" >&2
  missing=1
fi

refs=$(grep -oE '[A-Za-z0-9_./-]+\.go::[A-Za-z0-9_]+' "$matrix" | sort -u || true)
if [ -z "$refs" ]; then
  echo "no test references found in $matrix" >&2
  exit 1
fi
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

# Subtest names quoted after a reference must exist in the cited file.
while IFS= read -r cited; do
  [ -n "$cited" ] || continue
  file="${cited%%::*}"
  [ -f "$file" ] || continue
  while IFS= read -r subtest; do
    if ! grep -qF -- "$subtest" "$file"; then
      echo "$matrix: ${cited%%\`*}: no subtest $subtest" >&2
      missing=1
    fi
  done < <(grep -oE '"[^"]+"' <<<"${cited#*(}")
done < <(grep -oE '[A-Za-z0-9_./-]+\.go::[A-Za-z0-9_]+`` \(subtests? [^)]*\)' "$matrix" || true)

[ "$missing" -eq 0 ] && echo "acceptance matrix: $(wc -l <<<"$refs" | tr -d ' ') test references verified"
exit "$missing"
