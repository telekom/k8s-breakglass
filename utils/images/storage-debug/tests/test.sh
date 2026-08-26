#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -eu

root=$(cd -- "$(dirname -- "$0")/.." && pwd)
report="$root/bin/storage-report"
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/storage-debug-test.XXXXXX")
fake_bin="$test_dir/bin"
trap 'rm -rf "$test_dir"' EXIT HUP INT TERM
mkdir "$fake_bin"

printf '%s\n' '#!/bin/sh' 'exit 0' >"$fake_bin/fio"
printf '%s\n' '#!/bin/sh' 'exit 0' >"$fake_bin/ioping"
printf '%s\n' '#!/bin/sh' 'shift' 'exec "$@"' >"$fake_bin/timeout"
chmod 0755 "$fake_bin/fio" "$fake_bin/ioping"
chmod 0755 "$fake_bin/timeout"

dry_run=$($report --path "$test_dir" --size-mb 2 --runtime-seconds 1 --ioping-count 1 --dry-run)
printf '%s\n' "$dry_run" | grep -F 'schema_version=storage-debug/v1' >/dev/null
printf '%s\n' "$dry_run" | grep -F -- '--runtime=1s' >/dev/null

if $report --path "$test_dir" --runtime-seconds 61 --dry-run >/dev/null 2>&1; then
    echo "runtime bound was not enforced" >&2
    exit 1
fi

report_output="$test_dir/report.txt"
PATH="$fake_bin:$PATH" $report --path "$test_dir" --size-mb 1 --runtime-seconds 1 \
    --ioping-count 1 --output "$report_output" >/dev/null
grep -F 'fio_status=pass' "$report_output" >/dev/null
grep -F 'ioping_status=pass' "$report_output" >/dev/null
grep -F 'overall_status=pass' "$report_output" >/dev/null

echo "storage-debug tests passed"
