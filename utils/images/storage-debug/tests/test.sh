#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -eu

root=$(cd -- "$(dirname -- "$0")/.." && pwd)
report="$root/bin/storage-report"
dispatcher="$root/bin/storage-diagnostics"
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/storage-debug-test.XXXXXX")
outside_dir=$(mktemp -d "${TMPDIR:-/tmp}/storage-debug-outside.XXXXXX")
fake_bin="$test_dir/bin"
trap 'rm -rf "$test_dir" "$outside_dir"' EXIT HUP INT TERM
mkdir "$fake_bin"
mkdir "$test_dir/target" "$test_dir/nested"
chmod 0755 "$test_dir"
ln -s "$test_dir" "$test_dir/nested/path-link"
printf '%s\n' 'do not remove' >"$test_dir/.storage-debug-fio"

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
STORAGE_REPORT_DIR="$test_dir" PATH="$fake_bin:$PATH" $report --path "$test_dir" --size-mb 1 --runtime-seconds 1 \
    --ioping-count 1 --output "$report_output" >/dev/null
grep -F 'fio_status=pass' "$report_output" >/dev/null
grep -F 'ioping_status=pass' "$report_output" >/dev/null
grep -F 'overall_status=pass' "$report_output" >/dev/null
grep -F 'do not remove' "$test_dir/.storage-debug-fio" >/dev/null
test -r "$report_output"
if su nobody -s /bin/sh -c "test -r '$report_output'" 2>/dev/null; then
    echo "storage report was readable by a different UID" >&2
    exit 1
fi

if STORAGE_REPORT_DIR="$test_dir" PATH="$fake_bin:$PATH" $report --path "$test_dir" --output "$report_output" \
    >/dev/null 2>&1; then
    echo "existing report unexpectedly overwritten" >&2
    exit 1
fi
ln -s "$test_dir/missing-report.txt" "$test_dir/dangling-report.txt"
if STORAGE_REPORT_DIR="$test_dir" PATH="$fake_bin:$PATH" $report --path "$test_dir" --output "$test_dir/dangling-report.txt" \
    >/dev/null 2>&1; then
    echo "dangling report symlink unexpectedly accepted" >&2
    exit 1
fi
if STORAGE_REPORT_DIR="$test_dir" PATH="$fake_bin:$PATH" $report --path "$test_dir" --output "$outside_dir/report.txt" \
    >/dev/null 2>&1; then
    echo "report path traversal unexpectedly accepted" >&2
    exit 1
fi
ln -s "$test_dir" "$test_dir/path-link"
if PATH="$fake_bin:$PATH" $report --path "$test_dir/path-link" --dry-run >/dev/null 2>&1; then
    echo "symbolic-link test path unexpectedly accepted" >&2
    exit 1
fi
if PATH="$fake_bin:$PATH" $report --path "$test_dir/path-link/" --dry-run >/dev/null 2>&1; then
    echo "trailing symbolic-link test path unexpectedly accepted" >&2
    exit 1
fi
if PATH="$fake_bin:$PATH" $report --path "$test_dir/nested/path-link/target" --dry-run >/dev/null 2>&1; then
    echo "nested symbolic-link test path unexpectedly accepted" >&2
    exit 1
fi
if PATH="$fake_bin:$PATH" $report --path "$test_dir/../etc" --dry-run >/dev/null 2>&1; then
    echo "test path traversal unexpectedly accepted" >&2
    exit 1
fi

immutable_image="registry.example/storage-debug@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
plan=$(POD_NAMESPACE=incident-123 STORAGE_DEBUG_WORKLOAD_IMAGE="$immutable_image" \
    "$dispatcher" plan performance --storage-class fast-csi --pvc-size 8Gi)
printf '%s\n' "$plan" | grep -Fx 'schema_version=storage-diagnostics/v1' >/dev/null
printf '%s\n' "$plan" | grep -Fx 'intent=storage-diagnostics' >/dev/null
printf '%s\n' "$plan" | grep -Fx 'operation=performance' >/dev/null
printf '%s\n' "$plan" | grep -F -- '--testname default-fio' >/dev/null
printf '%s\n' "$plan" | grep -F -- '--size 8Gi' >/dev/null
printf '%s\n' "$plan" | grep -F -- "--image $immutable_image" >/dev/null

snapshot_plan=$(POD_NAMESPACE=incident-123 STORAGE_DEBUG_WORKLOAD_IMAGE="$immutable_image" \
    "$dispatcher" plan snapshot-restore --storage-class fast-csi --snapshot-class fast-snapshots)
printf '%s\n' "$snapshot_plan" | grep -F -- '--cleanup=true' >/dev/null
printf '%s\n' "$snapshot_plan" | grep -F -- '--skipCFScheck=true' >/dev/null

clone_plan=$(POD_NAMESPACE=incident-123 STORAGE_DEBUG_WORKLOAD_IMAGE="$immutable_image" \
    "$dispatcher" plan snapshot-source-clone --storage-class fast-csi --snapshot-class fast-snapshots)
printf '%s\n' "$clone_plan" | grep -F -- '--skipCFScheck=false' >/dev/null

block_plan=$(POD_NAMESPACE=incident-123 STORAGE_DEBUG_WORKLOAD_IMAGE="$immutable_image" \
    "$dispatcher" plan block-volume --storage-class fast-csi)
printf '%s\n' "$block_plan" | grep -F -- '--cleanup=true' >/dev/null
printf '%s\n' "$block_plan" | grep -F -- '--wait-timeout 120' >/dev/null

if POD_NAMESPACE=incident-123 STORAGE_DEBUG_WORKLOAD_IMAGE="$immutable_image" \
    "$dispatcher" plan performance --storage-class fast-csi --image attacker.example/tool:latest >/dev/null 2>&1; then
    echo "performance accepted a user-selected image" >&2
    exit 1
fi
if POD_NAMESPACE=incident-123 STORAGE_DEBUG_WORKLOAD_IMAGE="$immutable_image" \
    "$dispatcher" plan performance --storage-class fast-csi --fiofile /tmp/arbitrary.fio >/dev/null 2>&1; then
    echo "performance accepted an arbitrary fio program" >&2
    exit 1
fi
if POD_NAMESPACE=incident-123 STORAGE_DEBUG_WORKLOAD_IMAGE=registry.example/storage-debug:latest \
    "$dispatcher" plan performance --storage-class fast-csi >/dev/null 2>&1; then
    echo "performance accepted a mutable child image" >&2
    exit 1
fi
if POD_NAMESPACE=incident-123 STORAGE_DEBUG_WORKLOAD_IMAGE="$immutable_image" \
    "$dispatcher" plan performance --storage-class fast-csi --pvc-size 100Gi >/dev/null 2>&1; then
    echo "performance accepted an out-of-contract PVC size" >&2
    exit 1
fi
if POD_NAMESPACE='incident/other' STORAGE_DEBUG_WORKLOAD_IMAGE="$immutable_image" \
    "$dispatcher" plan block-volume --storage-class fast-csi >/dev/null 2>&1; then
    echo "cluster operation accepted an invalid namespace" >&2
    exit 1
fi
if POD_NAMESPACE='incident.other' STORAGE_DEBUG_WORKLOAD_IMAGE="$immutable_image" \
    "$dispatcher" plan block-volume --storage-class fast-csi >/dev/null 2>&1; then
    echo "cluster operation accepted a dotted namespace" >&2
    exit 1
fi
if POD_NAMESPACE=incident-123 STORAGE_DEBUG_WORKLOAD_IMAGE="$immutable_image" \
    "$dispatcher" plan performance --storage-class 'fast..csi' >/dev/null 2>&1; then
    echo "cluster operation accepted an invalid DNS storage class" >&2
    exit 1
fi

mounted=$($dispatcher mounted-volume --path "$test_dir" --size-mb 1 --runtime-seconds 1 --ioping-count 1 --dry-run)
printf '%s\n' "$mounted" | grep -Fx 'schema_version=storage-debug/v1' >/dev/null
docs=$($dispatcher docs)
printf '%s\n' "$docs" | grep -Fx 'upstream=/usr/share/breakglass/runbooks/upstream/storage-diagnostics' >/dev/null
printf '%s\n' "$docs" | grep -Fx 'internal=/usr/share/breakglass/runbooks/internal (optional read-only image-volume mount)' >/dev/null
$dispatcher runbook >/dev/null

echo "storage-debug tests passed"
