#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -eu

root=$(cd -- "$(dirname -- "$0")/.." && pwd)
reader="$root/bin/dump-reader"
test_dir=$(mktemp -d "${TMPDIR:-/tmp}/dump-reader-test.XXXXXX")
outside_dir=$(mktemp -d "${TMPDIR:-/tmp}/dump-reader-outside.XXXXXX")
trap 'rm -rf "$test_dir" "$outside_dir"' EXIT HUP INT TERM
mkdir "$test_dir/output"
mkdir "$test_dir/output/sub" "$test_dir/output/nested"
chmod 0755 "$test_dir" "$test_dir/output"
ln -s "$test_dir/output" "$test_dir/output/nested/path-link"
printf '%s\n' 'existing artifact' >"$test_dir/source.dump"
printf '%s\n' 'outside artifact' >"$outside_dir/outside.dump"

inspect=$(DUMP_INPUT_DIR="$test_dir" $reader inspect "$test_dir/source.dump")
printf '%s\n' "$inspect" | grep -F 'schema_version=dump-reader/v1' >/dev/null
printf '%s\n' "$inspect" | grep -F 'name=source.dump' >/dev/null
printf '%s\n' "$inspect" | grep -F 'size_bytes=18' >/dev/null

checksum=$(DUMP_INPUT_DIR="$test_dir" $reader checksum "$test_dir/source.dump")
printf '%s\n' "$checksum" | grep -F 'sha256=63a0c194794026e2f3e0374882bff803c4eae4822e7bc891766bb5f28c2c756f' >/dev/null

copy=$(DUMP_INPUT_DIR="$test_dir" DUMP_OUTPUT_DIR="$test_dir/output" $reader copy "$test_dir/source.dump")
printf '%s\n' "$copy" | grep -F 'name=source.dump' >/dev/null
cmp "$test_dir/source.dump" "$test_dir/output/source.dump"
test -r "$test_dir/output/source.dump"
if su nobody -s /bin/sh -c "test -r '$test_dir/output/source.dump'" 2>/dev/null; then
    echo "dump artifact was readable by a different UID" >&2
    exit 1
fi

if DUMP_INPUT_DIR="$test_dir" $reader copy "$test_dir/source.dump" >/dev/null 2>&1; then
    echo "copy unexpectedly succeeded without a writable output mount" >&2
    exit 1
fi
if DUMP_INPUT_DIR="$test_dir" $reader inspect "$test_dir/output/missing.dump" >/dev/null 2>&1; then
    echo "missing source unexpectedly succeeded" >&2
    exit 1
fi
ln -s source.dump "$test_dir/link.dump"
if DUMP_INPUT_DIR="$test_dir" $reader inspect "$test_dir/link.dump" >/dev/null 2>&1; then
    echo "symbolic link unexpectedly accepted" >&2
    exit 1
fi
if DUMP_INPUT_DIR="$test_dir" DUMP_OUTPUT_DIR="$test_dir/output" $reader copy "$test_dir/source.dump" >/dev/null 2>&1; then
    echo "overwrite unexpectedly succeeded" >&2
    exit 1
fi

mkdir "$test_dir/input"
if DUMP_INPUT_DIR="$test_dir/input" $reader inspect "$test_dir/input/../source.dump" >/dev/null 2>&1; then
    echo "input traversal unexpectedly succeeded" >&2
    exit 1
fi
mkdir "$test_dir/escaped"
ln -s "$outside_dir" "$test_dir/escaped/link-dir"
if DUMP_INPUT_DIR="$test_dir" $reader inspect "$test_dir/escaped/link-dir/outside.dump" >/dev/null 2>&1; then
    echo "symlink-directory traversal unexpectedly succeeded" >&2
    exit 1
fi
ln -s "$test_dir/source.dump" "$test_dir/output/dangling-check"
rm "$test_dir/output/dangling-check"
ln -s "$test_dir/missing.dump" "$test_dir/output/dangling-check"
if DUMP_INPUT_DIR="$test_dir" DUMP_OUTPUT_DIR="$test_dir/output" $reader copy "$test_dir/source.dump" dangling-check >/dev/null 2>&1; then
    echo "dangling output symlink unexpectedly accepted" >&2
    exit 1
fi
if DUMP_INPUT_DIR="$test_dir" DUMP_OUTPUT_DIR="$test_dir/output/nested/path-link/sub" \
    $reader copy "$test_dir/source.dump" nested-link.dump >/dev/null 2>&1; then
    echo "nested output symlink unexpectedly accepted" >&2
    exit 1
fi
ln -s "$test_dir/output" "$test_dir/output-link"
if DUMP_INPUT_DIR="$test_dir" DUMP_OUTPUT_DIR="$test_dir/output-link/" $reader copy "$test_dir/source.dump" trailing-link.dump >/dev/null 2>&1; then
    echo "trailing output symlink unexpectedly accepted" >&2
    exit 1
fi
if DUMP_INPUT_DIR="$test_dir" DUMP_OUTPUT_DIR="$test_dir/output" DUMP_MAX_COPY_BYTES=1 \
    $reader copy "$test_dir/source.dump" too-large.dump >/dev/null 2>&1; then
    echo "copy size bound was not enforced" >&2
    exit 1
fi

echo "dump-reader tests passed"
