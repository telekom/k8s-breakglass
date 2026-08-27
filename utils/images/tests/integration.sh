#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -eu

images_root=$(cd -- "$(dirname -- "$0")/.." && pwd)
test_root=$(mktemp -d "${TMPDIR:-/tmp}/utility-images-integration.XXXXXX")
storage_volume=$test_root/storage
storage_reports=$test_root/storage-reports
storage_read_only=$test_root/storage-read-only
dump_input=$test_root/dump-input
dump_output=$test_root/dump-output
outside=$test_root/outside
storage_metadata=$images_root/storage-debug/image-metadata.yaml
dump_metadata=$images_root/dump-reader/image-metadata.yaml
remove_storage_image=0
remove_dump_image=0
test_version=utility-integration-version
test_revision=utility-integration-revision
test_created=2026-01-02T03:04:05Z

fail() {
    echo "utility image integration: $1" >&2
    exit 1
}

metadata_value() {
    ruby - "$1" "$2" <<'RUBY'
require "yaml"
document = YAML.safe_load(File.read(ARGV.fetch(0)), aliases: false)
value = document.fetch("runtime").fetch(ARGV.fetch(1))
abort "metadata value is not scalar" if value.is_a?(Hash) || value.is_a?(Array)
puts value
RUBY
}

metadata_base_value() {
    ruby - "$1" "$2" <<'RUBY'
require "yaml"
document = YAML.safe_load(File.read(ARGV.fetch(0)), aliases: false)
puts document.fetch("base").fetch(ARGV.fetch(1))
RUBY
}

storage_expected_user=$(metadata_value "$storage_metadata" user)
storage_expected_base_name=$(metadata_base_value "$storage_metadata" image)
storage_expected_base_digest=$(metadata_base_value "$storage_metadata" digest)
storage_expected_entrypoint=$(ruby - "$storage_metadata" <<'RUBY'
require "yaml"
document = YAML.safe_load(File.read(ARGV.fetch(0)), aliases: false)
puts document.fetch("contract").fetch("executable")
RUBY
)
dump_expected_user=$(metadata_value "$dump_metadata" user)
dump_expected_base_name=$(metadata_base_value "$dump_metadata" image)
dump_expected_base_digest=$(metadata_base_value "$dump_metadata" digest)
dump_expected_entrypoint=$(ruby - "$dump_metadata" <<'RUBY'
require "yaml"
document = YAML.safe_load(File.read(ARGV.fetch(0)), aliases: false)
puts document.fetch("contract").fetch("executable")
RUBY
)

if [ -n "${STORAGE_IMAGE:-}" ]; then
    storage_image=$STORAGE_IMAGE
else
    storage_image=tcaas1618-storage-debug:integration-$$
    remove_storage_image=1
fi
if [ -n "${DUMP_IMAGE:-}" ]; then
    dump_image=$DUMP_IMAGE
else
    dump_image=tcaas1618-dump-reader:integration-$$
    remove_dump_image=1
fi

cleanup() {
    status=$?
    if [ "$remove_storage_image" -eq 1 ]; then
        docker image rm "$storage_image" >/dev/null 2>&1 || true
    fi
    if [ "$remove_dump_image" -eq 1 ]; then
        docker image rm "$dump_image" >/dev/null 2>&1 || true
    fi
    rm -rf "$test_root"
    exit "$status"
}
trap cleanup EXIT HUP INT TERM

command -v docker >/dev/null 2>&1 || fail "docker is required; integration tests do not silently skip"
docker buildx version >/dev/null 2>&1 || fail "docker buildx is required"
docker info >/dev/null 2>&1 || fail "Docker daemon is unavailable; integration tests do not silently skip"

arch=$(docker info --format '{{.Architecture}}')
case "${IMAGE_PLATFORM:-linux/$arch}" in
    linux/amd64|linux/arm64) platform=${IMAGE_PLATFORM:-linux/$arch} ;;
    linux/x86_64) platform=linux/amd64 ;;
    linux/aarch64) platform=linux/arm64 ;;
    *) fail "set IMAGE_PLATFORM to linux/amd64 or linux/arm64 (detected ${IMAGE_PLATFORM:-linux/$arch})" ;;
esac

mkdir -p "$storage_volume" "$storage_reports" "$storage_read_only" \
    "$dump_input/subdir" "$dump_output" "$outside"
# The container UID is intentionally not the host user. These are temporary,
# disposable fixtures, so grant only the access needed by the test mounts.
chmod 0777 "$storage_volume" "$storage_reports" "$storage_read_only" \
    "$dump_input" "$dump_input/subdir" "$dump_output"
printf '%s\n' 'keep this pre-existing file' >"$storage_volume/existing-data"
ln -s existing-data "$storage_volume/path-link"
mkdir "$storage_volume/nested"
ln -s /scratch "$storage_volume/nested/path-link"
printf '%s\n' 'real dump fixture for integration' >"$dump_input/existing.dump"
printf '%s\n' 'nested fixture' >"$dump_input/subdir/nested.dump"
printf '%s\n' 'outside fixture' >"$outside/outside.dump"
ln -s existing.dump "$dump_input/source-link.dump"
ln -s "$outside" "$dump_input/escape-dir"
ln -s "$dump_input/existing.dump" "$dump_output/destination-link"
mkdir "$dump_output/subdir" "$dump_output/nested"
ln -s /output "$dump_output/nested/path-link"

echo "building utility images for ${platform}"
docker buildx build --load --platform "$platform" \
    --build-arg VERSION="$test_version" \
    --build-arg VCS_REF="$test_revision" \
    --build-arg BUILD_DATE="$test_created" \
    -t "$storage_image" "$images_root/storage-debug"
docker buildx build --load --platform "$platform" \
    --build-arg VERSION="$test_version" \
    --build-arg VCS_REF="$test_revision" \
    --build-arg BUILD_DATE="$test_created" \
    -t "$dump_image" "$images_root/dump-reader"

assert_image_label() {
    image=$1
    label=$2
    expected=$3
    actual=$(docker image inspect "$image" --format "{{ index .Config.Labels \"$label\" }}")
    [ "$actual" = "$expected" ] || fail "$image label $label is $actual, expected $expected"
}

echo "checking OCI traceability labels"
for image in "$storage_image" "$dump_image"; do
    assert_image_label "$image" org.opencontainers.image.version "$test_version"
    assert_image_label "$image" org.opencontainers.image.revision "$test_revision"
    assert_image_label "$image" org.opencontainers.image.created "$test_created"
done
assert_image_label "$storage_image" org.opencontainers.image.base.name "$storage_expected_base_name"
assert_image_label "$storage_image" org.opencontainers.image.base.digest "$storage_expected_base_digest"
assert_image_label "$dump_image" org.opencontainers.image.base.name "$dump_expected_base_name"
assert_image_label "$dump_image" org.opencontainers.image.base.digest "$dump_expected_base_digest"

storage_user=$(docker image inspect "$storage_image" --format '{{.Config.User}}')
dump_user=$(docker image inspect "$dump_image" --format '{{.Config.User}}')
[ "$storage_user" = "$storage_expected_user" ] || fail "storage image user is $storage_user, metadata requires $storage_expected_user"
[ "$dump_user" = "$dump_expected_user" ] || fail "dump image user is $dump_user, metadata requires $dump_expected_user"

check_image_runtime() {
    image=$1
    docker run --rm --platform "$platform" --read-only --network none --cap-drop=ALL \
        --security-opt=no-new-privileges --tmpfs /tmp:rw,nosuid,nodev,size=64m \
        --entrypoint /bin/sh "$image" -c \
        'test "$(id -u):$(id -g)" = 65532:65532 && ! touch /usr/local/bin/integration-write-test'
}

check_image_runtime "$storage_image"
check_image_runtime "$dump_image"

run_storage() {
    docker run --rm --platform "$platform" --read-only --network none --cap-drop=ALL \
        --security-opt=no-new-privileges --tmpfs /tmp:rw,nosuid,nodev,size=64m \
        --mount "type=bind,src=$storage_volume,dst=/scratch" \
        --mount "type=bind,src=$storage_reports,dst=/reports" \
        -e STORAGE_REPORT_DIR=/reports "$storage_image" "$@"
}

run_storage_read_only() {
    docker run --rm --platform "$platform" --read-only --network none --cap-drop=ALL \
        --security-opt=no-new-privileges --tmpfs /tmp:rw,nosuid,nodev,size=64m \
        --mount "type=bind,src=$storage_read_only,dst=/scratch,readonly" \
        --mount "type=bind,src=$storage_reports,dst=/reports" \
        -e STORAGE_REPORT_DIR=/reports "$storage_image" "$@"
}

read_storage_report() {
    docker run --rm --platform "$platform" --read-only --network none --cap-drop=ALL \
        --security-opt=no-new-privileges --tmpfs /tmp:rw,nosuid,nodev,size=64m \
        --mount "type=bind,src=$storage_reports,dst=/reports,readonly" \
        --user 65532:65532 --entrypoint /bin/sh "$storage_image" -c "$1"
}

run_dump() {
    docker run --rm --platform "$platform" --read-only --network none --cap-drop=ALL \
        --security-opt=no-new-privileges --tmpfs /tmp:rw,nosuid,nodev,size=64m \
        --mount "type=bind,src=$dump_input,dst=/input,readonly" \
        --mount "type=bind,src=$dump_output,dst=/output" \
        "$dump_image" "$@"
}

read_dump_output() {
    docker run --rm --platform "$platform" --read-only --network none --cap-drop=ALL \
        --security-opt=no-new-privileges --tmpfs /tmp:rw,nosuid,nodev,size=64m \
        --mount "type=bind,src=$dump_input,dst=/input,readonly" \
        --mount "type=bind,src=$dump_output,dst=/output,readonly" \
        --user 65532:65532 --entrypoint /bin/sh "$dump_image" -c "$1"
}

check_image_contract() {
    image=$1
    expected_entrypoint=$2
    actual_entrypoint=$(docker image inspect "$image" --format '{{index .Config.Entrypoint 0}}')
    [ "$actual_entrypoint" = "$expected_entrypoint" ] || fail "${image} entrypoint is ${actual_entrypoint}, metadata requires ${expected_entrypoint}"
}

check_image_contract "$storage_image" "$storage_expected_entrypoint"
check_image_contract "$dump_image" "$dump_expected_entrypoint"
run_storage --help >/dev/null
run_dump help >/dev/null

assert_no_residuals() {
    directory=$1
    for candidate in "$directory"/.storage-debug-fio.* \
        "$directory"/.storage-report.* "$directory"/.dump-reader.*; do
        if [ -e "$candidate" ] || [ -L "$candidate" ]; then
            fail "temporary artifact remains: $candidate"
        fi
    done
}

echo "checking storage-report command modes and real tools"
dry_output=$(run_storage_read_only --path /scratch --size-mb 1 \
    --runtime-seconds 1 --ioping-count 1 --dry-run)
printf '%s\n' "$dry_output" | grep -F 'schema_version=storage-debug/v1' >/dev/null
printf '%s\n' "$dry_output" | grep -F 'filename=/scratch/.storage-debug-fio.XXXXXX' >/dev/null

stdout_output=$(run_storage --path /scratch --size-mb 1 --runtime-seconds 1 --ioping-count 1)
printf '%s\n' "$stdout_output" | grep -F 'fio_status=pass' >/dev/null
printf '%s\n' "$stdout_output" | grep -F 'ioping_status=pass' >/dev/null
printf '%s\n' "$stdout_output" | grep -F 'overall_status=pass' >/dev/null

run_storage --path /scratch --size-mb 1 --runtime-seconds 1 --ioping-count 1 \
    --output /reports/storage-report.txt >/dev/null
read_storage_report "grep -F 'overall_status=pass' /reports/storage-report.txt"
read_storage_report "grep -Eq '^size_mib=1$' /reports/storage-report.txt"
read_storage_report "grep -Eq '^runtime_seconds=1$' /reports/storage-report.txt"
read_storage_report "grep -Eq '^ioping_count=1$' /reports/storage-report.txt"

if run_storage_read_only --path /scratch --size-mb 1 --runtime-seconds 1 \
    --ioping-count 1 >/dev/null 2>&1; then
    fail "real fio run unexpectedly succeeded on a read-only mount"
fi
if run_storage --path /scratch --size-mb 1025 --dry-run >/dev/null 2>&1; then
    fail "size bound was not enforced"
fi
if run_storage --path /scratch --runtime-seconds 61 --dry-run >/dev/null 2>&1; then
    fail "runtime bound was not enforced"
fi
if run_storage --path /scratch --ioping-count 21 --dry-run >/dev/null 2>&1; then
    fail "ioping count bound was not enforced"
fi
if run_storage --path /scratch --size-mb 1 --runtime-seconds 1 --ioping-count 1 \
    --output /tmp/outside-report.txt >/dev/null 2>&1; then
    fail "report path escaped STORAGE_REPORT_DIR"
fi
if run_storage --path /scratch --size-mb 1 --runtime-seconds 1 --ioping-count 1 \
    --output /reports/storage-report.txt >/dev/null 2>&1; then
    fail "existing report was overwritten"
fi
if run_storage --path /scratch/path-link --dry-run >/dev/null 2>&1; then
    fail "symbolic-link test path was accepted"
fi
if run_storage --path /scratch/nested/path-link/nested --dry-run >/dev/null 2>&1; then
    fail "nested symbolic-link test path was accepted"
fi
if run_storage --path /scratch/../etc --dry-run >/dev/null 2>&1; then
    fail "test path traversal was accepted"
fi
assert_no_residuals "$storage_volume"
assert_no_residuals "$storage_reports"
[ -e "$storage_volume/existing-data" ] || fail "pre-existing storage file disappeared"

echo "checking dump-reader metadata, checksum, and safe copy"
dump_size=$(wc -c <"$dump_input/existing.dump" | tr -d '[:space:]')
expected_hash=$(if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$dump_input/existing.dump"
else
    shasum -a 256 "$dump_input/existing.dump"
fi | awk '{print $1}')

inspect_output=$(run_dump inspect /input/existing.dump)
printf '%s\n' "$inspect_output" | grep -F 'schema_version=dump-reader/v1' >/dev/null
printf '%s\n' "$inspect_output" | grep -F "size_bytes=$dump_size" >/dev/null
printf '%s\n' "$inspect_output" | grep -Eq '^mode=-[rwx-]+$'
printf '%s\n' "$inspect_output" | grep -Eq '^uid=[0-9]+$'
printf '%s\n' "$inspect_output" | grep -Eq '^gid=[0-9]+$'
printf '%s\n' "$inspect_output" | grep -Eq '^mtime_epoch=[0-9]+$'

checksum_output=$(run_dump checksum /input/existing.dump)
printf '%s\n' "$checksum_output" | grep -F "sha256=$expected_hash" >/dev/null

copy_output=$(run_dump copy /input/existing.dump copied.dump)
printf '%s\n' "$copy_output" | grep -F 'name=copied.dump' >/dev/null
printf '%s\n' "$copy_output" | grep -F "bytes=$dump_size" >/dev/null
printf '%s\n' "$copy_output" | grep -F "sha256=$expected_hash" >/dev/null
read_dump_output "cmp /input/existing.dump /output/copied.dump"

if run_dump generate /input/existing.dump >/dev/null 2>&1; then
    fail "dump generation command unexpectedly exists"
fi
if run_dump inspect /input/missing.dump >/dev/null 2>&1; then
    fail "missing dump unexpectedly succeeded"
fi
if run_dump inspect /input/subdir >/dev/null 2>&1; then
    fail "directory input unexpectedly succeeded"
fi
if run_dump inspect /input/source-link.dump >/dev/null 2>&1; then
    fail "symbolic-link input unexpectedly succeeded"
fi
if run_dump inspect /input/escape-dir/outside.dump >/dev/null 2>&1; then
    fail "symlink-directory escape unexpectedly succeeded"
fi
if run_dump inspect /input/../etc/passwd >/dev/null 2>&1; then
    fail "input traversal unexpectedly succeeded"
fi
if run_dump copy /input/existing.dump copied.dump >/dev/null 2>&1; then
    fail "copy overwrite unexpectedly succeeded"
fi
if run_dump copy /input/existing.dump ../escaped.dump >/dev/null 2>&1; then
    fail "copy output traversal unexpectedly succeeded"
fi
if run_dump copy /input/existing.dump /tmp/escaped.dump >/dev/null 2>&1; then
    fail "absolute copy output unexpectedly succeeded"
fi
if run_dump copy /input/existing.dump destination-link >/dev/null 2>&1; then
    fail "copy to output symlink unexpectedly succeeded"
fi
if docker run --rm --platform "$platform" --read-only --network none --cap-drop=ALL \
    --security-opt=no-new-privileges --tmpfs /tmp:rw,nosuid,nodev,size=64m \
    --mount "type=bind,src=$dump_input,dst=/input,readonly" \
    --mount "type=bind,src=$dump_output,dst=/output" \
    -e DUMP_OUTPUT_DIR=/output/nested/path-link/subdir "$dump_image" \
    copy /input/existing.dump nested-copy.dump >/dev/null 2>&1; then
    fail "copy through a nested output symlink unexpectedly succeeded"
fi
if docker run --rm --platform "$platform" --read-only --network none --cap-drop=ALL \
    --security-opt=no-new-privileges --tmpfs /tmp:rw,nosuid,nodev,size=64m \
    --mount "type=bind,src=$dump_input,dst=/input,readonly" \
    --mount "type=bind,src=$dump_output,dst=/output" \
    -e DUMP_MAX_COPY_BYTES=1 "$dump_image" copy /input/existing.dump too-large.dump >/dev/null 2>&1; then
    fail "copy size bound was not enforced"
fi
assert_no_residuals "$dump_output"
[ -e "$dump_output/copied.dump" ] || fail "copied dump disappeared"

echo "utility image integration passed for ${platform}"
