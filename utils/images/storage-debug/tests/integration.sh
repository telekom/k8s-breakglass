#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

root=$(cd -- "$(dirname -- "$0")/.." && pwd -P)
image=${STORAGE_DEBUG_IMAGE:-storage-debug-integration-$RANDOM}
platform=${IMAGE_PLATFORM:-linux/amd64}
remove_image=false
work=$(mktemp -d "${TMPDIR:-/tmp}/storage-debug-integration.XXXXXX")
storage="$work/storage"
reports="$work/reports"
docker_timeout_seconds=${STORAGE_DOCKER_TIMEOUT_SECONDS:-90}
run_id="storage-debug-integration-${RANDOM}-${RANDOM}"

fail() {
    printf 'storage-debug integration: %s\n' "$1" >&2
    exit 1
}

cleanup() {
    status=$?
    set +e
    owned_containers=$(docker ps -aq --filter "label=io.telekom.storage-debug.test-run=$run_id")
    for cid in $owned_containers; do
        if ! container_belongs_to_run "$cid"; then
            printf 'storage-debug integration: refusing to remove container without our ownership label: %s\n' "$cid" >&2
            status=1
            continue
        fi
        docker rm -f "$cid" >/dev/null 2>&1 || status=1
    done
    for cidfile in "$work"/*.cid; do
        [ -s "$cidfile" ] || continue
        cid=$(cat "$cidfile")
        if ! container_exists "$cid"; then
            continue
        fi
        if container_belongs_to_run "$cid"; then
            docker rm -f "$cid" >/dev/null 2>&1 || true
        else
            printf 'storage-debug integration: refusing to remove foreign container from cidfile: %s\n' "$cid" >&2
            status=1
        fi
    done
    [ "$remove_image" = true ] && docker image rm "$image" >/dev/null 2>&1
    rm -rf "$work"
    exit "$status"
}

container_belongs_to_run() {
    cid=$1
    [ "$(docker inspect --format '{{index .Config.Labels "io.telekom.storage-debug.test-run"}}' "$cid" 2>/dev/null || true)" = "$run_id" ]
}

container_exists() {
    docker inspect "$1" >/dev/null 2>&1
}

trap cleanup EXIT HUP INT TERM

for command_name in docker kind kubectl jq timeout; do
    command -v "$command_name" >/dev/null 2>&1 || fail "$command_name is required; integration never silently skips"
done
docker info >/dev/null 2>&1 || fail 'Docker daemon is unavailable'

case "$docker_timeout_seconds" in
    ''|*[!0-9]*) fail 'STORAGE_DOCKER_TIMEOUT_SECONDS must be a positive integer' ;;
esac
[ "$docker_timeout_seconds" -ge 1 ] || fail 'STORAGE_DOCKER_TIMEOUT_SECONDS must be at least one second'

run_docker() {
    local cidfile status cid
    cidfile="$work/container-${RANDOM}-${RANDOM}.cid"
    set +e
    timeout --foreground --kill-after=5 "$docker_timeout_seconds" \
        docker run --label "io.telekom.storage-debug.test-run=$run_id" --cidfile "$cidfile" "$@"
    status=$?
    set -e
    if [ -s "$cidfile" ]; then
        cid=$(cat "$cidfile")
        case "$cid" in
            *[!0-9a-f]*|'') fail "Docker wrote an invalid container ID" ;;
        esac
        if container_exists "$cid"; then
            container_belongs_to_run "$cid" || fail "Docker cidfile did not identify an owned container"
            docker rm -f "$cid" >/dev/null 2>&1 || true
        fi
    fi
    rm -f "$cidfile"
    return "$status"
}

mkdir -p "$storage" "$reports"
chmod 0777 "$storage" "$reports"
printf '%s\n' 'preserve this pre-existing file' >"$storage/sentinel"

if ! docker image inspect "$image" >/dev/null 2>&1; then
    docker build --pull=false --platform "$platform" \
        --build-arg VERSION=integration \
        --build-arg VCS_REF=integration \
        --build-arg BUILD_DATE=2026-01-02T03:04:05Z \
        --tag "$image" "$root"
    remove_image=true
fi

[ "$(docker image inspect "$image" --format '{{.Config.User}}')" = '65532:65532' ] || \
    fail 'image does not run as UID/GID 65532'
[ "$(docker image inspect "$image" --format '{{index .Config.Entrypoint 0}}')" = '/usr/local/bin/storage-diagnostics' ] || \
    fail 'image entrypoint is not storage-diagnostics'

saved_docker_timeout_seconds=$docker_timeout_seconds
docker_timeout_seconds=1
if run_docker --rm --network none --read-only --cap-drop=ALL \
    --security-opt=no-new-privileges --entrypoint /bin/sh "$image" -c 'sleep 30'; then
    fail 'outer Docker timeout did not stop a hung diagnostic process'
else
    timeout_status=$?
fi
docker_timeout_seconds=$saved_docker_timeout_seconds
case "$timeout_status" in
    124|137) ;;
    *) fail "outer Docker timeout returned unexpected status $timeout_status" ;;
esac
[ -z "$(docker ps -aq --filter "label=io.telekom.storage-debug.test-run=$run_id")" ] || \
    fail 'timed-out diagnostic container survived cleanup'

run_docker --rm --platform "$platform" --read-only --network none --cap-drop=ALL \
    --security-opt=no-new-privileges --tmpfs /tmp:rw,nosuid,nodev,size=64m \
    "$image" help >/dev/null

run_storage() {
    run_docker --rm --platform "$platform" --read-only --network none --cap-drop=ALL \
        --security-opt=no-new-privileges --tmpfs /tmp:rw,nosuid,nodev,size=64m \
        --mount "type=bind,src=$storage,dst=/scratch" \
        --mount "type=bind,src=$reports,dst=/reports" \
        -e STORAGE_REPORT_DIR=/reports "$image" mounted-volume "$@"
}

run_readonly_storage() {
    run_docker --rm --platform "$platform" --read-only --network none --cap-drop=ALL \
        --security-opt=no-new-privileges --tmpfs /tmp:rw,nosuid,nodev,size=64m \
        --mount "type=bind,src=$storage,dst=/scratch,readonly" \
        --mount "type=bind,src=$reports,dst=/reports" \
        -e STORAGE_REPORT_DIR=/reports "$image" mounted-volume "$@"
}

read_report() {
    run_docker --rm --platform "$platform" --read-only --network none --cap-drop=ALL \
        --security-opt=no-new-privileges --tmpfs /tmp:rw,nosuid,nodev,size=64m \
        --mount "type=bind,src=$reports,dst=/reports,readonly" \
        --entrypoint /bin/sh "$image" -c "$1"
}

printf '%s\n' 'checking actual attached-volume fio and ioping behavior'
dry_run=$(run_readonly_storage --path /scratch --size-mb 1 --runtime-seconds 1 \
    --ioping-count 1 --dry-run)
printf '%s\n' "$dry_run" | grep -F 'schema_version=storage-debug/v1' >/dev/null
if run_readonly_storage --path /scratch --size-mb 1 --runtime-seconds 1 --ioping-count 1 \
    >/dev/null 2>&1; then
    fail 'read-write test unexpectedly succeeded on a read-only mount'
fi

actual=$(run_storage --path /scratch --size-mb 1 --runtime-seconds 1 --ioping-count 1)
printf '%s\n' "$actual" | grep -Fx 'fio_status=pass' >/dev/null
printf '%s\n' "$actual" | grep -Fx 'ioping_status=pass' >/dev/null
printf '%s\n' "$actual" | grep -Fx 'overall_status=pass' >/dev/null

run_storage --path /scratch --size-mb 1 --runtime-seconds 1 --ioping-count 1 \
    --output /reports/storage-report.txt >/dev/null
read_report "grep -Fx 'overall_status=pass' /reports/storage-report.txt"
read_report "test \"\$(stat -c '%a' /reports/storage-report.txt)\" = 600"
[ -e "$storage/sentinel" ] || fail 'pre-existing attached-volume file disappeared'
for candidate in "$storage"/.storage-debug-fio.* "$reports"/.storage-report.*; do
    [ -e "$candidate" ] || continue
    fail "temporary artifact remains: $candidate"
done

printf '%s\n' 'checking operation plan and input boundaries'
immutable_image="registry.example/storage-debug@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
plan=$(run_docker --rm --platform "$platform" --read-only --network none --cap-drop=ALL \
    --security-opt=no-new-privileges --tmpfs /tmp:rw,nosuid,nodev,size=64m \
    -e POD_NAMESPACE=storage-session \
    -e STORAGE_DEBUG_WORKLOAD_IMAGE="$immutable_image" \
    "$image" plan performance --storage-class fast-csi --pvc-size 8Gi)
printf '%s\n' "$plan" | grep -Fx 'intent=storage-diagnostics' >/dev/null
printf '%s\n' "$plan" | grep -F -- '--testname default-fio' >/dev/null
if run_docker --rm --platform "$platform" --read-only --network none --cap-drop=ALL \
    --security-opt=no-new-privileges --tmpfs /tmp:rw,nosuid,nodev,size=64m \
    -e POD_NAMESPACE=storage.session -e STORAGE_DEBUG_WORKLOAD_IMAGE="$immutable_image" \
    "$image" plan performance --storage-class fast-csi >/dev/null 2>&1; then
    fail 'dotted namespace was accepted'
fi
if run_docker --rm --platform "$platform" --read-only --network none --cap-drop=ALL \
    --security-opt=no-new-privileges --tmpfs /tmp:rw,nosuid,nodev,size=64m \
    -e POD_NAMESPACE=storage-session -e STORAGE_DEBUG_WORKLOAD_IMAGE="$immutable_image" \
    "$image" plan performance --storage-class fast-csi --image attacker:latest >/dev/null 2>&1; then
    fail 'user-selected child image was accepted'
fi

printf '%s\n' 'checking real kubestr fio Kind behavior and cleanup'
STORAGE_DEBUG_IMAGE="$image" IMAGE_PLATFORM="$platform" "$root/tests/kind-kubestr.sh"

printf '%s\n' 'storage-debug Docker and Kind behavior proofs passed'
