#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail

root=$(cd -- "$(dirname "$0")/.." && pwd)
fixture=$(mktemp -d)
trap 'rm -rf -- "$fixture"' EXIT HUP INT TERM

cat >"$fixture/kind" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
state=${KIND_STATE:?}
delete_log=${KIND_DELETE_LOG:?}
case "${1:-}" in
get)
    [ "${2:-}" = clusters ] || exit 2
    cat "$state"
    ;;
create)
    name=
    kubeconfig=
    while [ "$#" -gt 0 ]; do
        case "$1" in
        --name) name=$2; shift 2 ;;
        --kubeconfig) kubeconfig=$2; shift 2 ;;
        *) shift ;;
        esac
    done
    [ -n "$name" ] && [ -n "$kubeconfig" ]
    if [ "${KIND_CREATE_MODE:-success}" = partial ]; then
        printf '%s\n' "$name" >"$state"
        : >"$kubeconfig"
        exit 42
    fi
    printf '%s\n' "$name" >"$state"
    : >"$kubeconfig"
    ;;
delete)
    name=
    while [ "$#" -gt 0 ]; do
        case "$1" in
        --name) name=$2; shift 2 ;;
        *) shift ;;
        esac
    done
    printf '%s\n' "$name" >>"$delete_log"
    : >"$state"
    ;;
*) exit 2 ;;
esac
EOF
chmod +x "$fixture/kind"

# shellcheck disable=SC1091
source "$root/tests/kind-lifecycle.sh"
export PATH="$fixture:$PATH"
export KIND_STATE="$fixture/clusters"
export KIND_DELETE_LOG="$fixture/deletes"
: >"$KIND_DELETE_LOG"

# A caller-owned name is rejected during preflight and is never deleted.
printf '%s\n' caller-owned >"$KIND_STATE"
KIND_LIFECYCLE_OWNED=0
collision_status=0
kind_lifecycle_create caller-owned kind-node:dev "$fixture/caller.kubeconfig" || collision_status=$?
[ "$collision_status" -eq 3 ] || {
    printf 'collision returned status %s, expected 3\n' "$collision_status" >&2
    exit 1
}
[ "$KIND_LIFECYCLE_OWNED" -eq 0 ] || {
    printf '%s\n' 'collision was incorrectly marked as owned' >&2
    exit 1
}
[ ! -s "$KIND_DELETE_LOG" ] || {
    printf '%s\n' 'caller-owned collision was deleted' >&2
    exit 1
}

# A failed create that leaves a cluster is owned and removed by cleanup.
: >"$KIND_STATE"
export KIND_CREATE_MODE=partial
KIND_LIFECYCLE_OWNED=0
partial_status=0
kind_lifecycle_create partial-owned kind-node:dev "$fixture/partial.kubeconfig" || partial_status=$?
[ "$partial_status" -eq 42 ] || {
    printf 'partial create returned status %s, expected 42\n' "$partial_status" >&2
    exit 1
}
[ "$KIND_LIFECYCLE_OWNED" -eq 1 ] || {
    printf '%s\n' 'partial cluster was not marked as owned' >&2
    exit 1
}
kind_lifecycle_cleanup partial-owned "$fixture/partial.kubeconfig"
[ ! -s "$KIND_STATE" ] || {
    printf '%s\n' 'partial cluster remained after owned cleanup' >&2
    exit 1
}
grep -Fx 'partial-owned' "$KIND_DELETE_LOG" >/dev/null || {
    printf '%s\n' 'owned partial cluster was not deleted' >&2
    exit 1
}

printf '%s\n' 'kind lifecycle ownership tests passed'
