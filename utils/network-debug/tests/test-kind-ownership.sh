#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

root=$(cd -- "$(dirname -- "$0")" && pwd)
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT HUP INT TERM

cat >"$fixture/kind" <<'EOF'
#!/bin/sh
set -eu
state=$KIND_FAKE_STATE
log=$KIND_FAKE_LOG
command=${1:-}
shift || true
case "$command" in
  get)
    if [ -f "$state" ] && [ "$(cat "$state")" = present ]; then
      printf '%s\n' "$KIND_CLUSTER_NAME"
    fi
    ;;
  create)
    printf '%s\n' create >>"$log"
    if [ "${KIND_FAKE_MODE:-success}" = partial ] || [ "${KIND_FAKE_MODE:-success}" = partial-hidden ] || [ "${KIND_FAKE_MODE:-success}" = same-name-takeover ]; then
      if [ "${KIND_FAKE_MODE:-success}" = partial-hidden ]; then
        printf '%s\n' artifact >"$state"
      elif [ "${KIND_FAKE_MODE:-success}" = same-name-takeover ]; then
        printf '%s\n' foreign >"$state"
      else
        printf '%s\n' present >"$state"
      fi
      exit 42
    fi
    printf '%s\n' present >"$state"
    ;;
  delete)
    printf '%s\n' delete >>"$log"
    rm -f "$state"
    ;;
  *)
    printf '%s\n' "unexpected kind command: $command" >&2
    exit 2
    ;;
esac
EOF
chmod +x "$fixture/kind"
cat >"$fixture/docker" <<'EOF'
#!/bin/sh
set -eu
if [ "${1:-}" = ps ] && [ -f "$KIND_FAKE_STATE" ] && [ "$(cat "$KIND_FAKE_STATE")" = artifact ]; then
	printf '%s\n' "sha256:partial-node"
elif [ "${1:-}" = ps ] && [ -f "$KIND_FAKE_STATE" ] && [ "$(cat "$KIND_FAKE_STATE")" = present ]; then
	printf '%s\n' "sha256:owned-node"
elif [ "${1:-}" = ps ] && [ -f "$KIND_FAKE_STATE" ] && [ "$(cat "$KIND_FAKE_STATE")" = foreign ]; then
	printf '%s\n' "sha256:foreign-node"
elif [ "${1:-}" = rm ]; then
	printf '%s\n' rm >>"$KIND_FAKE_LOG"
	rm -f "$KIND_FAKE_STATE"
fi
EOF
chmod +x "$fixture/docker"

run_case() {
	local mode=$1 initial=$2 expected_status=$3 expected_delete=$4
	local state="$fixture/${mode}.state" log="$fixture/${mode}.log"
	: >"$log"
	case "$initial" in
		present) printf '%s\n' present >"$state" ;;
		artifact) printf '%s\n' artifact >"$state" ;;
		absent) rm -f "$state" ;;
		*) printf '%s\n' "unknown initial state: $initial" >&2; exit 1 ;;
	esac

	if KIND_BIN="$fixture/kind" DOCKER_BIN="$fixture/docker" KIND_FAKE_STATE="$state" KIND_FAKE_LOG="$log" \
		KIND_FAKE_MODE="$mode" KIND_CLUSTER_NAME="ownership-$mode" \
		KIND_NODE_IMAGE=fixture KUBECONFIG_FILE="$fixture/kubeconfig" \
		KIND_CLUSTER_CREATED=false \
		bash -c '
			set -eu
			helper="$(cd -- "$1/../../../hack" && pwd)/kind-ownership.sh"
			. "$helper"
			if kind_create_owned_cluster; then
				status=0
			else
				status=$?
			fi
			test "$status" -eq "$2"
			if [ "$3" = true ]; then
				expected_log="create
delete"
				test "$(cat "$KIND_FAKE_LOG")" = "$expected_log"
			elif [ "$KIND_FAKE_MODE" = partial ] || [ "$KIND_FAKE_MODE" = partial-hidden ] || [ "$KIND_FAKE_MODE" = same-name-takeover ]; then
				test "$(cat "$KIND_FAKE_LOG")" = create
			else
				test ! -s "$KIND_FAKE_LOG"
			fi
		' bash "$root" "$expected_status" "$expected_delete"; then
		:
	else
		printf '%s\n' "ownership case $mode failed" >&2
		exit 1
	fi
	if [ "$mode" = collision ] || [ "$mode" = collision-hidden ]; then
		if [ ! -f "$state" ]; then
			printf '%s\n' 'collision case deleted the pre-existing cluster' >&2
			exit 1
		fi
elif [ "$expected_delete" = true ] && [ -f "$state" ]; then
	printf '%s\n' "ownership case $mode left a cluster" >&2
	exit 1
else
	:
fi
}

# A collision is rejected before create and never deleted.
run_case collision present 2 false
# Existing labeled node containers are also rejected before create.
run_case collision-hidden artifact 2 false
# kind can leave a partial cluster after a failed create; the failed attempt
# does not prove ownership, so cleanup must leave it untouched.
run_case partial absent 42 false
# A partial bootstrap may be visible only as a labeled Docker node container;
# it is still leaked safely rather than deleted by name.
run_case partial-hidden absent 42 false
# A same-name cluster can be taken over while create is failing; that foreign
# replacement must never be removed by the failed invocation.
run_case same-name-takeover absent 42 false

# Successful creation transitions to owned state and cleanup removes it.
state="$fixture/success.state"
log="$fixture/success.log"
KIND_BIN="$fixture/kind" DOCKER_BIN="$fixture/docker" KIND_FAKE_STATE="$state" KIND_FAKE_LOG="$log" \
KIND_FAKE_MODE=success KIND_CLUSTER_NAME=ownership-success KIND_NODE_IMAGE=fixture \
KUBECONFIG_FILE="$fixture/kubeconfig" KIND_CLUSTER_CREATED=false \
	KIND_CLUSTER_OWNER_IDS='' bash -c '
	set -eu
	helper="$(cd -- "$1/../../../hack" && pwd)/kind-ownership.sh"
	. "$helper"
	kind_create_owned_cluster
	test "$KIND_CLUSTER_CREATED" = true
	cleanup_status=0
	kind_cleanup_owned_cluster || cleanup_status=$?
	test "$cleanup_status" -eq 0
	test ! -e "$KIND_FAKE_STATE"
	test "$KIND_CLUSTER_CREATED" = false
	test -z "$KIND_CLUSTER_OWNER_IDS"
	kind_cleanup_owned_cluster
	test "$(cat "$KIND_FAKE_LOG")" = "create
rm"
' bash "$root" || exit 1

# A same-name replacement after successful creation has a different immutable
# node identity; cleanup must refuse the name-wide operation and leak safely.
state="$fixture/replacement.state"
log="$fixture/replacement.log"
KIND_BIN="$fixture/kind" DOCKER_BIN="$fixture/docker" KIND_FAKE_STATE="$state" KIND_FAKE_LOG="$log" \
KIND_FAKE_MODE=success KIND_CLUSTER_NAME=ownership-replacement KIND_NODE_IMAGE=fixture \
KUBECONFIG_FILE="$fixture/kubeconfig" KIND_CLUSTER_CREATED=false \
	KIND_CLUSTER_OWNER_IDS='' bash -c '
	set -eu
	helper="$(cd -- "$1/../../../hack" && pwd)/kind-ownership.sh"
	. "$helper"
	kind_create_owned_cluster
	printf "%s\n" foreign >"$KIND_FAKE_STATE"
	cleanup_status=0
	kind_cleanup_owned_cluster || cleanup_status=$?
	test "$cleanup_status" -eq 1
	test "$(cat "$KIND_FAKE_STATE")" = foreign
	test "$(cat "$KIND_FAKE_LOG")" = create
' bash "$root" || exit 1

printf '%s\n' 'kind ownership behavior checks passed'
