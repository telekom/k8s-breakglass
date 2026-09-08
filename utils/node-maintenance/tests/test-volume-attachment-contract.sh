#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail

root=$(cd -- "$(dirname -- "$0")/../../.." && pwd)
# shellcheck disable=SC1091
. "$root/hack/docker-resource-ownership.sh"
# shellcheck disable=SC1091
. "$(dirname -- "$0")/volume-attachment-cleanup.sh"

fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT INT TERM
cat >"$fixture/docker" <<'EOF'
#!/bin/sh
set -eu
case "${1:-}" in
volume)
	case "${2:-}" in
	inspect) [ -e "$FAKE_STATE/volume-present" ] ;;
	rm) rm -f "$FAKE_STATE/volume-present" ;;
	*) exit 2 ;;
	esac
	;;
ps)
	case "${FAKE_MODE:-owned}" in
	owned)
		printf '%s\n' aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
		printf '%s\n' cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc
		;;
	foreign) printf '%s\n' bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb ;;
	list-failure) exit 42 ;;
	*) exit 2 ;;
	esac
	;;
inspect)
	printf '%s\n' "${FAKE_LABEL:-run-label}"
	;;
rm)
	[ "${2:-}" = -fv ]
	case "${3:-}" in
	aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa) rm -f "$FAKE_STATE/owned" ;;
	cccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccccc) rm -f "$FAKE_STATE/second-owned" ;;
	*) exit 1 ;;
	esac
	;;
*) exit 2 ;;
esac
EOF
chmod +x "$fixture/docker"

run_case() {
	mode=$1
	label=run-label
	[ "$mode" = foreign ] && label=foreign-label
	printf x >"$fixture/volume-present"
	: >"$fixture/attached"
	: >"$fixture/owned"
	: >"$fixture/second-owned"
	if FAKE_STATE=$fixture FAKE_MODE=$mode FAKE_LABEL=$label docker_bin="$fixture/docker" docker_run_label=run-label volume_name=volume volume_owner_id=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa \
		remove_captured_volume; then
		result=0
	else
		result=$?
	fi
	case "$mode" in
	owned) [ "$result" -eq 0 ] && [ ! -e "$fixture/volume-present" ] && [ ! -e "$fixture/owned" ] && [ ! -e "$fixture/second-owned" ] ;;
	foreign|list-failure) [ "$result" -ne 0 ] && [ -e "$fixture/volume-present" ] && [ -e "$fixture/attached" ] ;;
	esac
}

run_case owned
run_case foreign
run_case list-failure
printf '%s\n' 'node volume attachment ownership contract passed'
