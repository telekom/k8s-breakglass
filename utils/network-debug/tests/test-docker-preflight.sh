#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

root=$(cd -- "$(dirname -- "$0")" && pwd)
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT HUP INT TERM

# Exercise the preflight contract through its public shell function. The
# resource probe is a behavioral fixture with the same tri-state contract as
# Docker: 0 present/owned, 1 absent, 2 inspection failure, 3 foreign resource.
run_case() {
	local probe_status=$1 expected_status=$2 expected_message=${3:-}
	local output status

	set +e
	output=$(FAKE_PROBE_STATUS="$probe_status" bash -c '
		set -u
		. "$1/docker-preflight.sh"
		docker_resource_present() { return "$FAKE_PROBE_STATUS"; }
		requirement() { printf "%s\\n" "$*"; return 97; }
		docker_require_resource_absent network fixture-network \
			"refusing to reuse fixture-network" \
			"could not inspect fixture-network"
	' bash "$root" 2>&1)
	status=$?
	set -e

	test "$status" -eq "$expected_status"
	if [ -n "$expected_message" ]; then
		test "$output" = "$expected_message"
	else
		test -z "$output"
	fi
}

# An absent exact name is claimable, while owned and foreign resources are
# both collisions. Inspection failures and unknown states remain fail-closed.
run_case 1 0
run_case 0 97 'refusing to reuse fixture-network'
run_case 3 97 'refusing to reuse fixture-network'
run_case 2 97 'could not inspect fixture-network'
run_case 42 97 'could not inspect fixture-network'

printf '%s\n' 'docker preflight behavior checks passed'
