#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

# Convert the ownership probe's tri-state result into the integration
# harness' fail-closed preflight behavior. `docker_resource_present` is
# provided by integration.sh (and is replaced by a behavioral fixture in the
# hermetic tests).
docker_require_resource_absent() {
	local kind=$1 name=$2 collision_message=$3 inspection_message=$4 state

	if docker_resource_present "$kind" "$name"; then
		requirement "$collision_message"
		return $?
	else
		state=$?
	fi
	case "$state" in
		1) return 0 ;; # The exact resource name is absent and can be claimed.
		3) requirement "$collision_message"; return $? ;; # Present, but not owned by us.
		2) requirement "$inspection_message"; return $? ;; # The daemon could not be inspected safely.
		*) requirement "$inspection_message"; return $? ;; # Unknown states fail closed too.
	esac
}
