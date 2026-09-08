#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

# shellcheck disable=SC2154 # integration state is supplied by the caller
remove_captured_volume() {
	attempt=0
	while [ "$attempt" -lt 10 ]; do
		"$docker_bin" volume inspect "$volume_name" >/dev/null 2>&1 || return 0
		attached_ids=$("$docker_bin" ps -aq --no-trunc --filter "volume=$volume_name") || return 1
		for attached_id in $attached_ids; do
			attached_label=$("$docker_bin" inspect --format '{{index .Config.Labels "io.telekom.node-maintenance.test-run"}}' "$attached_id") || return 1
			[ "$attached_label" = "$docker_run_label" ] || return 1
			docker_remove_resource_with_volumes "$docker_bin" container "$attached_id" >/dev/null 2>&1 || return 1
		done
		"$docker_bin" volume rm "$volume_name" >/dev/null 2>&1 || true
		attempt=$((attempt + 1))
		sleep 1
	done
	! "$docker_bin" volume inspect "$volume_name" >/dev/null 2>&1
}
