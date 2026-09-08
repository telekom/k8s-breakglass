#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

# Docker writes the immutable ID before returning from a successful --cidfile
# run. Callers must register this ID before doing any name-based observation.
docker_capture_resource_id_from_cidfile() {
	[ "$#" -eq 1 ] || return 2
	local cidfile=$1 id
	[ -s "$cidfile" ] || return 1
	id=$(cat "$cidfile") || return 1
	case "$id" in
		''|*[!0-9a-f]*) return 1 ;;
	esac
	printf '%s\n' "$id"
}
