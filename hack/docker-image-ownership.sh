#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

# Remove only the immutable image ID captured after this invocation created it.
# A replacement of the mutable tag between inspection and cleanup is therefore
# left untouched; deleting the tag itself would reintroduce a TOCTOU race.
docker_remove_image_if_id() {
	[ "$#" -eq 3 ] || return 2
	local docker_bin=$1 tag=$2 expected_id=$3 current_id
	[ -n "$expected_id" ] || return 2
	current_id=$("$docker_bin" image inspect --format '{{.Id}}' "$tag" 2>/dev/null) || return 1
	[ "$current_id" = "$expected_id" ] || return 3
	"$docker_bin" image rm "$expected_id" >/dev/null 2>&1
}
