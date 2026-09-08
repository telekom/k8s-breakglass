#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

# The caller owns this name because it was accepted by a successful docker run
# immediately before ID capture. This is only for that narrow capture-failure
# path; normal cleanup always uses the captured immutable ID.
cleanup_bounded_container_name() {
	[ "$#" -eq 2 ] || return 2
	local docker_bin=$1 name=$2
	[ -n "$name" ] || return 2
	docker_resource_call "$docker_bin" rm -f "$name" >/dev/null 2>&1 || true
}
