#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

script="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)/tests/kind-host-network.sh"
save_command="docker save --platform \"\${runner_platform}\" --output \"\${image_archive}\" \"\${image}\""
load_command="kind load image-archive \"\${image_archive}\" --name \"\${cluster}\""
assert_contains() {
	local needle=$1
	if ! grep -F "${needle}" "${script}" >/dev/null; then
		printf 'missing node-maintenance image-load contract assertion: %s\n' "${needle}" >&2
		exit 1
	fi
}

assert_contains "${save_command}"
assert_contains "${load_command}"
assert_contains 'timeout --foreground 5m kind load image-archive'
assert_contains 'Kind archive load exited with status'
assert_contains 'Exact-platform archive size:'
assert_contains "tar -tf \"\${image_archive}\""
assert_contains 'Kind archive load completed'
assert_contains 'Exact node-maintenance image is present in Kind containerd'
assert_contains "containerd_image=\"docker.io/library/\${image}\""
assert_contains 'cluster_create_attempted=true'
assert_contains "if [[ \"\${cluster_create_attempted}\" == true ]]"
assert_contains 'cluster_owned=false'
assert_contains "if [[ \"\${cluster_owned}\" == true ]] || partial_cluster_is_owned"
assert_contains 'found_context = 1'
assert_contains 'cluster_owned=true'
assert_contains "kubectl --kubeconfig \"\${kubeconfig}\" get --raw=/version"
create_line=$(rg -n '^if kind create cluster ' "${script}" | cut -d: -f1)
owner_line=$(rg -n '^\s*cluster_owned=true$' "${script}" | cut -d: -f1)
if [[ -z "${create_line}" || -z "${owner_line}" || "${owner_line}" -le "${create_line}" ]]; then
	printf 'cluster ownership must be claimed only after successful Kind creation\n' >&2
	exit 1
fi
assert_contains 'Kind containerd images:'
assert_contains 'volumeMounts | length) == 1'
assert_contains 'expected_exit'
assert_contains 'jq -s --arg expected'
assert_contains 'terminal_count'
assert_contains "length == 1 and .[0].result == \$expected"
assert_contains 'terminal_event=succeeded'
assert_contains 'terminal_event=failed'
if grep -F "helper_status=\${action_status}" "${script}" >/dev/null; then
	exit 1
fi
assert_contains 'helper_status=\$?'
assert_contains 'exactly one complete evidence bundle'
assert_contains "bundle_count=\$((bundle_count + 1))"
assert_contains 'bundle_dir}/metadata'
assert_contains "rm -f \"\${load_log}\""
if grep -F 'kind load docker-image' "${script}" >/dev/null; then
	exit 1
fi
printf '%s\n' 'node-maintenance exact-platform archive load contract passed'
