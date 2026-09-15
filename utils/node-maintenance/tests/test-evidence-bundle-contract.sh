#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail
command -v jq >/dev/null 2>&1 || { printf '%s\n' 'jq is required' >&2; exit 1; }

tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT

validate_one_bundle() {
	local root="$1" candidate bundle_dir bundle_count=0
	for candidate in "${root}"/*; do
		[[ -d "${candidate}" ]] || continue
		bundle_count=$((bundle_count + 1))
		bundle_dir="${candidate}"
	done
	[[ "${bundle_count}" -eq 1 ]] || return 1
	[[ -s "${bundle_dir}/metadata" && -s "${bundle_dir}/events.jsonl" ]]
}

validate_status_match() { [[ "$1" =~ ^[0-9]+$ && "$1" == "$2" ]]; }
validate_status_match 0 0
action_status="$(printf '%s\n' action_exit_status=7 | grep -F 'action_exit_status=' | cut -d= -f2)"
[[ "${action_status}" == 7 ]]
helper_status=0
[[ "${helper_status}" == 0 && "${action_status}" != "${helper_status}" ]]
helper_exit="${tmp}/helper.exit"
if (exit 7); then
	helper_status=0
else
	helper_status=$?
fi
printf '%s\n' "${helper_status}" >"${helper_exit}"
[[ "$(<"${helper_exit}")" == 7 ]]
if validate_status_match 0 1 || validate_status_match 1 0; then
	printf '%s\n' 'inconsistent wrapper and metadata statuses were accepted' >&2
	exit 1
fi

mkdir -p "${tmp}/one"
printf '%s\n' action=restart-autonegotiation >"${tmp}/one/metadata"
printf '%s\n' '{"event":"operation-completed","result":"succeeded"}' >"${tmp}/one/events.jsonl"
printf '%s\n' 0 >"${tmp}/helper.exit"
validate_one_bundle "${tmp}"
jq -s -e --arg expected succeeded '[.[] | select(.result == $expected and .event == "operation-completed")] | length == 1' <<'EOF' >/dev/null
{"result":"succeeded","time":"fixture","event":"operation-completed"}
EOF
if jq -s -e --arg expected succeeded '([.[] | select(.event == "operation-completed")] | length == 1 and .[0].result == $expected)' <<'EOF' >/dev/null
{"event":"operation-completed","result":"succeeded"}
{"event":"operation-completed","result":"failed"}
EOF
then
	printf '%s\n' 'contradictory terminal events were incorrectly accepted' >&2
	exit 1
fi

mkdir -p "${tmp}/decoy"
printf '%s\n' decoy >"${tmp}/decoy/metadata"
printf '%s\n' decoy >"${tmp}/decoy/events.jsonl"
if validate_one_bundle "${tmp}"; then
	printf '%s\n' 'multiple evidence bundles were incorrectly accepted' >&2
	exit 1
fi
mkdir -p "${tmp}/empty"
if validate_one_bundle "${tmp}/empty"; then
	printf '%s\n' 'an empty evidence root was incorrectly accepted' >&2
	exit 1
fi
printf '%s\n' 'evidence bundle uniqueness behavior passed'
