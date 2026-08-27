#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

set -eu

# Do not let a caller-controlled environment select helper binaries from a
# writable evidence or recovery mount. The image's fixed utility locations
# are part of the command contract.
PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin
export PATH

# These limits are deliberately fixed in the image rather than configurable by
# a request. They keep a failed driver, command, or mounted evidence volume
# from turning a bounded maintenance request into unbounded work or storage.
value_max_bytes=256
capture_timeout_seconds=10
capture_max_bytes=32768
evidence_max_bytes=393216
operation_lock_name=.node-maintenance-operation.lock
operation_lock_owner_name=owner
operation_lock_ttl_seconds=300

die() {
	printf 'node-maintenance: %s\n' "$*" >&2
	exit 2
}

validate_value() {
	label=$1
	value=$2

	[ -n "$value" ] || die "$label is required"
	[ "${#value}" -le "$value_max_bytes" ] || die "$label exceeds the fixed ${value_max_bytes}-byte limit"
	case "$value" in
		*[!A-Za-z0-9_.:@-]*) die "$label contains unsupported characters" ;;
	esac
}

validate_target() {
	target=$1
	validate_value "target node" "$target"
	actual_node=${BREAKGLASS_NODE_NAME:-}
	validate_value "BREAKGLASS_NODE_NAME" "$actual_node"
	[ "$target" = "$actual_node" ] || die "target node '$target' does not match controller-provided node '$actual_node'"
}

validate_interface() {
	validate_value "interface" "$1"
}

validate_mac_address() {
	label=$1
	value=$2
	case "$value" in
		[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]:[0-9A-Fa-f][0-9A-Fa-f]) ;;
		*) die "$label must be an exact six-octet MAC address" ;;
	esac
	[ "$value" != 00:00:00:00:00:00 ] || die "$label may not be the all-zero address"
	first_octet=${value%%:*}
	second_nibble=${first_octet#?}
	case "$second_nibble" in
		1|3|5|7|9|[Bb]|[Dd]|[Ff]) die "$label must be a unicast MAC address" ;;
	esac
}

validate_neighbor_address() {
	value=$1
	[ -n "$value" ] || die "neighbor address is required"
	[ "${#value}" -le 45 ] || die "neighbor address must be an IPv4 or IPv6 literal"
	case "$value" in
		*[!0-9A-Fa-f:.]*) die "neighbor address must be an IPv4 or IPv6 literal" ;;
	esac
	if printf '%s\n' "$value" | awk '
		/^[0-9]+(\.[0-9]+){3}$/ {
			n = split($0, octet, ".")
			for (i = 1; i <= n; i++) {
				if (octet[i] !~ /^(0|[1-9][0-9]{0,2})$/ || octet[i] > 255) exit 1
			}
			exit 0
		}
		{ exit 1 }
	'; then
		# The selected family is consumed by the calling fixed-action helper.
		# shellcheck disable=SC2034
		NEIGHBOR_FAMILY=-4
		return
	fi
	if printf '%s\n' "$value" | awk '
		{
			if ($0 !~ /^[0-9A-Fa-f:]+$/ || $0 ~ /:::/) exit 1
			compressed = index($0, "::") > 0
			tmp = $0
			sub(/::/, "", tmp)
			if (index(tmp, "::") > 0) exit 1
			if (($0 ~ /^:/ && $0 !~ /^::/) || ($0 ~ /:$/ && $0 !~ /::$/)) exit 1
			n = split($0, part, ":"); groups = 0
			for (i = 1; i <= n; i++) {
				if (part[i] == "") continue
				if (part[i] !~ /^[0-9A-Fa-f]{1,4}$/) exit 1
				groups++
			}
			if ((compressed && groups < 8) || (!compressed && groups == 8)) exit 0
			exit 1
		}
	'; then
		# shellcheck disable=SC2034
		NEIGHBOR_FAMILY=-6
		return
	fi
	die "neighbor address must be an IPv4 or IPv6 literal"
}

validate_vlan() {
	value=$1
	[ "${#value}" -le 4 ] || die "VLAN must be an integer from 1 through 4094"
	case "$value" in
		''|*[!0-9]*|0*) die "VLAN must be an integer from 1 through 4094" ;;
	esac
	if [ "$value" -lt 1 ] || [ "$value" -gt 4094 ]; then
		die "VLAN must be an integer from 1 through 4094"
	fi
}

validate_confirmation() {
	expected=$1
	actual=$2
	[ "$actual" = "$expected" ] || die "confirmation must be exactly '$expected'"
}

validate_sha256() {
	label=$1
	value=$2
	[ "${#value}" -eq 64 ] || die "$label must be an exact SHA-256 digest without a prefix"
	case "$value" in
		*[!0-9A-Fa-f]*) die "$label must be an exact SHA-256 digest without a prefix" ;;
	esac
}

validate_recording_context() {
	operation_id=${BREAKGLASS_OPERATION_ID:-}
	recording_id=${BREAKGLASS_RECORDING_ID:-}
	validate_value "BREAKGLASS_OPERATION_ID" "$operation_id"
	validate_value "BREAKGLASS_RECORDING_ID" "$recording_id"
}

validate_approved_action() {
	expected_action=$1
	approval_id=${BREAKGLASS_APPROVAL_ID:-}
	approved_action=${BREAKGLASS_APPROVED_ACTION:-}
	validate_value "BREAKGLASS_APPROVAL_ID" "$approval_id"
	validate_value "BREAKGLASS_APPROVED_ACTION" "$approved_action"
	[ "$approved_action" = "$expected_action" ] || die "controller-approved action '$approved_action' does not match requested action '$expected_action'"
}

validate_approved_network_request() {
	requested_target=$1
	requested_interface=$2
	requested_action=$3
	requested_neighbor=$4
	requested_bridge=$5
	requested_mac=$6
	requested_vlan=$7
	requested_confirmation=$8
	approved_request=${BREAKGLASS_APPROVED_NETWORK_REQUEST:-}
	[ -n "$approved_request" ] || die "BREAKGLASS_APPROVED_NETWORK_REQUEST is required"
	[ "${#approved_request}" -le "$value_max_bytes" ] || die "BREAKGLASS_APPROVED_NETWORK_REQUEST exceeds the fixed ${value_max_bytes}-byte limit"
	expected_request="target_node=$requested_target&interface=$requested_interface&action=$requested_action&neighbor_address=$requested_neighbor&bridge=$requested_bridge&entry_mac=$requested_mac&vlan=$requested_vlan&confirmation=$requested_confirmation"
	[ "$approved_request" = "$expected_request" ] || die "controller-approved network request does not exactly match the requested tuple"
}

prepare_evidence_dir() {
	directory=$1
	case "$directory" in
		/evidence) ;;
		/evidence/*)
			child=${directory#/evidence/}
			case "$child" in
				''|*/*|.|..|*[!A-Za-z0-9_.-]*) die "evidence directory must be /evidence or one safe child" ;;
			esac
			;;
		*) die "evidence directory must be /evidence or one safe child" ;;
	esac
	[ -d /evidence ] || die "/evidence must be a mounted directory"
	[ ! -L /evidence ] || die "/evidence may not be a symlink"
	root=$(readlink -f /evidence 2>/dev/null || true)
	[ "$root" = /evidence ] || die "/evidence did not resolve safely"
	if [ "$directory" != /evidence ]; then
		[ ! -L "$directory" ] || die "evidence directory may not be a symlink"
		mkdir "$directory" 2>/dev/null || [ -d "$directory" ] || die "cannot create evidence directory '$directory'"
	fi
	assert_safe_evidence_dir "$directory"
	chmod 0700 "$directory" || die "cannot protect evidence directory '$directory'"
	EVIDENCE_DIR=$directory
}

acquire_operation_lock() {
	directory=$1
	assert_safe_evidence_dir "$directory"
	lock_candidate="$directory/$operation_lock_name"
	if ! mkdir "$lock_candidate" 2>/dev/null; then
		reclaim_own_stale_operation_lock "$lock_candidate" || die "another node-maintenance operation is active for this evidence lease"
		mkdir "$lock_candidate" 2>/dev/null || die "another node-maintenance operation is active for this evidence lease"
	fi
	operation_lock=$lock_candidate
	[ ! -L "$operation_lock" ] || die "operation lock may not be a symlink"
	resolved_lock=$(readlink -f "$operation_lock" 2>/dev/null || true)
	[ "$resolved_lock" = "$operation_lock" ] || die "operation lock did not resolve safely"
	chmod 0700 "$operation_lock" || die "cannot protect operation lock"
	operation_lock_owner="$operation_lock/$operation_lock_owner_name"
	(umask 077; printf 'operation_id=%s\nrecording_id=%s\ncreated_epoch=%s\n' "$operation_id" "$recording_id" "$(date -u +%s)" >"$operation_lock_owner") || die "cannot record operation lock owner"
}

reclaim_own_stale_operation_lock() {
	lock_candidate=$1
	case "$lock_candidate" in "$EVIDENCE_DIR/$operation_lock_name") ;; *) return 1 ;; esac
	[ -d "$lock_candidate" ] && [ ! -L "$lock_candidate" ] || return 1
	owner_file="$lock_candidate/$operation_lock_owner_name"
	[ -f "$owner_file" ] && [ ! -L "$owner_file" ] || return 1
	[ "$(readlink -f "$owner_file" 2>/dev/null || true)" = "$owner_file" ] || return 1
	{
		IFS= read -r lock_operation
		IFS= read -r lock_recording
		IFS= read -r lock_created
	} <"$owner_file" || return 1
	[ "$lock_operation" = "operation_id=$operation_id" ] || return 1
	[ "$lock_recording" = "recording_id=$recording_id" ] || return 1
	lock_epoch=${lock_created#created_epoch=}
	case "$lock_epoch" in ''|*[!0-9]*) return 1 ;; esac
	[ "${#lock_epoch}" -le 10 ] || return 1
	now_epoch=$(date -u +%s) || return 1
	[ "$now_epoch" -ge "$lock_epoch" ] || return 1
	[ $((now_epoch - lock_epoch)) -ge "$operation_lock_ttl_seconds" ] || return 1
	rm -f "$owner_file" || return 1
	rmdir "$lock_candidate" 2>/dev/null
}

release_operation_lock() {
	if [ -n "${operation_lock:-}" ]; then
		[ -n "${EVIDENCE_DIR:-}" ] && [ -d "$EVIDENCE_DIR" ] && [ ! -L "$EVIDENCE_DIR" ] || return 1
		case "$operation_lock" in "$EVIDENCE_DIR/$operation_lock_name") ;; *) return 1 ;; esac
		[ ! -L "$operation_lock" ] || return 1
		[ "${operation_lock_owner:-}" = "$operation_lock/$operation_lock_owner_name" ] || return 1
		[ -f "$operation_lock_owner" ] && [ ! -L "$operation_lock_owner" ] || return 1
		grep -Fqx "operation_id=$operation_id" "$operation_lock_owner" || return 1
		grep -Fqx "recording_id=$recording_id" "$operation_lock_owner" || return 1
		rm -f "$operation_lock_owner" || return 1
		rmdir "$operation_lock" 2>/dev/null || return 1
		operation_lock=
	fi
}

interface_ifindex() {
	interface_name=$1
	timeout "$capture_timeout_seconds" ip -o link show dev "$interface_name" 2>/dev/null | awk -F: 'NR == 1 { gsub(/^[[:space:]]+/, "", $1); if ($1 ~ /^[1-9][0-9]*$/) print $1; exit }'
}

pin_interface_ifindex() {
	pinned_interface=$1
	pinned_ifindex=$(interface_ifindex "$pinned_interface") || die "cannot determine ifindex for interface '$pinned_interface'"
	case "$pinned_ifindex" in ''|*[!0-9]*) die "cannot determine ifindex for interface '$pinned_interface'" ;; esac
	printf '%s\n' "$pinned_ifindex"
}

assert_interface_ifindex() {
	pinned_interface=$1
	expected_ifindex=$2
	actual_ifindex=$(interface_ifindex "$pinned_interface") || return 1
	[ "$actual_ifindex" = "$expected_ifindex" ]
}

assert_safe_evidence_dir() {
	directory=$1
	case "$directory" in
		/evidence) ;;
		/evidence/*)
			child=${directory#/evidence/}
			case "$child" in ''|*/*|.|..|*[!A-Za-z0-9_.-]*) die "unsafe evidence directory" ;; esac
			;;
		*) die "unsafe evidence directory" ;;
	esac
	if [ ! -d /evidence ] || [ -L /evidence ]; then
		die "/evidence changed while handling evidence"
	fi
	[ ! -L "$directory" ] || die "evidence directory may not be a symlink"
	resolved_directory=$(readlink -f "$directory" 2>/dev/null || true)
	[ "$resolved_directory" = "$directory" ] || die "evidence directory changed or resolves outside /evidence"
}

assert_safe_bundle() {
	bundle=$1
	assert_safe_evidence_dir "${EVIDENCE_DIR:?evidence directory is not initialized}"
	case "$bundle" in "$EVIDENCE_DIR"/*) ;; *) die "unsafe evidence bundle" ;; esac
	if [ ! -d "$bundle" ] || [ -L "$bundle" ]; then
		die "evidence bundle changed while handling evidence"
	fi
	resolved_bundle=$(readlink -f "$bundle" 2>/dev/null || true)
	[ "$resolved_bundle" = "$bundle" ] || die "evidence bundle did not resolve safely"
}

new_bundle() {
	parent=$1
	command_name=$2
	assert_safe_evidence_dir "$parent"
	timestamp=$(date -u +%Y%m%dT%H%M%SZ)
	bundle=$(mktemp -d "$parent/${command_name}-${timestamp}-XXXXXX") || die "cannot create evidence bundle"
	assert_safe_bundle "$bundle"
	chmod 0700 "$bundle" || die "cannot protect evidence bundle"
	printf '%s\n' "$bundle"
}

capture() {
	output_file=$1
	shift
	case "$output_file" in "${bundle:?bundle is not initialized}"/*) ;; *) die "unsafe evidence output path" ;; esac
	assert_safe_bundle "$bundle"
	command -v timeout >/dev/null 2>&1 || die "timeout utility is required for bounded evidence capture"
	temporary_file=$(mktemp "$bundle/.capture.XXXXXX") || die "cannot create bounded capture temporary file"
	status_file=$(mktemp "$bundle/.capture-status.XXXXXX") || die "cannot create capture status file"
	fifo=$(mktemp "$bundle/.capture-fifo.XXXXXX") || die "cannot reserve capture pipe"
	rm -f "$fifo"
	mkfifo -m 0600 "$fifo" || die "cannot create capture pipe"
	(
		set +e
		timeout "$capture_timeout_seconds" "$@" >"$fifo" 2>&1
		printf '%s\n' "$?" >"$status_file"
	) &
	producer_pid=$!
	# Read at most one byte beyond the fixed quota. Closing the FIFO then
	# back-pressures or terminates a noisy producer instead of allowing an
	# unbounded temporary file to grow before the quota is checked.
	if ! head -c "$((capture_max_bytes + 1))" "$fifo" >"$temporary_file"; then
		rm -f "$fifo" "$status_file" "$temporary_file"
		die "cannot read bounded command output"
	fi
	if wait "$producer_pid"; then :; else :; fi
	rm -f "$fifo"
	[ -s "$status_file" ] || {
		rm -f "$status_file" "$temporary_file"
		die "capture command did not report an exit status"
	}
	status=$(cat "$status_file")
	rm -f "$status_file"
	bytes=$(wc -c <"$temporary_file" | tr -d ' ')
	if [ "$bytes" -gt "$capture_max_bytes" ]; then
		head -c "$capture_max_bytes" "$temporary_file" >"$output_file"
		printf '\ncapture_result=output-quota-exceeded\nexit_status=75\n' >>"$output_file"
		rm -f "$temporary_file"
		return 75
	fi
	mv "$temporary_file" "$output_file"
	printf '\nexit_status=%s\n' "$status" >>"$output_file"
	used_kib=$(du -sk "$bundle" | awk '{print $1}')
	[ "$used_kib" -le $((evidence_max_bytes / 1024)) ] || die "evidence quota exceeded"
	return "$status"
}

write_metadata() {
	metadata_file=$1
	command_name=$2
	target_node=$3
	interface=$4
	action=$5
	assert_safe_bundle "$(dirname "$metadata_file")"
	{
		printf 'command=%s\n' "$command_name"
		printf 'target_node=%s\n' "$target_node"
		printf 'interface=%s\n' "$interface"
		printf 'action=%s\n' "$action"
		printf 'operation_id=%s\n' "${operation_id:?recording context is not initialized}"
		printf 'recording_id=%s\n' "${recording_id:?recording context is not initialized}"
		if [ -n "${approval_id:-}" ]; then
			printf 'approval_id=%s\n' "$approval_id"
		fi
		printf 'started_at_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	} >"$metadata_file"
}

record_event() {
	event_name=$1
	result=$2
	assert_safe_bundle "${bundle:?bundle is not initialized}"
	validate_value "recording event" "$event_name"
	validate_value "recording result" "$result"
	printf '{"time":"%s","event":"%s","result":"%s","operation_id":"%s","recording_id":"%s","target_node":"%s"}\n' \
		"$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$event_name" "$result" "$operation_id" "$recording_id" "$target_node" \
		>>"$bundle/events.jsonl"
}
