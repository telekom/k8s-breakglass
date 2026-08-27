#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

set -eu

# These limits are deliberately fixed in the image rather than configurable by
# a request. They keep a failed driver, command, or mounted evidence volume
# from turning a bounded maintenance request into unbounded work or storage.
capture_timeout_seconds=10
capture_max_bytes=32768
evidence_max_bytes=393216

die() {
	printf 'node-maintenance: %s\n' "$*" >&2
	exit 2
}

validate_value() {
	label=$1
	value=$2

	[ -n "$value" ] || die "$label is required"
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

validate_confirmation() {
	expected=$1
	actual=$2
	[ "$actual" = "$expected" ] || die "confirmation must be exactly '$expected'"
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
		printf 'started_at_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	} >"$metadata_file"
}
