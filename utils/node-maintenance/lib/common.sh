#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

set -eu

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
	actual_node=$(hostname 2>/dev/null || true)
	[ -n "$actual_node" ] || die "cannot determine the local node identity"
	[ "$target" = "$actual_node" ] || die "target node '$target' does not match local node '$actual_node'"
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
	[ -n "$directory" ] || die "evidence directory is required"
	case "$directory" in
		/*) ;;
		*) die "evidence directory must be an absolute path" ;;
	esac
	case "$directory" in
		*..*) die "evidence directory may not contain '..'" ;;
	esac
	case "$directory" in
		/|/bin|/dev|/etc|/home|/proc|/root|/run|/sbin|/sys|/tmp|/usr|/var)
			die "evidence directory must be a dedicated child directory, not '$directory'" ;;
		/evidence|/evidence/*) ;;
		/*/*) ;;
		*) die "evidence directory must be a dedicated child directory" ;;
	esac
	mkdir -p "$directory" || die "cannot create evidence directory '$directory'"
	[ ! -L "$directory" ] || die "evidence directory may not be a symlink"
	resolved_directory=$(readlink -f "$directory" 2>/dev/null || true)
	[ -n "$resolved_directory" ] || die "cannot resolve evidence directory safely"
	protected_directory=$resolved_directory
	case "$protected_directory" in
		/private/*) protected_directory=${protected_directory#/private} ;;
	esac
	case "$protected_directory" in
		/|/bin|/bin/*|/dev|/dev/*|/etc|/etc/*|/home|/home/*|/proc|/proc/*|/root|/root/*|/run|/run/*|/sbin|/sbin/*|/sys|/sys/*|/usr|/usr/*|/var|/var/run|/var/run/*|/var/lib|/var/lib/*|/var/log|/var/log/*|/var/db|/var/db/*|/var/root|/var/root/*)
		die "evidence directory resolves to a protected system path" ;;
	esac
	chmod 0700 "$directory" || die "cannot protect evidence directory '$directory'"
}

new_bundle() {
	parent=$1
	command_name=$2
	timestamp=$(date -u +%Y%m%dT%H%M%SZ)
	bundle=$(mktemp -d "$parent/${command_name}-${timestamp}-XXXXXX") || die "cannot create evidence bundle"
	chmod 0700 "$bundle" || die "cannot protect evidence bundle"
	printf '%s\n' "$bundle"
}

capture() {
	output_file=$1
	shift
	set +e
	"$@" >"$output_file" 2>&1
	status=$?
	set -e
	printf '\nexit_status=%s\n' "$status" >>"$output_file"
	return "$status"
}

write_metadata() {
	metadata_file=$1
	command_name=$2
	target_node=$3
	interface=$4
	action=$5
	{
		printf 'command=%s\n' "$command_name"
		printf 'target_node=%s\n' "$target_node"
		printf 'interface=%s\n' "$interface"
		printf 'action=%s\n' "$action"
		printf 'started_at_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"
	} >"$metadata_file"
}
