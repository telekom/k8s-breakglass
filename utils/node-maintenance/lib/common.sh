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
# Kubernetes Node names are DNS subdomains and therefore at most 253 bytes.
node_name_max_bytes=253
capture_timeout_seconds=10
capture_max_bytes=32768
evidence_max_bytes=393216
# The canonical network approval has 88 literal delimiter/key bytes. Its
# largest public request is 442 bytes: a 253-byte Node name, a 15-byte Linux
# interface, neighbor-replace, a 39-byte IPv6 literal, a 17-byte MAC, and the
# fixed confirmation. Keep a fixed, explicit 1 KiB serialized-input ceiling as
# a separate malformed-controller-data guard rather than applying the generic
# per-value limit to the canonical tuple itself.
approved_network_request_max_bytes=1024
operation_lock_name=.node-maintenance-operation.lock

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
	validate_kubernetes_node_name "target node" "$target"
	actual_node=${BREAKGLASS_NODE_NAME:-}
	validate_kubernetes_node_name "BREAKGLASS_NODE_NAME" "$actual_node"
	[ "$target" = "$actual_node" ] || die "target node '$target' does not match controller-provided node '$actual_node'"
}

validate_kubernetes_node_name() {
	label=$1
	node_name=$2
	validate_value "$label" "$node_name"
	[ "${#node_name}" -le "$node_name_max_bytes" ] || die "$label exceeds the Kubernetes ${node_name_max_bytes}-byte limit"
	# Kubernetes Node names use RFC 1123 DNS-subdomain syntax: lowercase
	# alphanumeric labels, hyphens only within labels, and no label over 63 bytes.
	if ! printf '%s\n' "$node_name" | awk '
		{
			label_count = split($0, label, ".")
			for (i = 1; i <= label_count; i++) {
				if (length(label[i]) < 1 || length(label[i]) > 63 || label[i] !~ /^[a-z0-9]([a-z0-9-]*[a-z0-9])?$/) exit 1
			}
			exit 0
		}
	'; then
		die "$label must be a Kubernetes DNS subdomain"
	fi
}

validate_interface() {
	validate_linux_interface "interface" "$1"
}

validate_linux_interface() {
	label=$1
	interface_name=$2
	validate_value "$label" "$interface_name"
	# Linux IFNAMSIZ is 16 including its terminating NUL byte.
	[ "${#interface_name}" -le 15 ] || die "$label exceeds the Linux 15-byte interface-name limit"
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
	operation_artifact_id=$(sha256_text "$operation_id")
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
	[ "${#approved_request}" -le "$approved_network_request_max_bytes" ] || die "BREAKGLASS_APPROVED_NETWORK_REQUEST exceeds the fixed ${approved_network_request_max_bytes}-byte limit"
	expected_request="target_node=$requested_target&interface=$requested_interface&action=$requested_action&neighbor_address=$requested_neighbor&bridge=$requested_bridge&entry_mac=$requested_mac&vlan=$requested_vlan&confirmation=$requested_confirmation"
	[ "$approved_request" = "$expected_request" ] || die "controller-approved network request does not exactly match the requested tuple"
	# Consumed by the network-repair caller after this file is sourced.
	# shellcheck disable=SC2034
	APPROVED_NETWORK_REQUEST_DIGEST=$(sha256_text "$approved_request")
}

sha256_text() {
	value=$1
	digest=$(printf '%s' "$value" | sha256sum | awk 'NR == 1 { print $1 }') || die "cannot hash immutable operation tuple"
	validate_sha256 "operation tuple digest" "$digest"
	printf '%s\n' "$digest"
}

ensure_operation_artifact_id() {
	# Direct users of the common capture contract (including image self-tests)
	# may not have a controller recording context.  They still get a stable,
	# exact-format artifact identity; production commands always derive it from
	# the validated operation ID above.
	if [ -z "${operation_artifact_id:-}" ]; then
		operation_artifact_id=$(sha256_text "${operation_id:-node-maintenance-direct}")
	fi
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
	tuple_digest=$2
	assert_safe_evidence_dir "$directory"
	# The lock belongs to the mounted evidence volume, not to an optional
	# one-level evidence child.  This keeps all allowed EVIDENCE_DIR values in
	# one serialization domain.
	lock_directory=/evidence
	assert_safe_evidence_dir "$lock_directory"
	validate_sha256 "operation tuple digest" "$tuple_digest"
	command -v flock >/dev/null 2>&1 || die "flock utility is required for crash-safe operation exclusivity"
	lock_candidate="$lock_directory/$operation_lock_name"
	[ ! -L "$lock_candidate" ] || die "operation lock may not be a symlink"
	if [ ! -e "$lock_candidate" ]; then
		(umask 077; : >"$lock_candidate") || die "cannot create operation lock"
	fi
	operation_lock=$lock_candidate
	if [ ! -f "$operation_lock" ] || [ -L "$operation_lock" ]; then
		die "operation lock must be a regular file"
	fi
	resolved_lock=$(readlink -f "$operation_lock" 2>/dev/null || true)
	[ "$resolved_lock" = "$operation_lock" ] || die "operation lock did not resolve safely"
	chmod 0600 "$operation_lock" || die "cannot protect operation lock"
	# The fixed descriptor remains open in this shell and every bounded capture
	# child. Linux releases the advisory lock automatically on normal exit,
	# SIGKILL, or container death; wall-clock age is never a liveness signal.
	exec 9>>"$operation_lock" || die "cannot open operation lock"
	if ! flock -n 9; then
		exec 9>&-
		operation_lock=
		die "another node-maintenance operation is active for this evidence lock"
	fi
	operation_lock_tuple_digest=$tuple_digest
	# Truncate and write through the already locked descriptor, never by
	# resolving the evidence path a second time.
	: >"/proc/self/fd/9" || die "cannot reset operation lock record"
	printf 'schema=node-maintenance-lock/v2\noperation_id=%s\nrecording_id=%s\napproval_id=%s\ntuple_sha256=%s\nholder_pid=%s\nacquired_epoch=%s\n' \
		"$operation_id" "$recording_id" "${approval_id:-}" "$operation_lock_tuple_digest" "$$" "$(date -u +%s)" \
		>&9 || die "cannot record operation lock owner"
}

cleanup_evidence_temporary_candidates() {
	# This function is called only while the root evidence-volume flock is held.
	# A killed operation cannot run its EXIT trap, so the next lock holder removes
	# only image-created temporary names owned by the helper. Candidates live at
	# the selected volume root or safe child, never inside a committed bundle.
	[ -d /evidence ] && [ ! -L /evidence ] || return 1
	owner_uid=$(id -u) || return 1
	cleanup_temporary_directory() {
		directory=$1
		[ -d "$directory" ] && [ ! -L "$directory" ] || return 0
		for candidate in "$directory"/.capture-* "$directory"/.evidence-*; do
			[ -e "$candidate" ] || [ -L "$candidate" ] || continue
			[ -f "$candidate" ] || [ -p "$candidate" ] || continue
			candidate_owner=$(stat -c %u "$candidate" 2>/dev/null) || return 1
			[ "$candidate_owner" = "$owner_uid" ] || continue
			candidate_name=${candidate##*/}
			if ! printf '%s\n' "$candidate_name" | awk '
				/^\.capture-[0-9A-Fa-f]+(-status|-fifo|-quota)?\.[A-Za-z0-9]+$/ { id=$0; sub(/^\.capture-/, "", id); sub(/(-status|-fifo|-quota)?\.[A-Za-z0-9]+$/, "", id); if (length(id) == 64) exit 0 }
				/^\.evidence-[0-9A-Fa-f]+-(write|append)\.[A-Za-z0-9]+$/ { id=$0; sub(/^\.evidence-/, "", id); sub(/-(write|append)\.[A-Za-z0-9]+$/, "", id); if (length(id) == 64) exit 0 }
				{ exit 1 }
			'; then
				continue
			fi
			rm -f "$candidate" || return 1
		done
	}
	cleanup_temporary_directory /evidence || return 1
	if [ "${EVIDENCE_DIR:-/evidence}" != /evidence ]; then
		cleanup_temporary_directory "$EVIDENCE_DIR" || return 1
	fi
}

assert_no_active_legacy_locks() {
	# Releases before the volume-root lock used one lock file per safe child.
	# Never remove or overwrite those files: reject a new operation while a
	# legacy descriptor still holds one, and otherwise leave the stale file for
	# an operator-led migration cleanup.
	[ -d /evidence ] && [ ! -L /evidence ] || return 1
	for legacy_lock in /evidence/*/.node-maintenance-operation.lock; do
		[ -e "$legacy_lock" ] || [ -L "$legacy_lock" ] || continue
		legacy_directory=${legacy_lock%/*}
		[ -d "$legacy_directory" ] && [ ! -L "$legacy_directory" ] || return 1
		legacy_resolved=$(readlink -f "$legacy_directory" 2>/dev/null) || return 1
		[ "$legacy_resolved" = "$legacy_directory" ] || return 1
		[ ! -L "$legacy_lock" ] || return 1
		[ -f "$legacy_lock" ] || return 1
		if ! (exec 8<"$legacy_lock" && flock -n 8); then
			return 1
		fi
	done
}

release_operation_lock() {
	if [ -n "${operation_lock:-}" ]; then
		[ -n "${EVIDENCE_DIR:-}" ] && [ -d "$EVIDENCE_DIR" ] && [ ! -L "$EVIDENCE_DIR" ] || return 1
		case "$operation_lock" in "/evidence/$operation_lock_name") ;; *) return 1 ;; esac
		grep -Fqx "operation_id=$operation_id" /proc/self/fd/9 || return 1
		grep -Fqx "recording_id=$recording_id" /proc/self/fd/9 || return 1
		grep -Fqx "tuple_sha256=$operation_lock_tuple_digest" /proc/self/fd/9 || return 1
		flock -u 9 || return 1
		exec 9>&-
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

evidence_disk_kib() {
	evidence_path=$1
	evidence_kib=$(du -sk "$evidence_path" | awk 'NR == 1 { print $1 }') || die "cannot determine evidence disk usage"
	case "$evidence_kib" in ''|*[!0-9]*) die "cannot determine evidence disk usage" ;; esac
	printf '%s\n' "$evidence_kib"
}

assert_safe_evidence_output() {
	evidence_output=$1
	case "$evidence_output" in "${bundle:?bundle is not initialized}"/*) ;; *) die "unsafe evidence output path" ;; esac
	assert_safe_bundle "$bundle"
	if [ -e "$evidence_output" ] || [ -L "$evidence_output" ]; then
		[ -f "$evidence_output" ] && [ ! -L "$evidence_output" ] || die "evidence output is not a regular file"
	fi
}

commit_evidence_file() {
	evidence_candidate=$1
	evidence_output=$2
	assert_safe_evidence_output "$evidence_output"
	[ -f "$evidence_candidate" ] && [ ! -L "$evidence_candidate" ] || die "evidence candidate is not a regular file"
	ensure_operation_artifact_id
	case "$evidence_candidate" in
		"${EVIDENCE_DIR:?evidence directory is not initialized}"/.evidence-"$operation_artifact_id"-write.*|"$EVIDENCE_DIR"/.evidence-"$operation_artifact_id"-append.*|"$EVIDENCE_DIR"/.capture-"$operation_artifact_id".*|"$EVIDENCE_DIR"/.capture-"$operation_artifact_id"-status.*|"$EVIDENCE_DIR"/.capture-"$operation_artifact_id"-fifo.*|"$EVIDENCE_DIR"/.capture-"$operation_artifact_id"-quota.*) ;;
		*) die "unsafe evidence candidate" ;;
	esac

	current_kib=$(evidence_disk_kib "$bundle")
	output_kib=0
	if [ -e "$evidence_output" ]; then
		output_kib=$(evidence_disk_kib "$evidence_output")
	fi
	candidate_kib=$(evidence_disk_kib "$evidence_candidate")
	maximum_kib=$((evidence_max_bytes / 1024))
	final_kib=$((current_kib - output_kib + candidate_kib))
	if [ "$final_kib" -gt "$maximum_kib" ]; then
		rm -f "$evidence_candidate" || die "cannot remove over-quota evidence candidate"
		die "evidence quota exceeded"
	fi

	# Flush the complete candidate before rename.  BusyBox sync is part of the
	# pinned base image and avoids an unreviewed filesystem-specific helper.
	if ! command -v sync >/dev/null 2>&1; then
		rm -f "$evidence_candidate" || true
		die "sync utility is required for bounded evidence durability"
	fi
	if ! sync; then
		rm -f "$evidence_candidate" || true
		die "cannot flush bounded evidence candidate"
	fi
	# The process-held evidence-volume flock serializes all bundle writers. The
	# candidate lives beside the bundle on the same controller-owned volume;
	# rename replaces the output atomically only after the final quota is known.
	mv -f "$evidence_candidate" "$evidence_output" || {
		rm -f "$evidence_candidate" || true
		die "cannot commit bounded evidence output"
	}
	sync || die "cannot flush committed evidence output"
}

write_evidence() {
	evidence_output=$1
	ensure_operation_artifact_id
	evidence_candidate=$(mktemp "${EVIDENCE_DIR:?evidence directory is not initialized}/.evidence-$operation_artifact_id-write.XXXXXX") || die "cannot create bounded evidence candidate"
	if ! cat >"$evidence_candidate"; then
		rm -f "$evidence_candidate" || true
		die "cannot write bounded evidence candidate"
	fi
	commit_evidence_file "$evidence_candidate" "$evidence_output"
}

append_evidence() {
	evidence_output=$1
	assert_safe_evidence_output "$evidence_output"
	ensure_operation_artifact_id
	evidence_candidate=$(mktemp "${EVIDENCE_DIR:?evidence directory is not initialized}/.evidence-$operation_artifact_id-append.XXXXXX") || die "cannot create bounded evidence candidate"
	if [ -e "$evidence_output" ] && ! cat "$evidence_output" >"$evidence_candidate"; then
		rm -f "$evidence_candidate" || true
		die "cannot read existing evidence output"
	fi
	if ! cat >>"$evidence_candidate"; then
		rm -f "$evidence_candidate" || true
		die "cannot append bounded evidence candidate"
	fi
	commit_evidence_file "$evidence_candidate" "$evidence_output"
}

capture() {
	output_file=$1
	shift
	ensure_operation_artifact_id
	assert_safe_evidence_output "$output_file"
	command -v timeout >/dev/null 2>&1 || die "timeout utility is required for bounded evidence capture"
	temporary_file=$(mktemp "${EVIDENCE_DIR:?evidence directory is not initialized}/.capture-$operation_artifact_id.XXXXXX") || die "cannot create bounded capture temporary file"
	status_file=$(mktemp "$EVIDENCE_DIR/.capture-$operation_artifact_id-status.XXXXXX") || {
		rm -f "$temporary_file" || true
		die "cannot create capture status file"
	}
	fifo=$(mktemp "$EVIDENCE_DIR/.capture-$operation_artifact_id-fifo.XXXXXX") || {
		rm -f "$temporary_file" "$status_file" || true
		die "cannot reserve capture pipe"
	}
	rm -f "$fifo" || {
		rm -f "$temporary_file" "$status_file" "$fifo" || true
		die "cannot prepare capture pipe"
	}
	mkfifo -m 0600 "$fifo" || {
		rm -f "$temporary_file" "$status_file" "$fifo" || true
		die "cannot create capture pipe"
	}
	(
		set +e
		timeout "$capture_timeout_seconds" "$@" >"$fifo" 2>&1
		producer_status=$?
		if ! printf '%s\n' "$producer_status" >"$status_file"; then
			exit 125
		fi
	) &
	producer_pid=$!
	# Read at most one byte beyond the fixed quota. Closing the FIFO then
	# back-pressures or terminates a noisy producer instead of allowing an
	# unbounded temporary file to grow before the quota is checked.
	if ! head -c "$((capture_max_bytes + 1))" "$fifo" >"$temporary_file"; then
		rm -f "$fifo" "$status_file" "$temporary_file" || true
		die "cannot read bounded command output"
	fi
	if ! wait "$producer_pid"; then
		[ -s "$status_file" ] || {
			rm -f "$fifo" "$status_file" "$temporary_file" || true
			die "capture producer exited without reporting a status"
		}
	fi
	rm -f "$fifo" || {
		rm -f "$status_file" "$temporary_file" || true
		die "cannot remove capture pipe"
	}
	[ -s "$status_file" ] || {
		rm -f "$status_file" "$temporary_file" || true
		die "capture command did not report an exit status"
	}
	status=$(cat "$status_file") || {
		rm -f "$status_file" "$temporary_file" || true
		die "cannot read capture command status"
	}
	rm -f "$status_file" || {
		rm -f "$temporary_file" || true
		die "cannot remove capture status file"
	}
	case "$status" in ''|*[!0-9]*) rm -f "$temporary_file" || true; die "capture command reported an invalid exit status" ;; esac
	bytes=$(wc -c <"$temporary_file" | tr -d ' ') || {
		rm -f "$temporary_file" || true
		die "cannot determine bounded capture size"
	}
	case "$bytes" in ''|*[!0-9]*) rm -f "$temporary_file" || true; die "cannot determine bounded capture size" ;; esac
	if [ "$bytes" -gt "$capture_max_bytes" ]; then
		quota_file=$(mktemp "$EVIDENCE_DIR/.capture-$operation_artifact_id-quota.XXXXXX") || {
			rm -f "$temporary_file" || true
			die "cannot create bounded capture candidate"
		}
		head -c "$capture_max_bytes" "$temporary_file" >"$quota_file" || {
			rm -f "$temporary_file" "$quota_file" || true
			die "cannot trim bounded capture candidate"
		}
		rm -f "$temporary_file" || {
			rm -f "$quota_file" || true
			die "cannot remove bounded capture source"
		}
		temporary_file=$quota_file
		if ! printf '\ncapture_result=output-quota-exceeded\nexit_status=75\n' >>"$temporary_file"; then
			rm -f "$temporary_file" || true
			die "cannot finalize bounded quota capture"
		fi
		commit_evidence_file "$temporary_file" "$output_file"
		return 75
	fi
	if ! printf '\nexit_status=%s\n' "$status" >>"$temporary_file"; then
		rm -f "$temporary_file" || true
		die "cannot finalize bounded capture"
	fi
	commit_evidence_file "$temporary_file" "$output_file"
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
	} | write_evidence "$metadata_file"
}

record_event() {
	event_name=$1
	result=$2
	assert_safe_bundle "${bundle:?bundle is not initialized}"
	validate_value "recording event" "$event_name"
	validate_value "recording result" "$result"
	printf '{"time":"%s","event":"%s","result":"%s","operation_id":"%s","recording_id":"%s","target_node":"%s"}\n' \
		"$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$event_name" "$result" "$operation_id" "$recording_id" "$target_node" \
		| append_evidence "$bundle/events.jsonl"
}
