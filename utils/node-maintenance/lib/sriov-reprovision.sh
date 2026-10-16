#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

set -eu

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
# shellcheck disable=SC1091
. "$script_dir/common.sh"

usage() {
	cat >&2 <<'EOF2'
Usage:
  sriov-reprovision --target-node NODE --interface PF --virtual-functions N \
    --evidence-dir /evidence[/SAFE_CHILD] --confirm SRIOV-REPROVISION

Re-creates the SR-IOV virtual functions of one physical function (PF) from the
node's own netplan configuration, for a node that lost them (for example the
boot-order race of SCHIFF-3206). The helper asks systemd over its private
socket (mounted read-only at /run/systemd/private) to run, as transient host
units:

  netplan apply --sriov-only
  netplan rebind PF

and then waits until the PF has exactly N virtual functions, each bound to a
driver. N is the approved count from the allowlist; a netplan configuration
that yields another count fails the post-check. Nothing is persisted.

The controller must bind BREAKGLASS_APPROVED_ACTION=sriov-reprovision and the
exact BREAKGLASS_APPROVED_SRIOV_REQUEST tuple.
EOF2
}

# Upper bound for the VFs to appear and bind; the session deadline still applies.
sriov_wait_seconds=120

target_node=
pf=
vfs=
evidence_dir=
confirmation=
target_node_seen=false
pf_seen=false
vfs_seen=false
evidence_dir_seen=false
confirmation_seen=false
while [ "$#" -gt 0 ]; do
	case "$1" in
		--target-node) [ "$target_node_seen" = false ] || die "--target-node may be supplied only once"; [ "$#" -ge 2 ] || die "--target-node needs a value"; target_node_seen=true; target_node=$2; shift 2 ;;
		--interface) [ "$pf_seen" = false ] || die "--interface may be supplied only once"; [ "$#" -ge 2 ] || die "--interface needs a value"; pf_seen=true; pf=$2; shift 2 ;;
		--virtual-functions) [ "$vfs_seen" = false ] || die "--virtual-functions may be supplied only once"; [ "$#" -ge 2 ] || die "--virtual-functions needs a value"; vfs_seen=true; vfs=$2; shift 2 ;;
		--evidence-dir) [ "$evidence_dir_seen" = false ] || die "--evidence-dir may be supplied only once"; [ "$#" -ge 2 ] || die "--evidence-dir needs a value"; evidence_dir_seen=true; evidence_dir=$2; shift 2 ;;
		--confirm) [ "$confirmation_seen" = false ] || die "--confirm may be supplied only once"; [ "$#" -ge 2 ] || die "--confirm needs a value"; confirmation_seen=true; confirmation=$2; shift 2 ;;
		-h|--help) usage; exit 0 ;;
		*) die "unsupported option '$1'" ;;
	esac
done

validate_target "$target_node"
validate_interface "$pf"
case "$pf" in .|..|-*) die "interface '$pf' is not a PF name" ;; esac
case "$vfs" in
	''|0*|*[!0-9]*) die "--virtual-functions must be a positive integer without leading zeros" ;;
esac
[ "$vfs" -le 256 ] || die "--virtual-functions must not exceed 256"
validate_confirmation SRIOV-REPROVISION "$confirmation"
validate_recording_context
validate_approved_action sriov-reprovision
approved_request=${BREAKGLASS_APPROVED_SRIOV_REQUEST:-}
[ "$approved_request" = "target_node=$target_node&interface=$pf&virtual_functions=$vfs&confirmation=SRIOV-REPROVISION" ] \
	|| die "controller-approved SR-IOV request does not exactly match the requested tuple"
validate_action_deadline
prepare_evidence_dir "$evidence_dir"
acquire_operation_lock "$evidence_dir" "$(sha256_text "$approved_request")"
trap 'cleanup_evidence_temporary_candidates || true; release_operation_lock || true' EXIT
assert_no_active_legacy_locks || die "an older node-maintenance operation is active or requires migration"
cleanup_evidence_temporary_candidates || die "cannot clean stale evidence temporary files"

bundle=$(new_bundle "$evidence_dir" sriov-reprovision)
write_metadata "$bundle/metadata" sriov-reprovision "$target_node" "$pf" sriov-reprovision
printf 'virtual_functions=%s\n' "$vfs" | append_evidence "$bundle/metadata"
record_event operation-started accepted

device=/sys/class/net/$pf/device
# vf_state prints "numvfs=X present=Y bound=Z" for the PF.
vf_state() {
	numvfs=$(cat "$device/sriov_numvfs" 2>/dev/null || echo -)
	present=0
	bound=0
	for vf in "$device"/virtfn*; do
		[ -e "$vf" ] || continue
		present=$((present + 1))
		[ -e "$vf/driver" ] && bound=$((bound + 1))
	done
	printf 'numvfs=%s present=%s bound=%s\n' "$numvfs" "$present" "$bound"
}

total=$(cat "$device/sriov_totalvfs" 2>/dev/null || true)
case "$total" in
	''|*[!0-9]*)
		record_event operation-completed preflight-failed
		die "interface '$pf' is not an SR-IOV physical function on this node; nothing was changed (evidence: $bundle)"
		;;
esac
if [ "$total" -lt "$vfs" ]; then
	record_event operation-completed preflight-failed
	die "interface '$pf' supports $total virtual functions, fewer than the approved $vfs; nothing was changed (evidence: $bundle)"
fi
vf_state | append_evidence "$bundle/before-vfs.txt"
printf 'sriov_totalvfs=%s\n' "$total" | append_evidence "$bundle/before-vfs.txt"
capture "$bundle/before-links.txt" ip -brief link show || true

validate_action_deadline
# service-action bounds each netplan run to 120 s and then stops the unit; the
# 10-second evidence bound would kill it first. Allow 150 s per step, never
# beyond the approved deadline.
netplan_timeout() {
	capture_timeout_seconds=150
	# shellcheck disable=SC2154 # action_deadline is set by validate_action_deadline in common.sh
	if [ -n "$action_deadline" ]; then
		remaining=$((action_deadline - $(date +%s)))
		[ "$remaining" -ge "$capture_timeout_seconds" ] || capture_timeout_seconds=$remaining
	fi
	[ "$capture_timeout_seconds" -gt 0 ]
}
set +e
apply_status=deadline
rebind_status=-
if netplan_timeout; then
	capture "$bundle/action-netplan-sriov-apply.txt" service-action netplan-sriov-apply
	apply_status=$?
fi
if [ "$apply_status" = 0 ]; then
	rebind_status=deadline
	if netplan_timeout; then
		capture "$bundle/action-netplan-rebind.txt" service-action netplan-rebind "$pf"
		rebind_status=$?
	fi
fi
capture_timeout_seconds=10
set -e

result=failed
if [ "$apply_status" = 0 ] && [ "$rebind_status" = 0 ]; then
	waited=0
	while [ "$waited" -lt "$sriov_wait_seconds" ]; do
		if [ "$(vf_state)" = "numvfs=$vfs present=$vfs bound=$vfs" ]; then
			result=succeeded
			break
		fi
		deadline=${BREAKGLASS_ACTION_DEADLINE_UNIX:-}
		if [ -n "$deadline" ] && [ "$(date +%s)" -ge "$deadline" ]; then
			break
		fi
		sleep 2
		waited=$((waited + 2))
	done
fi
vf_state | append_evidence "$bundle/after-vfs.txt"
capture "$bundle/after-links.txt" ip -brief link show || true
assert_safe_bundle "$bundle"
printf 'apply_exit_status=%s\nrebind_exit_status=%s\npost_check=%s\ncompleted_at_utc=%s\n' \
	"$apply_status" "$rebind_status" "$result" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" | append_evidence "$bundle/metadata"
if [ "$result" != succeeded ]; then
	record_event operation-completed failed
	printf 'SR-IOV re-provision of %s did not reach %s bound virtual functions; recommend replacing the node (evidence: %s)\n' "$pf" "$vfs" "$bundle" >&2
	exit 1
fi
record_event operation-completed succeeded
printf 'SR-IOV re-provision of %s completed with %s bound virtual functions; inspect evidence at %s\n' "$pf" "$vfs" "$bundle"
