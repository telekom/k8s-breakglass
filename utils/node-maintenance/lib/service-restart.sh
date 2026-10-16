#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

set -eu

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
# shellcheck disable=SC1091
. "$script_dir/common.sh"

usage() {
	cat >&2 <<'EOF'
Usage:
  service-restart --target-node NODE --unit UNIT \
    --evidence-dir /evidence[/SAFE_CHILD] --confirm SERVICE-RESTART

Allowed units:
  containerd.service   On a CRA node (cra.service loaded) systemd restarts
                       cra.service with it (Requires=), so the CRA checks apply.
  kubelet.service
  cra.service          The CRA/vSR router container unit (CRA nodes only).

The helper asks systemd over its private socket (mounted read-only at
/run/systemd/private) to restart exactly one unit, then waits until the unit
is active again with a new activation time. On a CRA node it also waits for
cra.service and the host-side hbn and netconf links, and for oam0 to carry a
global address when the node has oam0. Nothing is persisted on the node.

The controller must bind BREAKGLASS_APPROVED_ACTION=service-restart and the
exact BREAKGLASS_APPROVED_SERVICE_REQUEST tuple.
EOF
}

# Upper bound for a unit to come back; the session deadline still applies.
service_restart_wait_seconds=240

target_node=
unit=
evidence_dir=
confirmation=
target_node_seen=false
unit_seen=false
evidence_dir_seen=false
confirmation_seen=false
while [ "$#" -gt 0 ]; do
	case "$1" in
		--target-node) [ "$target_node_seen" = false ] || die "--target-node may be supplied only once"; [ "$#" -ge 2 ] || die "--target-node needs a value"; target_node_seen=true; target_node=$2; shift 2 ;;
		--unit) [ "$unit_seen" = false ] || die "--unit may be supplied only once"; [ "$#" -ge 2 ] || die "--unit needs a value"; unit_seen=true; unit=$2; shift 2 ;;
		--evidence-dir) [ "$evidence_dir_seen" = false ] || die "--evidence-dir may be supplied only once"; [ "$#" -ge 2 ] || die "--evidence-dir needs a value"; evidence_dir_seen=true; evidence_dir=$2; shift 2 ;;
		--confirm) [ "$confirmation_seen" = false ] || die "--confirm may be supplied only once"; [ "$#" -ge 2 ] || die "--confirm needs a value"; confirmation_seen=true; confirmation=$2; shift 2 ;;
		-h|--help) usage; exit 0 ;;
		*) die "unsupported option '$1'" ;;
	esac
done

validate_target "$target_node"
case "$unit" in
	containerd.service|kubelet.service|cra.service) ;;
	*) die "unit '$unit' is not allowlisted" ;;
esac
validate_confirmation SERVICE-RESTART "$confirmation"
validate_recording_context
validate_approved_action service-restart
approved_request=${BREAKGLASS_APPROVED_SERVICE_REQUEST:-}
[ "$approved_request" = "target_node=$target_node&unit=$unit&confirmation=SERVICE-RESTART" ] \
	|| die "controller-approved service request does not exactly match the requested tuple"
validate_action_deadline
prepare_evidence_dir "$evidence_dir"
acquire_operation_lock "$evidence_dir" "$(sha256_text "$approved_request")"
trap 'cleanup_evidence_temporary_candidates || true; release_operation_lock || true' EXIT
assert_no_active_legacy_locks || die "an older node-maintenance operation is active or requires migration"
cleanup_evidence_temporary_candidates || die "cannot clean stale evidence temporary files"

bundle=$(new_bundle "$evidence_dir" service-restart)
write_metadata "$bundle/metadata" service-restart "$target_node" "" service-restart
printf 'unit=%s\n' "$unit" | append_evidence "$bundle/metadata"
record_event operation-started accepted

# probe_field FILE KEY prints one key=value field from a service-action probe capture.
probe_field() {
	sed -n "s/.*[[:space:]]$2=\\([^[:space:]]*\\).*/\\1/p" "$1" | head -n 1
}

if ! capture "$bundle/before-unit.txt" service-action probe "$unit" ||
	[ "$(probe_field "$bundle/before-unit.txt" load_state)" != loaded ]; then
	record_event operation-completed preflight-failed
	die "unit '$unit' is not loaded on this node; nothing was restarted (evidence: $bundle)"
fi
before_enter=$(probe_field "$bundle/before-unit.txt" active_enter_monotonic_us)
case "$before_enter" in
	''|*[!0-9]*)
		record_event operation-completed preflight-failed
		die "unit '$unit' reported no activation time; nothing was restarted (evidence: $bundle)"
		;;
esac
cra_node=false
if capture "$bundle/before-cra.txt" service-action probe cra.service &&
	[ "$(probe_field "$bundle/before-cra.txt" load_state)" = loaded ]; then
	cra_node=true
fi
check_cra=false
case "$unit" in
	cra.service) check_cra=true ;;
	containerd.service) check_cra=$cra_node ;;
esac
cra_before_enter=$(probe_field "$bundle/before-cra.txt" active_enter_monotonic_us)
if [ "$check_cra" = true ]; then
	case "$cra_before_enter" in
		''|*[!0-9]*)
			record_event operation-completed preflight-failed
			die "cra.service reported no activation time; nothing was restarted (evidence: $bundle)"
			;;
	esac
fi
capture "$bundle/before-links.txt" ip -brief link show || true
printf 'cra_node=%s\ncra_checks=%s\n' "$cra_node" "$check_cra" | append_evidence "$bundle/metadata"

validate_action_deadline
set +e
capture "$bundle/action-restart.txt" service-action restart "$unit"
action_status=$?
set -e

# healthy prints nothing and returns 0 when every post-check holds.
healthy() {
	capture "$bundle/after-unit.txt" service-action probe "$unit" || return 1
	[ "$(probe_field "$bundle/after-unit.txt" active_state)" = active ] || return 1
	after_enter=$(probe_field "$bundle/after-unit.txt" active_enter_monotonic_us)
	case "$after_enter" in ''|*[!0-9]*) return 1 ;; esac
	[ "$after_enter" -gt "$before_enter" ] || return 1
	[ "$check_cra" = true ] || return 0
	capture "$bundle/after-cra.txt" service-action probe cra.service || return 1
	[ "$(probe_field "$bundle/after-cra.txt" active_state)" = active ] || return 1
	cra_after_enter=$(probe_field "$bundle/after-cra.txt" active_enter_monotonic_us)
	case "$cra_after_enter" in ''|*[!0-9]*) return 1 ;; esac
	[ "$cra_after_enter" -gt "$cra_before_enter" ] || return 1
	[ -e /sys/class/net/hbn ] && [ -e /sys/class/net/netconf ] || return 1
	if [ -e /sys/class/net/oam0 ]; then
		[ -n "$(ip -o addr show dev oam0 scope global 2>/dev/null)" ] || return 1
	fi
	return 0
}

result=failed
if [ "$action_status" -eq 0 ]; then
	waited=0
	while [ "$waited" -lt "$service_restart_wait_seconds" ]; do
		if healthy; then
			result=succeeded
			break
		fi
		deadline=${BREAKGLASS_ACTION_DEADLINE_UNIX:-}
		if [ -n "$deadline" ] && [ "$(date +%s)" -ge "$deadline" ]; then
			break
		fi
		sleep 5
		waited=$((waited + 5))
	done
fi
capture "$bundle/after-links.txt" ip -brief link show || true
assert_safe_bundle "$bundle"
printf 'action_exit_status=%s\npost_check=%s\ncompleted_at_utc=%s\n' "$action_status" "$result" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" | append_evidence "$bundle/metadata"
if [ "$result" != succeeded ]; then
	record_event operation-completed failed
	printf 'Restart of %s did not pass the post-checks; recommend replacing the node (evidence: %s)\n' "$unit" "$bundle" >&2
	exit 1
fi
record_event operation-completed succeeded
printf 'Restart of %s completed and passed the post-checks; inspect evidence at %s\n' "$unit" "$bundle"
