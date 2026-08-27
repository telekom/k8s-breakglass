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
  network-repair --target-node NODE --interface IFACE --action ACTION \
    [action-specific exact target options] \
    --evidence-dir /evidence[/SAFE_CHILD] --confirm NETWORK-REPAIR

Allowed actions:
  link-cycle                 Take IFACE down, then bring it back up.
  restart-autonegotiation    Ask IFACE to restart auto-negotiation.
  neighbor-replace           Replace one exact IP-to-MAC neighbor entry.
    requires --neighbor-address IP --entry-mac MAC
  bridge-fdb-replace         Replace one exact bridge FDB entry.
    requires --bridge BRIDGE --entry-mac MAC --vlan VLAN

The controller must independently bind BREAKGLASS_APPROVED_ACTION to the
requested action and provide operation, approval, and recording identifiers.
EOF
}

target_node=
interface=
action=
neighbor_address=
bridge_name=
entry_mac=
vlan=
evidence_dir=
confirmation=
while [ "$#" -gt 0 ]; do
	case "$1" in
		--target-node) [ "$#" -ge 2 ] || die "--target-node needs a value"; target_node=$2; shift 2 ;;
		--interface) [ "$#" -ge 2 ] || die "--interface needs a value"; interface=$2; shift 2 ;;
		--action) [ "$#" -ge 2 ] || die "--action needs a value"; action=$2; shift 2 ;;
		--neighbor-address) [ "$#" -ge 2 ] || die "--neighbor-address needs a value"; neighbor_address=$2; shift 2 ;;
		--bridge) [ "$#" -ge 2 ] || die "--bridge needs a value"; bridge_name=$2; shift 2 ;;
		--entry-mac) [ "$#" -ge 2 ] || die "--entry-mac needs a value"; entry_mac=$2; shift 2 ;;
		--vlan) [ "$#" -ge 2 ] || die "--vlan needs a value"; vlan=$2; shift 2 ;;
		--evidence-dir) [ "$#" -ge 2 ] || die "--evidence-dir needs a value"; evidence_dir=$2; shift 2 ;;
		--confirm) [ "$#" -ge 2 ] || die "--confirm needs a value"; confirmation=$2; shift 2 ;;
		-h|--help) usage; exit 0 ;;
		*) die "unsupported option '$1'" ;;
	esac
done

validate_target "$target_node"
validate_interface "$interface"
validate_value "action" "$action"
validate_confirmation NETWORK-REPAIR "$confirmation"
validate_recording_context

case "$action" in
	link-cycle|restart-autonegotiation)
		[ -z "$neighbor_address$bridge_name$entry_mac$vlan" ] || die "action '$action' does not accept entry-target options"
		;;
	neighbor-replace)
		[ -z "$bridge_name$vlan" ] || die "neighbor-replace does not accept bridge or VLAN targets"
		validate_neighbor_address "$neighbor_address"
		validate_mac_address "neighbor MAC" "$entry_mac"
		;;
	bridge-fdb-replace)
		[ -z "$neighbor_address" ] || die "bridge-fdb-replace does not accept a neighbor address"
		validate_interface "$bridge_name"
		[ "$bridge_name" != "$interface" ] || die "bridge and port interface must be different"
		validate_mac_address "FDB MAC" "$entry_mac"
		validate_vlan "$vlan"
		;;
	*) die "action '$action' is not allowlisted" ;;
esac

validate_approved_action "$action"
prepare_evidence_dir "$evidence_dir"
trap 'release_operation_lock || true' EXIT
acquire_operation_lock "$evidence_dir"

bundle=$(new_bundle "$evidence_dir" network-repair)
write_metadata "$bundle/metadata" network-repair "$target_node" "$interface" "$action"
{
	[ -z "$neighbor_address" ] || printf 'neighbor_address=%s\n' "$neighbor_address"
	[ -z "$bridge_name" ] || printf 'bridge=%s\n' "$bridge_name"
	[ -z "$entry_mac" ] || printf 'entry_mac=%s\n' "$entry_mac"
	[ -z "$vlan" ] || printf 'vlan=%s\n' "$vlan"
} >>"$bundle/metadata"
record_event operation-started accepted

if ! capture "$bundle/before-link.txt" ip -details link show dev "$interface"; then
	record_event operation-completed preflight-failed
	die "interface '$interface' was not found; no repair was attempted (evidence: $bundle)"
fi
capture "$bundle/before-addresses.txt" ip -brief address show dev "$interface" || true
capture "$bundle/before-routes.txt" ip route show dev "$interface" || true
capture "$bundle/before-neighbors.txt" ip neigh show dev "$interface" || true

case "$action" in
	neighbor-replace)
		if ! capture "$bundle/before-neighbor-route.txt" ip "$NEIGHBOR_FAMILY" route get "$neighbor_address" dev "$interface"; then
			record_event operation-completed preflight-failed
			die "neighbor '$neighbor_address' is not reachable through exact interface '$interface'; no repair was attempted (evidence: $bundle)"
		fi
		capture "$bundle/before-neighbor-entry.txt" ip "$NEIGHBOR_FAMILY" neigh show to "$neighbor_address" dev "$interface" || true
		;;
	bridge-fdb-replace)
		if ! capture "$bundle/before-bridge.txt" ip -details link show dev "$bridge_name"; then
			record_event operation-completed preflight-failed
			die "bridge '$bridge_name' was not found; no repair was attempted (evidence: $bundle)"
		fi
		if [ ! -d "/sys/class/net/$bridge_name/bridge" ]; then
			record_event operation-completed preflight-failed
			die "'$bridge_name' is not a bridge; no repair was attempted (evidence: $bundle)"
		fi
		master_path=$(readlink -f "/sys/class/net/$interface/master" 2>/dev/null || true)
		master=${master_path##*/}
		if [ "$master" != "$bridge_name" ]; then
			record_event operation-completed preflight-failed
			die "interface '$interface' is not attached to exact bridge '$bridge_name'; no repair was attempted (evidence: $bundle)"
		fi
		capture "$bundle/before-bridge-vlan.txt" bridge vlan show dev "$interface" || true
		# Defined by the sourced fixed-limit contract in common.sh.
		# shellcheck disable=SC2154
		if ! timeout "$capture_timeout_seconds" bridge vlan show dev "$interface" | awk -v requested="$vlan" '
			{
				for (i = 1; i <= NF; i++) {
					if ($i ~ /^[0-9]+$/ && $i == requested) found = 1
					if ($i ~ /^[0-9]+-[0-9]+$/) {
						split($i, limits, "-")
						if (requested >= limits[1] && requested <= limits[2]) found = 1
					}
				}
			}
			END { exit(found ? 0 : 1) }
		'; then
			record_event operation-completed preflight-failed
			die "VLAN '$vlan' is not configured on exact bridge port '$interface'; no repair was attempted (evidence: $bundle)"
		fi
		capture "$bundle/before-fdb-entry.txt" bridge -details fdb show br "$bridge_name" brport "$interface" || true
		;;
esac

printf 'Target: %s\nInterface: %s\nAction: %s\nEvidence: %s\n' \
	"$target_node" "$interface" "$action" "$bundle"
printf 'Confirmation and controller action binding accepted. Applying one allowlisted action...\n'

set +e
case "$action" in
	link-cycle)
		if capture "$bundle/action-link-down.txt" ip link set dev "$interface" down; then
			capture "$bundle/action-link-up.txt" ip link set dev "$interface" up
			action_status=$?
		else
			action_status=$?
		fi
		;;
	restart-autonegotiation)
		capture "$bundle/action-restart-autonegotiation.txt" ethtool -r "$interface"
		action_status=$?
		;;
	neighbor-replace)
		capture "$bundle/action-neighbor-replace.txt" ip "$NEIGHBOR_FAMILY" neigh replace "$neighbor_address" lladdr "$entry_mac" nud reachable dev "$interface"
		action_status=$?
		;;
	bridge-fdb-replace)
		capture "$bundle/action-bridge-fdb-replace.txt" bridge fdb replace "$entry_mac" dev "$interface" master static vlan "$vlan"
		action_status=$?
		;;
esac
set -e

capture "$bundle/after-link.txt" ip -details link show dev "$interface" || true
capture "$bundle/after-addresses.txt" ip -brief address show dev "$interface" || true
capture "$bundle/after-routes.txt" ip route show dev "$interface" || true
capture "$bundle/after-neighbors.txt" ip neigh show dev "$interface" || true
case "$action" in
	neighbor-replace)
		capture "$bundle/after-neighbor-entry.txt" ip "$NEIGHBOR_FAMILY" neigh show to "$neighbor_address" dev "$interface" || true
		;;
	bridge-fdb-replace)
		capture "$bundle/after-bridge-vlan.txt" bridge vlan show dev "$interface" || true
		capture "$bundle/after-fdb-entry.txt" bridge -details fdb show br "$bridge_name" brport "$interface" || true
		;;
esac
assert_safe_bundle "$bundle"
printf 'action_exit_status=%s\ncompleted_at_utc=%s\n' "$action_status" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$bundle/metadata"

if [ "$action_status" -ne 0 ]; then
	record_event operation-completed failed
	printf 'Repair failed; inspect before/after evidence at %s\n' "$bundle" >&2
	exit "$action_status"
fi
record_event operation-completed succeeded
printf 'Repair completed; inspect before/after evidence at %s\n' "$bundle"
