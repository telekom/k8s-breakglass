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
    --evidence-dir ABSOLUTE_PATH --confirm NETWORK-REPAIR

Allowed actions:
  link-cycle                 Take IFACE down, then bring it back up.
  flush-neighbors            Flush neighbor entries belonging to IFACE.
  restart-autonegotiation    Ask the NIC to restart auto-negotiation.
EOF
}

target_node=
interface=
action=
evidence_dir=
confirmation=
while [ "$#" -gt 0 ]; do
	case "$1" in
		--target-node) [ "$#" -ge 2 ] || die "--target-node needs a value"; target_node=$2; shift 2 ;;
		--interface) [ "$#" -ge 2 ] || die "--interface needs a value"; interface=$2; shift 2 ;;
		--action) [ "$#" -ge 2 ] || die "--action needs a value"; action=$2; shift 2 ;;
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
prepare_evidence_dir "$evidence_dir"

case "$action" in
	link-cycle|flush-neighbors|restart-autonegotiation) ;;
	*) die "action '$action' is not allowlisted" ;;
esac

bundle=$(new_bundle "$evidence_dir" network-repair)
write_metadata "$bundle/metadata" network-repair "$target_node" "$interface" "$action"

if ! capture "$bundle/before-link.txt" ip -details link show dev "$interface"; then
	die "interface '$interface' was not found; no repair was attempted (evidence: $bundle)"
fi
capture "$bundle/before-addresses.txt" ip -brief address show dev "$interface" || true
capture "$bundle/before-routes.txt" ip route show dev "$interface" || true
capture "$bundle/before-neighbors.txt" ip neigh show dev "$interface" || true

printf 'Target: %s\nInterface: %s\nAction: %s\nEvidence: %s\n' \
	"$target_node" "$interface" "$action" "$bundle"
printf 'Confirmation accepted. Applying the allowlisted action...\n'

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
	flush-neighbors)
		capture "$bundle/action-flush-neighbors.txt" ip neigh flush dev "$interface"
		action_status=$?
		;;
	restart-autonegotiation)
		capture "$bundle/action-restart-autonegotiation.txt" ethtool -r "$interface"
		action_status=$?
		;;
esac
set -e

capture "$bundle/after-link.txt" ip -details link show dev "$interface" || true
capture "$bundle/after-addresses.txt" ip -brief address show dev "$interface" || true
capture "$bundle/after-routes.txt" ip route show dev "$interface" || true
capture "$bundle/after-neighbors.txt" ip neigh show dev "$interface" || true
assert_safe_bundle "$bundle"
printf 'action_exit_status=%s\ncompleted_at_utc=%s\n' "$action_status" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$bundle/metadata"

if [ "$action_status" -ne 0 ]; then
	printf 'Repair failed; inspect before/after evidence at %s\n' "$bundle" >&2
	exit "$action_status"
fi
printf 'Repair completed; inspect before/after evidence at %s\n' "$bundle"
