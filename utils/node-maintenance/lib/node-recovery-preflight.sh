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
  node-recovery --target-node NODE --interface IFACE \
    --evidence-dir ABSOLUTE_PATH --confirm NODE-RECOVERY-PREFLIGHT

This command is read-only. It records link, address, route, neighbor, NIC,
resolver, and kernel evidence for the explicitly named node and interface.
EOF
}

target_node=
interface=
evidence_dir=
confirmation=
while [ "$#" -gt 0 ]; do
	case "$1" in
		--target-node) [ "$#" -ge 2 ] || die "--target-node needs a value"; target_node=$2; shift 2 ;;
		--interface) [ "$#" -ge 2 ] || die "--interface needs a value"; interface=$2; shift 2 ;;
		--evidence-dir) [ "$#" -ge 2 ] || die "--evidence-dir needs a value"; evidence_dir=$2; shift 2 ;;
		--confirm) [ "$#" -ge 2 ] || die "--confirm needs a value"; confirmation=$2; shift 2 ;;
		-h|--help) usage; exit 0 ;;
		*) die "unsupported option '$1'" ;;
	esac
done

validate_target "$target_node"
validate_interface "$interface"
validate_confirmation NODE-RECOVERY-PREFLIGHT "$confirmation"
validate_recording_context
prepare_evidence_dir "$evidence_dir"
trap 'release_operation_lock || true' EXIT
acquire_operation_lock "$evidence_dir"

bundle=$(new_bundle "$evidence_dir" node-recovery)
write_metadata "$bundle/metadata" node-recovery "$target_node" "$interface" read-only
record_event operation-started accepted

if ! capture "$bundle/interface.txt" ip -details link show dev "$interface"; then
	record_event operation-completed preflight-failed
	printf 'Interface %s was not found; evidence bundle is incomplete: %s\n' "$interface" "$bundle" >&2
	exit 1
fi

# Each probe is fixed and read-only. A driver may not support every probe, so
# its exit status is retained in the evidence and does not hide other probes.
capture "$bundle/addresses.txt" ip -brief address show dev "$interface" || true
capture "$bundle/routes.txt" ip route show dev "$interface" || true
capture "$bundle/neighbors.txt" ip neigh show dev "$interface" || true
capture "$bundle/ethtool.txt" ethtool "$interface" || true
capture "$bundle/resolver.txt" cat /etc/resolv.conf || true
capture "$bundle/kernel.txt" uname -a || true
assert_safe_bundle "$bundle"
printf 'completed_at_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$bundle/metadata"
record_event operation-completed succeeded

printf 'Preflight completed for target %s, interface %s. Evidence: %s\n' \
	"$target_node" "$interface" "$bundle"
