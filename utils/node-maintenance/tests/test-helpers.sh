#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

# Fast behavioral guards that do not need a container runtime. Positive
# evidence-path and mutation behavior is exercised against the built image by
# integration.sh, where /evidence is an actual disposable volume.
set -eu

test_dir=$(cd -- "$(dirname -- "$0")" && pwd)
root_dir=$(cd -- "$test_dir/.." && pwd)
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/node-maintenance-test.XXXXXX")
trap 'rm -rf "$tmp_dir"' EXIT INT TERM

fail() { printf 'FAIL: %s\n' "$*" >&2; exit 1; }
pass() { printf 'PASS: %s\n' "$*"; }

assert_rejected() {
	name=$1
	shift
	if "$@" >"$tmp_dir/stdout" 2>"$tmp_dir/stderr"; then
		fail "$name was accepted"
	fi
	pass "$name"
}

network_repair="$root_dir/lib/network-repair.sh"
preflight="$root_dir/lib/node-recovery-preflight.sh"
kexec_validate="$root_dir/lib/kexec-recovery-validate.sh"

assert_rejected 'network repair without target' "$network_repair" \
	--interface eth0 --action flush-neighbors --evidence-dir /evidence --confirm NETWORK-REPAIR
assert_rejected 'network repair without confirmation' "$network_repair" \
	--target-node node-a --interface eth0 --action flush-neighbors --evidence-dir /evidence
assert_rejected 'network repair with unallowlisted action' "$network_repair" \
	--target-node node-a --interface eth0 --action route-replace --evidence-dir /evidence --confirm NETWORK-REPAIR
assert_rejected 'broad neighbor flush is not allowlisted' "$network_repair" \
	--target-node node-a --interface eth0 --action flush-neighbors --evidence-dir /evidence --confirm NETWORK-REPAIR
assert_rejected 'neighbor repair without an exact address and MAC' "$network_repair" \
	--target-node node-a --interface eth0 --action neighbor-replace --evidence-dir /evidence --confirm NETWORK-REPAIR
assert_rejected 'bridge FDB repair without an exact bridge MAC and VLAN' "$network_repair" \
	--target-node node-a --interface eth0 --action bridge-fdb-replace --evidence-dir /evidence --confirm NETWORK-REPAIR
assert_rejected 'preflight with unsafe interface' "$preflight" \
	--target-node node-a --interface 'eth0;reboot' --evidence-dir /evidence --confirm NODE-RECOVERY-PREFLIGHT
assert_rejected 'hostname is not a node identity fallback' "$preflight" \
	--target-node node-a --interface eth0 --evidence-dir /evidence --confirm NODE-RECOVERY-PREFLIGHT
BREAKGLASS_NODE_NAME=node-a assert_rejected 'controller node mismatch is rejected' "$preflight" \
	--target-node node-b --interface eth0 --evidence-dir /evidence --confirm NODE-RECOVERY-PREFLIGHT
BREAKGLASS_NODE_NAME=node-a assert_rejected 'host evidence path is rejected' "$preflight" \
	--target-node node-a --interface eth0 --evidence-dir /host/etc/foo --confirm NODE-RECOVERY-PREFLIGHT
BREAKGLASS_NODE_NAME=node-a assert_rejected 'kexec validation rejects caller-selected paths' "$kexec_validate" \
	--target-node node-a --recovery-profile rescue-a --kernel-path /tmp/kernel \
	--evidence-dir /evidence --confirm KEXEC-RECOVERY-VALIDATE
BREAKGLASS_NODE_NAME=node-a BREAKGLASS_OPERATION_ID=op-a BREAKGLASS_RECORDING_ID=record-a \
	BREAKGLASS_APPROVAL_ID=approval-a BREAKGLASS_APPROVED_ACTION=link-cycle \
	assert_rejected 'controller action binding mismatch is rejected' "$network_repair" \
	--target-node node-a --interface eth0 --action neighbor-replace \
	--neighbor-address 192.0.2.2 --entry-mac 02:00:00:00:00:02 \
	--evidence-dir /evidence --confirm NETWORK-REPAIR

printf 'PASS: node-maintenance fast behavioral guards completed\n'
