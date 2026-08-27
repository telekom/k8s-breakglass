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

assert_rejected 'network repair without target' "$network_repair" \
	--interface eth0 --action flush-neighbors --evidence-dir /evidence --confirm NETWORK-REPAIR
assert_rejected 'network repair without confirmation' "$network_repair" \
	--target-node node-a --interface eth0 --action flush-neighbors --evidence-dir /evidence
assert_rejected 'network repair with unallowlisted action' "$network_repair" \
	--target-node node-a --interface eth0 --action route-replace --evidence-dir /evidence --confirm NETWORK-REPAIR
assert_rejected 'preflight with unsafe interface' "$preflight" \
	--target-node node-a --interface 'eth0;reboot' --evidence-dir /evidence --confirm NODE-RECOVERY-PREFLIGHT
assert_rejected 'hostname is not a node identity fallback' "$preflight" \
	--target-node node-a --interface eth0 --evidence-dir /evidence --confirm NODE-RECOVERY-PREFLIGHT
BREAKGLASS_NODE_NAME=node-a assert_rejected 'controller node mismatch is rejected' "$preflight" \
	--target-node node-b --interface eth0 --evidence-dir /evidence --confirm NODE-RECOVERY-PREFLIGHT
BREAKGLASS_NODE_NAME=node-a assert_rejected 'host evidence path is rejected' "$preflight" \
	--target-node node-a --interface eth0 --evidence-dir /host/etc/foo --confirm NODE-RECOVERY-PREFLIGHT

printf 'PASS: node-maintenance static behavior guards completed\n'
