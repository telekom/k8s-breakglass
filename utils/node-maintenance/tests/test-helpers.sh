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

assert_rejected_with_message() {
	name=$1
	expected=$2
	shift 2
	if "$@" >"$tmp_dir/stdout" 2>"$tmp_dir/stderr"; then
		fail "$name was accepted"
	fi
	grep -F -- "$expected" "$tmp_dir/stderr" >/dev/null || fail "$name did not report '$expected'"
	pass "$name"
}

network_repair="$root_dir/lib/network-repair.sh"
preflight="$root_dir/lib/node-recovery-preflight.sh"
kexec_validate="$root_dir/lib/kexec-recovery-validate.sh"

assert_neighbor_literal_accepted() {
	address=$1
	family=$2
	actual=$(sh -c '. "$1"; validate_neighbor_address "$2"; printf "%s" "$NEIGHBOR_FAMILY"' sh \
		"$root_dir/lib/common.sh" "$address") || fail "literal neighbor address $address was rejected"
	[ "$actual" = "$family" ] || fail "literal neighbor address $address selected $actual, want $family"
	pass "literal neighbor address $address is accepted as $family"
}

assert_neighbor_literal_rejected_before_network() {
	address=$1
	if BREAKGLASS_NODE_NAME=node-a BREAKGLASS_OPERATION_ID=op-a BREAKGLASS_RECORDING_ID=record-a \
		BREAKGLASS_APPROVAL_ID=approval-a BREAKGLASS_APPROVED_ACTION=neighbor-replace \
		sh -x "$network_repair" --target-node node-a --interface lo --action neighbor-replace \
		--neighbor-address "$address" --entry-mac 02:00:00:00:00:02 \
		--evidence-dir /evidence --confirm NETWORK-REPAIR >"$tmp_dir/stdout" 2>"$tmp_dir/stderr"; then
		fail "non-literal neighbor address $address was accepted"
	fi
	grep -F 'neighbor address must be an IPv4 or IPv6 literal' "$tmp_dir/stderr" >/dev/null \
		|| fail "non-literal neighbor address $address did not fail literal validation"
	if grep -E '[[:space:]]ip([[:space:]]|$)' "$tmp_dir/stderr" >/dev/null; then
		fail "non-literal neighbor address $address reached an ip command"
	fi
	pass "non-literal neighbor address $address is rejected before network access"
}

assert_neighbor_literal_accepted 192.0.2.2 -4
assert_neighbor_literal_accepted 2001:db8::2 -6
assert_neighbor_literal_accepted ::1 -6
for invalid_neighbor in example.com 192.0.2.256 192.0.2.01 192.0.2 2001:db8:::1 2001:db8::1::2 2001:db8:1; do
	assert_neighbor_literal_rejected_before_network "$invalid_neighbor"
done

huge_vlan=$(awk 'BEGIN { for (i = 0; i < 1000; i++) printf "9" }')
BREAKGLASS_NODE_NAME=node-a
export BREAKGLASS_NODE_NAME
assert_rejected 'huge decimal VLAN is rejected before numeric conversion' "$network_repair" \
	--target-node node-a --interface eth0 --action bridge-fdb-replace --bridge br0 --entry-mac 02:00:00:00:00:02 --vlan "$huge_vlan" \
	--evidence-dir /evidence --confirm NETWORK-REPAIR
unset BREAKGLASS_NODE_NAME
assert_rejected_with_message 'duplicate network option is rejected even with an empty second value' '--interface may be supplied only once' "$network_repair" \
	--target-node node-a --interface eth0 --interface '' --action link-cycle --evidence-dir /evidence --confirm NETWORK-REPAIR
assert_rejected 'irrelevant empty entry flag is rejected' "$network_repair" \
	--target-node node-a --interface eth0 --action link-cycle --entry-mac '' --evidence-dir /evidence --confirm NETWORK-REPAIR

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
BREAKGLASS_NODE_NAME=node-a BREAKGLASS_OPERATION_ID=op-a BREAKGLASS_RECORDING_ID=record-a \
	BREAKGLASS_APPROVAL_ID=approval-a BREAKGLASS_APPROVED_ACTION=bridge-fdb-replace \
	assert_rejected_with_message 'bridge FDB repair reports its missing bridge argument' 'bridge is required' "$network_repair" \
	--target-node node-a --interface eth0 --action bridge-fdb-replace --entry-mac 02:00:00:00:00:02 --vlan 100 \
	--evidence-dir /evidence --confirm NETWORK-REPAIR
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
assert_rejected_with_message 'duplicate kexec option is rejected before provider validation' '--target-node may be supplied only once' "$kexec_validate" \
	--target-node node-a --target-node node-a --recovery-profile rescue-a \
	--evidence-dir /evidence --confirm KEXEC-RECOVERY-VALIDATE
BREAKGLASS_NODE_NAME=node-a BREAKGLASS_OPERATION_ID=op-a BREAKGLASS_RECORDING_ID=record-a \
	BREAKGLASS_APPROVAL_ID=approval-a BREAKGLASS_APPROVED_ACTION=link-cycle \
	assert_rejected 'controller action binding mismatch is rejected' "$network_repair" \
	--target-node node-a --interface eth0 --action neighbor-replace \
	--neighbor-address 192.0.2.2 --entry-mac 02:00:00:00:00:02 \
	--evidence-dir /evidence --confirm NETWORK-REPAIR

long_node=$(awk 'BEGIN { for (i = 0; i < 257; i++) printf "n" }')
BREAKGLASS_NODE_NAME="$long_node" assert_rejected 'oversized controller value is rejected' "$preflight" \
	--target-node "$long_node" --interface eth0 --evidence-dir /evidence \
	--confirm NODE-RECOVERY-PREFLIGHT

# 63 + 1 + 63 + 1 + 63 + 1 + 61 = the RFC 1123/Kubernetes maximum of 253.
max_node=$(awk 'BEGIN { for (label = 1; label <= 4; label++) { limit = (label == 4 ? 61 : 63); for (i = 0; i < limit; i++) printf "n"; if (label < 4) printf "." } }')
[ "${#max_node}" -eq 253 ] || fail 'maximum Kubernetes node fixture is not 253 bytes'
if ! BREAKGLASS_NODE_NAME="$max_node" sh -c '. "$1"; validate_target "$2"' sh \
	"$root_dir/lib/common.sh" "$max_node" >"$tmp_dir/stdout" 2>"$tmp_dir/stderr"; then
	fail 'maximum Kubernetes node name was rejected'
fi
pass 'maximum Kubernetes node name is accepted'
too_long_node="${max_node}n"
[ "${#too_long_node}" -eq 254 ] || fail 'above-limit Kubernetes node fixture is not 254 bytes'
BREAKGLASS_NODE_NAME="$too_long_node" assert_rejected_with_message \
	'valid-looking 254-byte Kubernetes node name is rejected by the public helper' \
	'target node exceeds the Kubernetes 253-byte limit' "$preflight" \
	--target-node "$too_long_node" --interface eth0 --evidence-dir /evidence \
	--confirm NODE-RECOVERY-PREFLIGHT

invalid_node_label=$(awk 'BEGIN { for (i = 0; i < 64; i++) printf "n" }')
if BREAKGLASS_NODE_NAME="$invalid_node_label" sh -c '. "$1"; validate_target "$2"' sh \
	"$root_dir/lib/common.sh" "$invalid_node_label" >"$tmp_dir/stdout" 2>"$tmp_dir/stderr"; then
	fail 'Kubernetes node name with a 64-byte DNS label was accepted'
fi
pass 'Kubernetes node name with a 64-byte DNS label is rejected'

max_interface=$(awk 'BEGIN { for (i = 0; i < 15; i++) printf "i" }')
if ! sh -c '. "$1"; validate_interface "$2"' sh "$root_dir/lib/common.sh" "$max_interface" >"$tmp_dir/stdout" 2>"$tmp_dir/stderr"; then
	fail 'maximum Linux interface name was rejected'
fi
pass 'maximum Linux interface name is accepted'
too_long_interface=$(awk 'BEGIN { for (i = 0; i < 16; i++) printf "i" }')
if sh -c '. "$1"; validate_interface "$2"' sh "$root_dir/lib/common.sh" "$too_long_interface" >"$tmp_dir/stdout" 2>"$tmp_dir/stderr"; then
	fail 'Linux interface name above 15 bytes was accepted'
fi
pass 'Linux interface name above 15 bytes is rejected'

# This probes the serialization guard itself, not public request validation:
# 88 fixed bytes + 253-byte node + 256-byte serializer field + 413-byte field
# + 14-byte confirmation is exactly the 1024-byte fixed controller-data cap.
serializer_interface=$(awk 'BEGIN { for (i = 0; i < 256; i++) printf "i" }')
serializer_action=$(awk 'BEGIN { for (i = 0; i < 413; i++) printf "a" }')
max_approved_tuple="target_node=$max_node&interface=$serializer_interface&action=$serializer_action&neighbor_address=&bridge=&entry_mac=&vlan=&confirmation=NETWORK-REPAIR"
if ! BREAKGLASS_APPROVED_NETWORK_REQUEST="$max_approved_tuple" sh -c '
	. "$1"
	validate_approved_network_request "$2" "$3" "$4" "" "" "" "" NETWORK-REPAIR
' sh "$root_dir/lib/common.sh" "$max_node" "$serializer_interface" "$serializer_action" >"$tmp_dir/stdout" 2>"$tmp_dir/stderr"; then
	fail '1024-byte controller-approved tuple serialization was rejected'
fi
pass '1024-byte controller-approved tuple serialization is accepted'

oversized_serializer_action=$(awk 'BEGIN { for (i = 0; i < 414; i++) printf "a" }')
oversized_approved_tuple="target_node=$max_node&interface=$serializer_interface&action=$oversized_serializer_action&neighbor_address=&bridge=&entry_mac=&vlan=&confirmation=NETWORK-REPAIR"
if BREAKGLASS_APPROVED_NETWORK_REQUEST="$oversized_approved_tuple" sh -c '
	. "$1"
	validate_approved_network_request "$2" "$3" "$4" "" "" "" "" NETWORK-REPAIR
' sh "$root_dir/lib/common.sh" "$max_node" "$serializer_interface" "$oversized_serializer_action" >"$tmp_dir/stdout" 2>"$tmp_dir/stderr"; then
	fail 'above-bound controller-approved network tuple was accepted'
fi
pass 'above-bound controller-approved network tuple is rejected'

invalid_approved_tuple="${max_approved_tuple%NETWORK-REPAIR}NETWORK-REPAIX"
if BREAKGLASS_APPROVED_NETWORK_REQUEST="$invalid_approved_tuple" sh -c '
	. "$1"
	validate_approved_network_request "$2" "$3" "$4" "" "" "" "" NETWORK-REPAIR
' sh "$root_dir/lib/common.sh" "$max_node" "$serializer_interface" "$serializer_action" >"$tmp_dir/stdout" 2>"$tmp_dir/stderr"; then
	fail 'forged controller-approved network tuple was accepted'
fi
pass 'forged controller-approved network tuple is rejected'

printf 'PASS: node-maintenance fast behavioral guards completed\n'
