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
	expected=$2
	shift 2
	if "$@" >"$tmp_dir/stdout" 2>"$tmp_dir/stderr"; then
		fail "$name was accepted"
	fi
	grep -F -- "$expected" "$tmp_dir/stderr" >/dev/null || fail "$name did not report '$expected'"
	pass "$name"
}

assert_rejected_with_message() {
	assert_rejected "$@"
}

network_repair="$root_dir/lib/network-repair.sh"
preflight="$root_dir/lib/node-recovery-preflight.sh"
kexec_validate="$root_dir/lib/kexec-recovery-validate.sh"
service_restart="$root_dir/lib/service-restart.sh"
module_load="$root_dir/lib/module-load.sh"
sriov_reprovision="$root_dir/lib/sriov-reprovision.sh"

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

# Controller deadlines derive from time.Duration-bounded session expiry and
# can exceed the 10-digit Unix timestamp range after 2286-11-20.
BREAKGLASS_ACTION_DEADLINE_UNIX=10000000000 sh -c '. "$1"; validate_action_deadline' sh "$root_dir/lib/common.sh" \
	|| fail "11-digit future action deadline was rejected"
pass "11-digit future action deadline is accepted"
# shellcheck disable=SC2016
assert_rejected "12-digit action deadline" "exceeds the bounded timestamp format" \
	env BREAKGLASS_ACTION_DEADLINE_UNIX=100000000000 sh -c '. "$1"; validate_action_deadline' sh "$root_dir/lib/common.sh"
# shellcheck disable=SC2016
assert_rejected "expired action deadline" "approved action deadline expired" \
	env BREAKGLASS_ACTION_DEADLINE_UNIX=1 sh -c '. "$1"; validate_action_deadline' sh "$root_dir/lib/common.sh"
for invalid_neighbor in example.com 192.0.2.256 192.0.2.01 192.0.2 2001:db8:::1 2001:db8::1::2 2001:db8:1; do
	assert_neighbor_literal_rejected_before_network "$invalid_neighbor"
done

huge_vlan=$(awk 'BEGIN { for (i = 0; i < 1000; i++) printf "9" }')
BREAKGLASS_NODE_NAME=node-a
export BREAKGLASS_NODE_NAME
assert_rejected 'huge decimal VLAN is rejected before numeric conversion' 'VLAN must be an integer from 1 through 4094' "$network_repair" \
	--target-node node-a --interface eth0 --action bridge-fdb-replace --bridge br0 --entry-mac 02:00:00:00:00:02 --vlan "$huge_vlan" \
	--evidence-dir /evidence --confirm NETWORK-REPAIR
# Keep the exact controller node for every guard that must pass target
# validation before it reaches its own rejection. The dedicated no-node test
# below unsets it deliberately.
assert_rejected_with_message 'duplicate network option is rejected even with an empty second value' '--interface may be supplied only once' "$network_repair" \
	--target-node node-a --interface eth0 --interface '' --action link-cycle --evidence-dir /evidence --confirm NETWORK-REPAIR
assert_rejected 'irrelevant empty entry flag is rejected' "action 'link-cycle' does not accept entry-target options" "$network_repair" \
	--target-node node-a --interface eth0 --action link-cycle --entry-mac '' --evidence-dir /evidence --confirm NETWORK-REPAIR

assert_rejected 'network repair without target' 'target node is required' "$network_repair" \
	--interface eth0 --action flush-neighbors --evidence-dir /evidence --confirm NETWORK-REPAIR
assert_rejected 'network repair without confirmation' "confirmation must be exactly 'NETWORK-REPAIR'" "$network_repair" \
	--target-node node-a --interface eth0 --action flush-neighbors --evidence-dir /evidence
assert_rejected 'network repair with unallowlisted action' "action 'route-replace' is not allowlisted" "$network_repair" \
	--target-node node-a --interface eth0 --action route-replace --evidence-dir /evidence --confirm NETWORK-REPAIR
assert_rejected 'broad neighbor flush is not allowlisted' "action 'flush-neighbors' is not allowlisted" "$network_repair" \
	--target-node node-a --interface eth0 --action flush-neighbors --evidence-dir /evidence --confirm NETWORK-REPAIR
assert_rejected 'neighbor repair without an exact address and MAC' 'neighbor-replace requires --neighbor-address and --entry-mac' "$network_repair" \
	--target-node node-a --interface eth0 --action neighbor-replace --evidence-dir /evidence --confirm NETWORK-REPAIR
assert_rejected 'bridge FDB repair without an exact bridge MAC and VLAN' 'bridge is required' "$network_repair" \
	--target-node node-a --interface eth0 --action bridge-fdb-replace --evidence-dir /evidence --confirm NETWORK-REPAIR
BREAKGLASS_NODE_NAME=node-a BREAKGLASS_OPERATION_ID=op-a BREAKGLASS_RECORDING_ID=record-a \
	BREAKGLASS_APPROVAL_ID=approval-a BREAKGLASS_APPROVED_ACTION=bridge-fdb-replace \
	assert_rejected_with_message 'bridge FDB repair reports its missing bridge argument' 'bridge is required' "$network_repair" \
	--target-node node-a --interface eth0 --action bridge-fdb-replace --entry-mac 02:00:00:00:00:02 --vlan 100 \
	--evidence-dir /evidence --confirm NETWORK-REPAIR
assert_rejected 'preflight with unsafe interface' 'interface contains unsupported characters' "$preflight" \
	--target-node node-a --interface 'eth0;reboot' --evidence-dir /evidence --confirm NODE-RECOVERY-PREFLIGHT

unset BREAKGLASS_NODE_NAME
assert_rejected 'hostname is not a node identity fallback' 'BREAKGLASS_NODE_NAME is required' "$preflight" \
	--target-node node-a --interface eth0 --evidence-dir /evidence --confirm NODE-RECOVERY-PREFLIGHT
BREAKGLASS_NODE_NAME=node-a
export BREAKGLASS_NODE_NAME
assert_rejected 'controller node mismatch is rejected' "target node 'node-b' does not match controller-provided node 'node-a'" "$preflight" \
	--target-node node-b --interface eth0 --evidence-dir /evidence --confirm NODE-RECOVERY-PREFLIGHT
BREAKGLASS_OPERATION_ID=op-a BREAKGLASS_RECORDING_ID=record-a \
	assert_rejected 'host evidence path is rejected' 'evidence directory must be /evidence or one safe child' "$preflight" \
	--target-node node-a --interface eth0 --evidence-dir /host/etc/foo --confirm NODE-RECOVERY-PREFLIGHT
assert_rejected 'kexec validation rejects caller-selected paths' "unsupported option '--kernel-path'" "$kexec_validate" \
	--target-node node-a --recovery-profile rescue-a --kernel-path /tmp/kernel \
	--evidence-dir /evidence --confirm KEXEC-RECOVERY-VALIDATE
assert_rejected_with_message 'duplicate kexec option is rejected before provider validation' '--target-node may be supplied only once' "$kexec_validate" \
	--target-node node-a --target-node node-a --recovery-profile rescue-a \
	--evidence-dir /evidence --confirm KEXEC-RECOVERY-VALIDATE
# The image installs the same script as kexec-recovery; the name selects execution.
mkdir -p "$tmp_dir/kexec-bin"
ln -s "$root_dir/lib/common.sh" "$tmp_dir/kexec-bin/common.sh"
ln -s "$kexec_validate" "$tmp_dir/kexec-bin/kexec-recovery"
kexec_execute="$tmp_dir/kexec-bin/kexec-recovery"
assert_rejected 'kexec execution rejects the validation-only confirmation' "confirmation must be exactly 'KEXEC-RECOVERY'" "$kexec_execute" \
	--target-node node-a --recovery-profile rescue-a \
	--evidence-dir /evidence --confirm KEXEC-RECOVERY-VALIDATE
BREAKGLASS_OPERATION_ID=op-a BREAKGLASS_RECORDING_ID=record-a \
	BREAKGLASS_APPROVAL_ID=approval-a BREAKGLASS_APPROVED_ACTION=kexec-recovery-validate \
	assert_rejected 'kexec execution requires an execution approval, not a validation approval' "controller-approved action 'kexec-recovery-validate' does not match requested action 'kexec-recovery'" "$kexec_execute" \
	--target-node node-a --recovery-profile rescue-a \
	--evidence-dir /evidence --confirm KEXEC-RECOVERY
BREAKGLASS_OPERATION_ID=op-a BREAKGLASS_RECORDING_ID=record-a \
	BREAKGLASS_APPROVAL_ID=approval-a BREAKGLASS_APPROVED_ACTION=kexec-recovery \
	assert_rejected 'kexec execution requires the controller-bound boot ID' 'BREAKGLASS_KEXEC_BOOT_ID is required' "$kexec_execute" \
	--target-node node-a --recovery-profile rescue-a \
	--evidence-dir /evidence --confirm KEXEC-RECOVERY
BREAKGLASS_OPERATION_ID=op-a BREAKGLASS_RECORDING_ID=record-a \
	BREAKGLASS_APPROVAL_ID=approval-a BREAKGLASS_APPROVED_ACTION=kexec-recovery \
	assert_rejected 'kexec validation never accepts an execution approval' "controller-approved action 'kexec-recovery' does not match requested action 'kexec-recovery-validate'" "$kexec_validate" \
	--target-node node-a --recovery-profile rescue-a \
	--evidence-dir /evidence --confirm KEXEC-RECOVERY-VALIDATE
BREAKGLASS_OPERATION_ID=op-a BREAKGLASS_RECORDING_ID=record-a \
	BREAKGLASS_APPROVAL_ID=approval-a BREAKGLASS_APPROVED_ACTION=link-cycle \
	assert_rejected 'controller action binding mismatch is rejected' "controller-approved action 'link-cycle' does not match requested action 'neighbor-replace'" "$network_repair" \
	--target-node node-a --interface eth0 --action neighbor-replace \
	--neighbor-address 192.0.2.2 --entry-mac 02:00:00:00:00:02 \
	--evidence-dir /evidence --confirm NETWORK-REPAIR

long_node=$(awk 'BEGIN { for (i = 0; i < 257; i++) printf "n" }')
BREAKGLASS_NODE_NAME="$long_node" assert_rejected 'oversized controller value is rejected' 'BREAKGLASS_NODE_NAME exceeds the fixed 256-byte limit' "$preflight" \
	--target-node node-a --interface eth0 --evidence-dir /evidence \
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

BREAKGLASS_NODE_NAME=node-a
export BREAKGLASS_NODE_NAME
assert_rejected 'broad neighbor table flush is not allowlisted' "action 'neighbor-flush' is not allowlisted" "$network_repair" \
	--target-node node-a --interface eth0 --action neighbor-flush --evidence-dir /evidence --confirm NETWORK-REPAIR
assert_rejected 'broad bridge FDB flush is not allowlisted' "action 'bridge-fdb-flush' is not allowlisted" "$network_repair" \
	--target-node node-a --interface eth0 --action bridge-fdb-flush --bridge br0 --evidence-dir /evidence --confirm NETWORK-REPAIR
assert_rejected 'VRF is rejected for bridge FDB repair' 'bridge-fdb-replace does not accept a VRF' "$network_repair" \
	--target-node node-a --interface eth0 --action bridge-fdb-replace --bridge br0 --entry-mac 02:00:00:00:00:02 --vlan 100 \
	--vrf vrf-red --evidence-dir /evidence --confirm NETWORK-REPAIR
assert_rejected 'VRF is rejected for link actions' "action 'link-cycle' does not accept entry-target options" "$network_repair" \
	--target-node node-a --interface eth0 --action link-cycle --vrf vrf-red --evidence-dir /evidence --confirm NETWORK-REPAIR
assert_rejected 'VRF must differ from the interface' 'VRF and interface must be different' "$network_repair" \
	--target-node node-a --interface eth0 --action neighbor-replace --neighbor-address 192.0.2.2 --entry-mac 02:00:00:00:00:02 \
	--vrf eth0 --evidence-dir /evidence --confirm NETWORK-REPAIR
assert_rejected 'preview is limited to exact replace actions' '--dry-run is supported only for exact replace actions' "$network_repair" \
	--target-node node-a --interface eth0 --action link-cycle --dry-run --evidence-dir /evidence --confirm NETWORK-REPAIR

assert_network_tuple() {
	name=$1
	want=$2
	approved=$3
	shift 3
	if BREAKGLASS_APPROVED_NETWORK_REQUEST="$approved" sh -c '. "$1"; shift; validate_approved_network_request "$@"' sh \
		"$root_dir/lib/common.sh" "$@" >"$tmp_dir/stdout" 2>"$tmp_dir/stderr"; then
		[ "$want" = accepted ] || fail "$name was accepted"
	else
		[ "$want" = rejected ] || fail "$name was rejected: $(cat "$tmp_dir/stderr")"
	fi
	pass "$name"
}
neighbor_tuple='target_node=node-a&interface=eth0&action=neighbor-replace&neighbor_address=192.0.2.2&bridge=&entry_mac=02:00:00:00:00:02&vlan='
assert_network_tuple 'legacy tuple without VRF or preview is unchanged' accepted "$neighbor_tuple&confirmation=NETWORK-REPAIR" \
	node-a eth0 neighbor-replace 192.0.2.2 "" 02:00:00:00:00:02 "" NETWORK-REPAIR
assert_network_tuple 'VRF-bound tuple is accepted for the same VRF' accepted "$neighbor_tuple&vrf=vrf-red&confirmation=NETWORK-REPAIR" \
	node-a eth0 neighbor-replace 192.0.2.2 "" 02:00:00:00:00:02 "" NETWORK-REPAIR vrf-red false
assert_network_tuple 'VRF-bound tuple is rejected for another VRF' rejected "$neighbor_tuple&vrf=vrf-red&confirmation=NETWORK-REPAIR" \
	node-a eth0 neighbor-replace 192.0.2.2 "" 02:00:00:00:00:02 "" NETWORK-REPAIR vrf-blue false
assert_network_tuple 'VRF-less approval cannot run inside a VRF' rejected "$neighbor_tuple&confirmation=NETWORK-REPAIR" \
	node-a eth0 neighbor-replace 192.0.2.2 "" 02:00:00:00:00:02 "" NETWORK-REPAIR vrf-red false
assert_network_tuple 'preview approval cannot execute a mutation' rejected "$neighbor_tuple&dry_run=true&confirmation=NETWORK-REPAIR" \
	node-a eth0 neighbor-replace 192.0.2.2 "" 02:00:00:00:00:02 "" NETWORK-REPAIR "" false
assert_network_tuple 'mutation approval cannot be replayed as a preview' rejected "$neighbor_tuple&confirmation=NETWORK-REPAIR" \
	node-a eth0 neighbor-replace 192.0.2.2 "" 02:00:00:00:00:02 "" NETWORK-REPAIR "" true
assert_network_tuple 'preview tuple is accepted for a preview' accepted "$neighbor_tuple&vrf=vrf-red&dry_run=true&confirmation=NETWORK-REPAIR" \
	node-a eth0 neighbor-replace 192.0.2.2 "" 02:00:00:00:00:02 "" NETWORK-REPAIR vrf-red true

# service-restart: fixed unit allowlist, its own confirmation, action and tuple binding.
service_env() {
	env BREAKGLASS_NODE_NAME=node-a BREAKGLASS_OPERATION_ID=op-a BREAKGLASS_RECORDING_ID=record-a \
		BREAKGLASS_APPROVAL_ID=approval-a BREAKGLASS_APPROVED_ACTION="$1" \
		BREAKGLASS_APPROVED_SERVICE_REQUEST="$2" "$service_restart" \
		--target-node node-a --unit "$3" --evidence-dir /evidence --confirm "$4"
}
service_tuple='target_node=node-a&unit=containerd.service&confirmation=SERVICE-RESTART'
assert_rejected 'service-restart rejects a unit outside the allowlist' "unit 'sshd.service' is not allowlisted" \
	service_env service-restart "$service_tuple" sshd.service SERVICE-RESTART
assert_rejected 'service-restart rejects a unit path' "unit '../containerd.service' is not allowlisted" \
	service_env service-restart "$service_tuple" ../containerd.service SERVICE-RESTART
assert_rejected 'service-restart requires its own confirmation' "confirmation must be exactly 'SERVICE-RESTART'" \
	service_env service-restart "$service_tuple" containerd.service NETWORK-REPAIR
assert_rejected 'service-restart requires a service-restart approval' "controller-approved action 'link-cycle' does not match requested action 'service-restart'" \
	service_env link-cycle "$service_tuple" containerd.service SERVICE-RESTART
assert_rejected 'service-restart approval is bound to the exact unit' 'controller-approved service request does not exactly match the requested tuple' \
	service_env service-restart "$service_tuple" kubelet.service SERVICE-RESTART
assert_rejected 'service-restart rejects duplicate options' '--unit may be supplied only once' \
	"$service_restart" --target-node node-a --unit kubelet.service --unit containerd.service \
	--evidence-dir /evidence --confirm SERVICE-RESTART

# module-load: exact module name, its own confirmation, action and tuple binding.
module_env() {
	env BREAKGLASS_NODE_NAME=node-a BREAKGLASS_OPERATION_ID=op-a BREAKGLASS_RECORDING_ID=record-a \
		BREAKGLASS_APPROVAL_ID=approval-a BREAKGLASS_APPROVED_ACTION="$1" \
		BREAKGLASS_APPROVED_MODULE_REQUEST="$2" "$module_load" \
		--target-node node-a --module "$3" --evidence-dir /evidence --confirm "$4"
}
module_tuple='target_node=node-a&module=ip6_gre&confirmation=MODULE-LOAD'
assert_rejected 'module-load rejects a path' 'module must be an exact kernel module name' module_env module-load "$module_tuple" ../ip6_gre MODULE-LOAD
assert_rejected 'module-load rejects module parameters' 'module must be an exact kernel module name' module_env module-load "$module_tuple" 'ip6_gre debug=1' MODULE-LOAD
long_module=$(awk 'BEGIN { for (i = 0; i < 57; i++) printf "m" }')
assert_rejected 'module-load rejects a name over 56 bytes' 'module name exceeds 56 bytes' module_env module-load "$module_tuple" "$long_module" MODULE-LOAD
assert_rejected 'module-load requires its own confirmation' "confirmation must be exactly 'MODULE-LOAD'" module_env module-load "$module_tuple" ip6_gre SERVICE-RESTART
assert_rejected 'module-load requires a module-load approval' "controller-approved action 'service-restart' does not match requested action 'module-load'" \
	module_env service-restart "$module_tuple" ip6_gre MODULE-LOAD
assert_rejected 'module-load approval is bound to the exact module' 'controller-approved module request does not exactly match the requested tuple' \
	module_env module-load "$module_tuple" gre MODULE-LOAD

# sriov-reprovision: exact PF and approved VF count, its own confirmation, action and tuple binding.
sriov_env() {
	env BREAKGLASS_NODE_NAME=node-a BREAKGLASS_OPERATION_ID=op-a BREAKGLASS_RECORDING_ID=record-a \
		BREAKGLASS_APPROVAL_ID=approval-a BREAKGLASS_APPROVED_ACTION="$1" \
		BREAKGLASS_APPROVED_SRIOV_REQUEST="$2" "$sriov_reprovision" \
		--target-node node-a --interface "$3" --virtual-functions "$4" --evidence-dir /evidence --confirm "$5"
}
sriov_tuple='target_node=node-a&interface=ens1f0&virtual_functions=8&confirmation=SRIOV-REPROVISION'
assert_rejected 'sriov-reprovision rejects an interface with unsupported characters' 'interface contains unsupported characters' \
	sriov_env sriov-reprovision "$sriov_tuple" 'ens1f0 x' 8 SRIOV-REPROVISION
assert_rejected 'sriov-reprovision rejects a dot PF' "interface '..' is not a PF name" sriov_env sriov-reprovision "$sriov_tuple" .. 8 SRIOV-REPROVISION
assert_rejected 'sriov-reprovision rejects an option-like PF' "interface '-h' is not a PF name" sriov_env sriov-reprovision "$sriov_tuple" -h 8 SRIOV-REPROVISION
assert_rejected 'sriov-reprovision rejects a zero VF count' 'must be a positive integer' sriov_env sriov-reprovision "$sriov_tuple" ens1f0 0 SRIOV-REPROVISION
assert_rejected 'sriov-reprovision rejects a leading zero' 'must be a positive integer' sriov_env sriov-reprovision "$sriov_tuple" ens1f0 08 SRIOV-REPROVISION
assert_rejected 'sriov-reprovision rejects more than 256 VFs' 'must not exceed 256' sriov_env sriov-reprovision "$sriov_tuple" ens1f0 257 SRIOV-REPROVISION
assert_rejected 'sriov-reprovision requires its own confirmation' "confirmation must be exactly 'SRIOV-REPROVISION'" \
	sriov_env sriov-reprovision "$sriov_tuple" ens1f0 8 SERVICE-RESTART
assert_rejected 'sriov-reprovision requires a sriov-reprovision approval' "controller-approved action 'service-restart' does not match requested action 'sriov-reprovision'" \
	sriov_env service-restart "$sriov_tuple" ens1f0 8 SRIOV-REPROVISION
assert_rejected 'sriov-reprovision approval is bound to the exact PF' 'controller-approved SR-IOV request does not exactly match the requested tuple' \
	sriov_env sriov-reprovision "$sriov_tuple" ens1f1 8 SRIOV-REPROVISION
assert_rejected 'sriov-reprovision approval is bound to the exact VF count' 'controller-approved SR-IOV request does not exactly match the requested tuple' \
	sriov_env sriov-reprovision "$sriov_tuple" ens1f0 4 SRIOV-REPROVISION
assert_rejected 'sriov-reprovision rejects duplicate options' '--interface may be supplied only once' \
	"$sriov_reprovision" --target-node node-a --interface ens1f0 --interface ens1f1 --virtual-functions 8 \
	--evidence-dir /evidence --confirm SRIOV-REPROVISION

printf 'PASS: node-maintenance fast behavioral guards completed\n'
