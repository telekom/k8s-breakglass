#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

# Only run inside the disposable Docker/Kind network namespace owned by the
# integration harness. These fixed test links are never production targets.
set -eu

node=${BREAKGLASS_NODE_NAME:?controller node is required}
fixture_id=${BREAKGLASS_FIXTURE_ID:?unique fixture identity is required}
case "$fixture_id" in ''|*[!A-Za-z0-9_.-]*) printf 'Invalid fixture identity\n' >&2; exit 2;; esac
helper=/usr/local/bin/node-maintenance
links='bg-n0 bg-n1 bg-f0 bg-f0-peer bg-f1 bg-f1-peer bg-f2 bg-f2-peer bg-br0 bg-br1'

fail() { printf 'exact-network fixture: %s\n' "$*" >&2; exit 1; }

cleanup() {
	result=$?
	trap - EXIT
	set +e
	for link in bg-n0 bg-f0 bg-f1 bg-f2 bg-br0 bg-br1; do
		ip link delete dev "$link" 2>/dev/null
	done
	for link in $links; do
		if ip link show dev "$link" >/dev/null 2>&1; then
			printf 'Fixture link survived cleanup: %s\n' "$link" >&2
			result=1
		fi
	done
	[ "$result" -ne 0 ] || printf 'PASS: exact-network fixture links removed\n'
	exit "$result"
}

# Check every name before arming cleanup; never delete a pre-existing device.
for link in $links; do
	if ip link show dev "$link" >/dev/null 2>&1; then
		fail "refusing to reuse existing link $link"
	fi
done
trap cleanup EXIT

ip link add bg-n0 type veth peer name bg-n1
ip address add 192.0.2.1/24 dev bg-n0
ip link set bg-n0 up
ip link set bg-n1 up
ip neigh replace 192.0.2.2 lladdr 02:00:00:00:00:ff nud permanent dev bg-n0
ip neigh replace 192.0.2.3 lladdr 02:00:00:00:00:03 nud permanent dev bg-n0
ip neigh replace 192.0.2.2 lladdr 02:00:00:00:00:04 nud permanent dev bg-n1
for bridge in bg-br0 bg-br1; do
	ip link add "$bridge" type bridge
	ip link set "$bridge" type bridge vlan_filtering 1
	ip link set "$bridge" up
done
for port in bg-f0 bg-f1 bg-f2; do
	ip link add "$port" type veth peer name "$port-peer"
	bridge=bg-br0
	[ "$port" != bg-f2 ] || bridge=bg-br1
	ip link set "$port" master "$bridge"
	ip link set "$port" up
	ip link set "$port-peer" up
	bridge vlan add dev "$port" vid 100
	bridge vlan add dev "$port" vid 200
done
bridge fdb add 02:00:00:00:01:00 dev bg-f1 master static vlan 100
bridge fdb add 02:00:00:00:01:00 dev bg-f1 master static vlan 200
bridge fdb add 02:00:00:00:01:01 dev bg-f1 master static vlan 100
bridge fdb add 02:00:00:00:01:00 dev bg-f2 master static vlan 100

assert_neighbor() {
	ip -4 neigh show to "$2" dev "$1" |
		awk -v address="$2" -v mac="$3" -v state="${4:-}" '
			$1 == address {
				if (state != "" && $NF != state) next
				for (i = 1; i < NF; i++) if ($i == "lladdr" && $(i+1) == mac) found++
			}
			END { exit(found == 1 ? 0 : 1) }
		' || fail "neighbor $1/$2 did not retain expected MAC $3"
}

assert_fdb() {
	bridge fdb show br "$1" brport "$2" |
		awk -v mac="$3" -v vlan="$4" -v expected="$5" '
			tolower($1) == mac {
				for (i = 1; i < NF; i++) if ($i == "vlan" && $(i+1) == vlan) found++
			}
			END { exit(found == expected ? 0 : 1) }
		' || fail "FDB $1/$2/$3/$4 did not have expected entry count $5"
}

assert_decoys() {
	assert_neighbor bg-n0 192.0.2.3 02:00:00:00:00:03 PERMANENT
	assert_neighbor bg-n1 192.0.2.2 02:00:00:00:00:04 PERMANENT
	assert_fdb bg-br0 bg-f1 02:00:00:00:01:00 200 1
	assert_fdb bg-br0 bg-f1 02:00:00:00:01:01 100 1
	assert_fdb bg-br1 bg-f2 02:00:00:00:01:00 100 1
}

context() {
	label=$1
	action=$2
	export BREAKGLASS_OPERATION_ID="$fixture_id-$label"
	export BREAKGLASS_APPROVAL_ID="approval-$fixture_id-$label"
	export BREAKGLASS_RECORDING_ID="recording-$fixture_id-$label"
	export BREAKGLASS_APPROVED_ACTION="$action"
	export BREAKGLASS_APPROVED_NETWORK_REQUEST="target_node=$node&interface=$3&action=$action&neighbor_address=$4&bridge=$5&entry_mac=$6&vlan=$7&confirmation=NETWORK-REPAIR"
}

bundle_for_operation() {
	match=
	count=0
	for candidate in /evidence/*; do
		[ -d "$candidate" ] || continue
		if grep -Fxq "operation_id=$BREAKGLASS_OPERATION_ID" "$candidate/metadata"; then
			match=$candidate
			count=$((count + 1))
		fi
	done
	[ "$count" -eq 1 ] || fail "operation did not publish exactly one owned evidence bundle"
	printf '%s\n' "$match"
}

expect_rejected() {
	expected=$1
	shift
	lock_before=$(cat /evidence/.node-maintenance-operation.lock)
	bundles_before=$(find /evidence -mindepth 1 -maxdepth 1 -type d | wc -l)
	if output=$("$@" 2>&1); then
		fail 'invalid request was accepted'
	else
		status=$?
	fi
	[ "$status" -eq 2 ] || fail "invalid request returned $status, expected 2"
	printf '%s\n' "$output" | grep -Fq -- "$expected" || fail 'invalid request did not explain its rejection'
	[ "$(cat /evidence/.node-maintenance-operation.lock)" = "$lock_before" ] ||
		fail 'rejected tuple changed the operation lock record'
	[ "$(find /evidence -mindepth 1 -maxdepth 1 -type d | wc -l)" = "$bundles_before" ] ||
		fail 'rejected tuple created an operation bundle'
	assert_decoys
}

assert_decoys
context neighbor neighbor-replace bg-n0 192.0.2.2 '' 02:00:00:00:00:02 ''
"$helper" network-repair --target-node "$node" --interface bg-n0 --action neighbor-replace \
	--neighbor-address 192.0.2.2 --entry-mac 02:00:00:00:00:02 \
	--evidence-dir /evidence --confirm NETWORK-REPAIR
assert_neighbor bg-n0 192.0.2.2 02:00:00:00:00:02
assert_decoys
bundle=$(bundle_for_operation)
grep -Fq '02:00:00:00:00:ff' "$bundle/before-neighbor-entry.txt" || fail 'old neighbor was not recorded'
grep -Fq '02:00:00:00:00:02' "$bundle/after-neighbor-entry.txt" || fail 'new neighbor was not recorded'
grep -Fxq 'action_exit_status=0' "$bundle/metadata" || fail 'neighbor action was not recorded as successful'
grep -Fxq "approval_id=$BREAKGLASS_APPROVAL_ID" "$bundle/metadata" || fail 'neighbor approval correlation is missing'
grep -Fxq "recording_id=$BREAKGLASS_RECORDING_ID" "$bundle/metadata" || fail 'neighbor recording correlation is missing'
grep -Fxq 'exit_status=0' "$bundle/action-neighbor-replace.txt" || fail 'real neighbor executor did not succeed'
cat "$bundle/metadata" "$bundle/events.jsonl"
printf 'PASS: exact neighbor replacement preserves IP and interface decoys\n'

expect_rejected 'does not exactly match the requested tuple' "$helper" network-repair \
	--target-node "$node" --interface bg-n0 --action neighbor-replace \
	--neighbor-address 192.0.2.3 --entry-mac 02:00:00:00:00:02 \
	--evidence-dir /evidence --confirm NETWORK-REPAIR
for action in flush-neighbors bridge-fdb-flush; do
	expect_rejected 'is not allowlisted' "$helper" network-repair \
		--target-node "$node" --interface bg-n0 --action "$action" \
		--evidence-dir /evidence --confirm NETWORK-REPAIR
done
assert_neighbor bg-n0 192.0.2.2 02:00:00:00:00:02
printf 'PASS: forged neighbor tuple and broad flushes fail before mutation\n'

context fdb bridge-fdb-replace bg-f0 '' bg-br0 02:00:00:00:01:00 100
"$helper" network-repair --target-node "$node" --interface bg-f0 --action bridge-fdb-replace \
	--bridge bg-br0 --entry-mac 02:00:00:00:01:00 --vlan 100 \
	--evidence-dir /evidence --confirm NETWORK-REPAIR
assert_fdb bg-br0 bg-f0 02:00:00:00:01:00 100 1
assert_fdb bg-br0 bg-f1 02:00:00:00:01:00 100 0
assert_decoys
bundle=$(bundle_for_operation)
grep -Fxq 'action_exit_status=0' "$bundle/metadata" || fail 'FDB action was not recorded as successful'
grep -Fxq "approval_id=$BREAKGLASS_APPROVAL_ID" "$bundle/metadata" || fail 'FDB approval correlation is missing'
grep -Fxq "recording_id=$BREAKGLASS_RECORDING_ID" "$bundle/metadata" || fail 'FDB recording correlation is missing'
grep -Fxq 'exit_status=0' "$bundle/action-bridge-fdb-replace.txt" || fail 'real FDB executor did not succeed'
grep -Fq '02:00:00:00:01:00' "$bundle/after-fdb-entry.txt" || fail 'new FDB entry was not recorded'
cat "$bundle/metadata" "$bundle/events.jsonl"
printf 'PASS: exact FDB replacement preserves MAC, VLAN and bridge decoys\n'

expect_rejected 'does not exactly match the requested tuple' "$helper" network-repair \
	--target-node "$node" --interface bg-f0 --action bridge-fdb-replace \
	--bridge bg-br0 --entry-mac 02:00:00:00:01:01 --vlan 100 \
	--evidence-dir /evidence --confirm NETWORK-REPAIR
context wrong-vlan bridge-fdb-replace bg-f0 '' bg-br0 02:00:00:00:01:00 300
if "$helper" network-repair --target-node "$node" --interface bg-f0 --action bridge-fdb-replace \
	--bridge bg-br0 --entry-mac 02:00:00:00:01:00 --vlan 300 \
	--evidence-dir /evidence --confirm NETWORK-REPAIR; then
	fail 'unconfigured VLAN was accepted'
else
	[ "$?" -eq 2 ] || fail 'unconfigured VLAN returned an unexpected status'
fi
bundle=$(bundle_for_operation)
[ ! -e "$bundle/action-bridge-fdb-replace.txt" ] || fail 'failed VLAN preflight reached the mutating action'
grep -Fq '"result":"preflight-failed"' "$bundle/events.jsonl" || fail 'VLAN failure was not recorded'
assert_fdb bg-br0 bg-f0 02:00:00:00:01:00 100 1
assert_decoys
printf 'PASS: forged FDB tuple and unconfigured VLAN preserve all entries\n'
