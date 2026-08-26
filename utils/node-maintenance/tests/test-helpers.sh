#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

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
	--interface eth0 --action flush-neighbors --evidence-dir "$tmp_dir/evidence" --confirm NETWORK-REPAIR
assert_rejected 'network repair without confirmation' "$network_repair" \
	--target-node node-a --interface eth0 --action flush-neighbors --evidence-dir "$tmp_dir/evidence"
assert_rejected 'network repair with unallowlisted action' "$network_repair" \
	--target-node node-a --interface eth0 --action route-replace --evidence-dir "$tmp_dir/evidence" --confirm NETWORK-REPAIR
assert_rejected 'preflight with unsafe interface' "$preflight" \
	--target-node node-a --interface 'eth0;reboot' --evidence-dir "$tmp_dir/evidence" --confirm NODE-RECOVERY-PREFLIGHT

fake_bin="$tmp_dir/bin"
mkdir -p "$fake_bin"
cat >"$fake_bin/ip" <<'EOF'
#!/bin/sh
case "$*" in
  *"link show dev eth0"*) printf '%s\n' '2: eth0: <UP> mtu 1500' ;;
  *"address show dev eth0"*) printf '%s\n' 'eth0 UP 192.0.2.10/24' ;;
  *"route show dev eth0"*) printf '%s\n' 'default via 192.0.2.1 dev eth0' ;;
  *"neigh show dev eth0"*) printf '%s\n' '192.0.2.1 lladdr 00:11:22:33:44:55 REACHABLE' ;;
  *"link set dev eth0"*) exit 0 ;;
  *"neigh flush dev eth0"*) printf '%s\n' '1 flushed' ;;
  *) exit 1 ;;
esac
EOF
cat >"$fake_bin/ethtool" <<'EOF'
#!/bin/sh
[ "${ETHTOOL_FAIL:-0}" = 1 ] && exit 7
printf '%s\n' 'Settings for eth0: speed: 1000Mb/s'
EOF
cat >"$fake_bin/cat" <<'EOF'
#!/bin/sh
printf '%s\n' 'nameserver 192.0.2.53'
EOF
cat >"$fake_bin/uname" <<'EOF'
#!/bin/sh
printf '%s\n' 'Linux test-node 6.1.0'
EOF
cat >"$fake_bin/hostname" <<'EOF'
#!/bin/sh
printf '%s\n' 'node-a'
EOF
chmod 0555 "$fake_bin"/*

evidence_dir="$tmp_dir/evidence"
PATH="$fake_bin:$PATH" "$preflight" --target-node node-a --interface eth0 \
	--evidence-dir "$evidence_dir" --confirm NODE-RECOVERY-PREFLIGHT >"$tmp_dir/preflight-output"
bundle=$(sed -n 's/.*Evidence: //p' "$tmp_dir/preflight-output")
[ -n "$bundle" ] || fail 'preflight did not print an evidence bundle'
grep -q '^exit_status=0$' "$bundle/interface.txt" || fail 'preflight interface probe did not execute successfully'
grep -q '^command=node-recovery$' "$bundle/metadata" || fail 'preflight metadata command missing'
grep -q 'target_node=node-a' "$bundle/metadata" || fail 'preflight target missing from metadata'
pass 'preflight evidence and metadata'

PATH="$fake_bin:$PATH" "$network_repair" --target-node node-a --interface eth0 \
	--action flush-neighbors --evidence-dir "$evidence_dir" --confirm NETWORK-REPAIR >"$tmp_dir/repair-output"
repair_bundle=$(sed -n 's/.*Evidence: //p' "$tmp_dir/repair-output" | head -n 1)
grep -q '^exit_status=0$' "$repair_bundle/before-link.txt" || fail 'repair before probe did not execute successfully'
grep -q '^exit_status=0$' "$repair_bundle/after-link.txt" || fail 'repair after probe did not execute successfully'
grep -q 'action=flush-neighbors' "$repair_bundle/metadata" || fail 'repair action missing from metadata'
pass 'repair before/after evidence and metadata'

if PATH="$fake_bin:$PATH" ETHTOOL_FAIL=1 "$network_repair" \
	--target-node node-a --interface eth0 --action restart-autonegotiation \
	--evidence-dir "$evidence_dir" --confirm NETWORK-REPAIR >"$tmp_dir/failed-repair-output" 2>&1; then
	fail 'failed repair was accepted'
fi
failed_bundle=$(sed -n 's/.*Evidence: //p' "$tmp_dir/failed-repair-output" | head -n 1)
grep -q '^exit_status=0$' "$failed_bundle/before-link.txt" || fail 'failed repair before probe did not execute successfully'
grep -q '^exit_status=0$' "$failed_bundle/after-link.txt" || fail 'failed repair after probe did not execute successfully'
grep -q 'action_exit_status=7' "$failed_bundle/metadata" || fail 'failed action status missing from metadata'
pass 'failed repair preserves before/after evidence'

if PATH="$fake_bin:$PATH" "$preflight" --target-node node-b --interface eth0 \
	--evidence-dir "$evidence_dir" --confirm NODE-RECOVERY-PREFLIGHT >"$tmp_dir/mismatch-output" 2>&1; then
	fail 'preflight accepted a target different from the local node'
fi
pass 'target must match local node identity'

PATH="$fake_bin:$PATH" assert_rejected 'evidence root is rejected' "$preflight" \
	--target-node node-a --interface eth0 --evidence-dir / --confirm NODE-RECOVERY-PREFLIGHT
PATH="$fake_bin:$PATH" assert_rejected 'host system path is rejected' "$preflight" \
	--target-node node-a --interface eth0 --evidence-dir /etc --confirm NODE-RECOVERY-PREFLIGHT
