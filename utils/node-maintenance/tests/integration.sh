#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

# Integration proof for the node-maintenance image. Every container uses a
# disposable Docker network namespace (--network none) and named volume. The
# runner's network namespaces are never joined or changed.
set -eu

test_dir=$(cd -- "$(dirname -- "$0")" && pwd)
root_dir=$(cd -- "$test_dir/.." && pwd)
docker_bin=${DOCKER:-docker}
image=${NODE_MAINTENANCE_TEST_IMAGE:-}
keep_image=${NODE_MAINTENANCE_KEEP_IMAGE:-0}
build_image=${NODE_MAINTENANCE_BUILD_IMAGE:-1}
prefix="node-maintenance-it-$$"
tmp_dir=$(mktemp -d "${TMPDIR:-/tmp}/node-maintenance-integration.XXXXXX")
built_image=0
image_owned=0
container_name=
volume_name=

fail() {
	printf 'FAIL: %s\n' "$*" >&2
	exit 1
}

pass() {
	printf 'PASS: %s\n' "$*"
}

cleanup() {
	exit_code=$?
	cleanup_failed=0
	if [ -n "${container_name:-}" ]; then
		"$docker_bin" rm -f "$container_name" >/dev/null 2>&1 || true
		if "$docker_bin" container inspect "$container_name" >/dev/null 2>&1; then
			printf 'FAIL: disposable container %s survived cleanup\n' "$container_name" >&2
			cleanup_failed=1
		fi
	fi
	if [ -n "${volume_name:-}" ]; then
		"$docker_bin" volume rm "$volume_name" >/dev/null 2>&1 || true
		if "$docker_bin" volume inspect "$volume_name" >/dev/null 2>&1; then
			printf 'FAIL: disposable volume %s survived cleanup\n' "$volume_name" >&2
			cleanup_failed=1
		fi
	fi
	if [ "$built_image" -eq 1 ] && [ "$image_owned" -eq 1 ] && [ "$keep_image" != 1 ]; then
		"$docker_bin" image rm "$image" >/dev/null 2>&1 || true
	fi
	rm -rf "$tmp_dir"
	if [ "$cleanup_failed" -ne 0 ] && [ "$exit_code" -eq 0 ]; then
		exit_code=1
	fi
	exit "$exit_code"
}
trap cleanup EXIT

require_command() {
	command -v "$1" >/dev/null 2>&1 || fail "required command '$1' is not installed"
}

require_command "$docker_bin"
require_command mktemp
require_command grep
require_command sed
require_command sha256sum

"$docker_bin" info >/dev/null 2>&1 || fail "Docker daemon is unavailable; install/start Docker and rerun (no feature skip is allowed)"
docker_os=$("$docker_bin" info --format '{{.OSType}}') || fail "Docker daemon did not report its operating system"
[ "$docker_os" = linux ] || fail "integration requires a Linux Docker daemon for real network namespaces; got '$docker_os'"

docker_help=$($docker_bin run --help 2>&1) || fail "Docker cannot advertise run capabilities"
for required_flag in '--network' '--read-only' '--cap-drop' '--cap-add' '--security-opt' '--mount'; do
	printf '%s\n' "$docker_help" | grep -F -- "$required_flag" >/dev/null || fail "Docker lacks required '$required_flag' support"
done

if [ -z "$image" ]; then
	image="node-maintenance-integration:$$"
	build_image=1
	image_owned=1
fi
if [ "$build_image" = 1 ]; then
	printf 'Building integration image %s\n' "$image"
	"$docker_bin" build --pull=false -t "$image" "$root_dir" || fail "image build failed; integration cannot be skipped"
	built_image=1
else
	"$docker_bin" image inspect "$image" >/dev/null 2>&1 || fail "requested image '$image' is unavailable"
fi

runbook_bundle="$tmp_dir/runbook-bundle"
mkdir -p "$runbook_bundle"
printf '%s\n' \
	'schema: breakglass.runbook/v1' \
	'intent: node-maintenance' \
	'version: 0.1.0' \
	'image:' \
	'  name: ghcr.io/telekom/k8s-breakglass/utils/node-maintenance' \
	'  digest: sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' \
	'  architectures:' \
	'    - amd64' \
	'    - arm64' \
	'compatibility:' \
	'  kubernetes: ">=1.31.0"' \
	'  utility: node-maintenance' \
	'  utilityVersions:' \
	'    - dev' \
	'index:' \
	'  - id: node-maintenance-overview' \
	'    title: Node maintenance overview' \
	'    path: runbooks/node-maintenance.md' \
	'    summary: Bounded node recovery and repair procedures.' \
	'    security: Fixed commands, explicit capabilities, and disposable evidence.' \
	'source:' \
	'  repository: https://github.com/telekom/k8s-breakglass' \
	'  revision: 0123456789abcdef0123456789abcdef01234567' \
	'  generatedAt: "2026-08-27T00:00:00Z"' \
	>"$runbook_bundle/bundle.yaml"
mkdir -p "$runbook_bundle/runbooks"
printf '%s\n' \
	'# Deployment runbook fixture' \
	'' \
	'Intent: node-maintenance' \
	'Bundle version: 0.1.0' \
	'Utility image digest: sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff' \
	'Source revision: 0123456789abcdef0123456789abcdef01234567' \
	'' \
	'Prerequisites: Linux node, image-volume support, and an administrator-owned template.' \
	'Limits: fixed node-recovery/network-repair commands and bounded probes.' \
	'Evidence: use a dedicated /evidence volume and preserve the resulting bundle.' \
	'Security boundary: read-only root, no privilege escalation, and explicit capabilities.' \
	'Failure modes: stop on denied guards, failed pulls, or incomplete evidence.' \
	'Cleanup: delete the disposable Pod, volume, and session-owned resources.' \
	'' \
	'- [Node maintenance overview](runbooks/node-maintenance.md)' \
	>"$runbook_bundle/INDEX.md"
printf '%s\n' \
	'# Node maintenance overview' \
	'' \
	'Use the fixed node-recovery and network-repair commands with the required evidence and confirmation boundaries.' \
	>"$runbook_bundle/runbooks/node-maintenance.md"
docs_output=$(
	"$docker_bin" run --rm --network none --read-only --cap-drop ALL \
		--security-opt no-new-privileges --security-opt seccomp=builtin \
		--mount "type=bind,source=$runbook_bundle,destination=/usr/share/breakglass/runbooks/internal,readonly" \
		--entrypoint /bin/sh "$image" -c '
			test -r /usr/share/breakglass/runbooks/upstream/node-maintenance/README.md
			test -r /usr/share/breakglass/runbooks/upstream/node-maintenance/network-repair.md
			test -r /usr/share/breakglass/runbooks/upstream/node-maintenance/kexec-recovery-validation.md
			test -r /usr/share/breakglass/runbooks/internal/bundle.yaml
			test -r /usr/share/breakglass/runbooks/internal/INDEX.md
			test -r /usr/share/breakglass/runbooks/internal/runbooks/node-maintenance.md
			cat /usr/share/breakglass/runbooks/internal/bundle.yaml
			if printf modified >>/usr/share/breakglass/runbooks/internal/bundle.yaml 2>/dev/null; then
				exit 70
			fi
		' 2>/dev/null
) || fail 'built-in and mounted runbooks were not readable with a read-only downstream bundle'
printf '%s\n' "$docs_output" | grep -q '^schema: breakglass.runbook/v1$' \
	|| fail 'mounted runbook bundle metadata was not discovered through the shared contract'
printf '%s\n' "$docs_output" | grep -q '^  digest: sha256:ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff$' \
	|| fail 'mounted runbook bundle did not expose its immutable utility digest'
printf '%s\n' "$docs_output" | grep -q '^index:$' \
	|| fail 'mounted runbook bundle did not expose its required index metadata'
pass 'generic and optional downstream runbooks are readable while the bundle remains read-only'

new_fixture() {
	label=$1
	container_name="${prefix}-${label}"
	volume_name="${prefix}-volume-${label}"
	fixture_dir="$tmp_dir/$label"
	mkdir -p "$fixture_dir"
	"$docker_bin" volume create "$volume_name" >/dev/null || fail "could not create disposable volume '$volume_name'"
	case "$label" in
		guard-evidence-symlink)
			"$docker_bin" run --rm --entrypoint /bin/sh \
				--mount "source=$volume_name,destination=/evidence" "$image" \
				-c 'ln -s /host/etc /evidence/escaped' || fail 'could not seed symlink attack fixture'
			;;
		guard-evidence-rename)
			"$docker_bin" run --rm --entrypoint /bin/sh \
				--mount "source=$volume_name,destination=/evidence" "$image" \
				-c 'mkdir /evidence/race && mv /evidence/race /evidence/race-original && ln -s /host/etc /evidence/race' \
				|| fail 'could not seed rename attack fixture'
			;;
		guard-operation-lock)
			"$docker_bin" run --rm --entrypoint /bin/sh \
				--mount "source=$volume_name,destination=/evidence" "$image" \
				-c 'mkdir /evidence/.node-maintenance-operation.lock' \
				|| fail 'could not seed concurrent-operation fixture'
			;;
	esac
}

destroy_fixture() {
	"$docker_bin" rm -f "$container_name" >/dev/null 2>&1 || true
	if "$docker_bin" container inspect "$container_name" >/dev/null 2>&1; then
		fail "disposable container '$container_name' survived cleanup"
	fi
	"$docker_bin" volume rm "$volume_name" >/dev/null 2>&1 || fail "cleanup failed for volume '$volume_name'"
	"$docker_bin" volume inspect "$volume_name" >/dev/null 2>&1 && fail "disposable volume '$volume_name' survived cleanup"
	container_name=
	volume_name=
}

run_command() {
	label=$1
	expected_exit=$2
	capability=$3
	approved_action=$4
	shift 4
	new_fixture "$label"
	output_file="$fixture_dir/output"
	set +e
	if [ "$capability" = none ]; then
		"$docker_bin" run \
			--name "$container_name" --user 0 --env BREAKGLASS_NODE_NAME=node-a \
			--env BREAKGLASS_OPERATION_ID="operation-$label" \
			--env BREAKGLASS_RECORDING_ID="recording-$label" \
			--env BREAKGLASS_APPROVAL_ID="approval-$label" \
			--env BREAKGLASS_APPROVED_ACTION="$approved_action" \
			--network none --read-only --cap-drop ALL \
			--security-opt no-new-privileges --security-opt seccomp=builtin \
			--mount "source=$volume_name,destination=/evidence" \
			"$image" "$@" >"$output_file" 2>&1
	else
		[ "$capability" = NET_ADMIN ] || fail "unsupported requested test capability '$capability'"
		"$docker_bin" run \
			--name "$container_name" --user 0 --env BREAKGLASS_NODE_NAME=node-a \
			--env BREAKGLASS_OPERATION_ID="operation-$label" \
			--env BREAKGLASS_RECORDING_ID="recording-$label" \
			--env BREAKGLASS_APPROVAL_ID="approval-$label" \
			--env BREAKGLASS_APPROVED_ACTION="$approved_action" \
			--network none --read-only --cap-drop ALL --cap-add NET_ADMIN \
			--security-opt no-new-privileges --security-opt seccomp=builtin \
			--mount "source=$volume_name,destination=/evidence" \
			"$image" "$@" >"$output_file" 2>&1
	fi
	actual_exit=$?
	set -e
	cat "$output_file"
	assert_container_security "$container_name" "$capability"
	if [ "$expected_exit" = nonzero ]; then
		[ "$actual_exit" -ne 0 ] || fail "$label unexpectedly succeeded"
	else
		[ "$actual_exit" -eq "$expected_exit" ] || fail "$label returned $actual_exit, expected $expected_exit"
	fi
}

assert_container_security() {
	name=$1
	expected_capability=$2
	network_mode=$("$docker_bin" inspect --format '{{.HostConfig.NetworkMode}}' "$name") || fail "could not inspect container '$name'"
	readonly_root=$("$docker_bin" inspect --format '{{.HostConfig.ReadonlyRootfs}}' "$name") || fail "could not inspect read-only root for '$name'"
	user=$("$docker_bin" inspect --format '{{.Config.User}}' "$name") || fail "could not inspect user for '$name'"
	cap_drop=$("$docker_bin" inspect --format '{{join .HostConfig.CapDrop ","}}' "$name") || fail "could not inspect dropped capabilities for '$name'"
	cap_add=$("$docker_bin" inspect --format '{{join .HostConfig.CapAdd ","}}' "$name") || fail "could not inspect added capabilities for '$name'"
	security_opts=$("$docker_bin" inspect --format '{{join .HostConfig.SecurityOpt ","}}' "$name") || fail "could not inspect security options for '$name'"
	[ "$network_mode" = none ] || fail "$name used network mode '$network_mode', expected none"
	[ "$readonly_root" = true ] || fail "$name did not use a read-only root filesystem"
	[ "$user" = 0 ] || fail "$name did not run as UID 0 for the capability-bound helper"
	[ "$cap_drop" = ALL ] || fail "$name did not drop all capabilities (got '$cap_drop')"
	case "$expected_capability" in
		none) [ -z "$cap_add" ] || fail "$name added capabilities for a read-only preflight (got '$cap_add')" ;;
		NET_ADMIN)
			case "$cap_add" in
				NET_ADMIN|CAP_NET_ADMIN) ;;
				*) fail "$name did not add only NET_ADMIN (got '$cap_add')" ;;
			esac
			;;
	esac
	case ",$security_opts," in
		*,no-new-privileges,* ) ;;
		*) fail "$name did not set no-new-privileges (got '$security_opts')" ;;
	esac
	case ",$security_opts," in
		*,seccomp=builtin,* ) ;;
		*) fail "$name did not set the runtime-default seccomp profile (got '$security_opts')" ;;
	esac
}

bundle_from_output() {
	output_file=$1
	bundle=$(sed -n 's/.*Evidence: //p' "$output_file" | tail -n 1)
	case "$bundle" in
		/evidence/*) ;;
		*) fail "output did not contain a safe evidence bundle path: '$bundle'" ;;
	esac
	printf '%s\n' "$bundle"
}

copy_bundle() {
	output_file=$1
	bundle=$2
	"$docker_bin" cp "$container_name:$bundle" "$fixture_dir/" >/dev/null || fail "could not copy evidence bundle '$bundle'"
	host_bundle="$fixture_dir/$(basename "$bundle")"
	printf '%s\n' "$host_bundle"
}

assert_capture_statuses() {
	host_bundle=$1
	shift
	for evidence_file in "$@"; do
		grep -q '^exit_status=' "$host_bundle/$evidence_file" || fail "evidence file lacks an exit status: $host_bundle/$evidence_file"
	done
}

new_fixture capture-output-quota
set +e
# The quoted program is evaluated inside the test container; host-side
# expansion would invalidate the namespace and evidence-path proof.
# shellcheck disable=SC2016
"$docker_bin" run \
	--name "$container_name" --user 0 --network none --read-only --cap-drop ALL \
	--security-opt no-new-privileges --security-opt seccomp=builtin \
	--mount "source=$volume_name,destination=/evidence" \
	--entrypoint /bin/sh "$image" -c '
		. /usr/local/libexec/node-maintenance/common.sh
		EVIDENCE_DIR=/evidence
		bundle=/evidence/quota
		mkdir -m 0700 "$bundle"
		set +e
		capture "$bundle/output" awk '\''BEGIN { for (i = 0; i < 40000; i++) printf "x" }'\''
		status=$?
		set -e
		[ "$status" -eq 75 ]
	' >"$fixture_dir/output" 2>&1
quota_status=$?
set -e
cat "$fixture_dir/output"
assert_container_security "$container_name" none
[ "$quota_status" -eq 0 ] || fail "bounded capture behavior returned $quota_status"
"$docker_bin" cp "$container_name:/evidence/quota/output" "$fixture_dir/quota-output" >/dev/null \
	|| fail 'could not copy bounded capture evidence'
[ "$(wc -c <"$fixture_dir/quota-output" | tr -d ' ')" -le 32832 ] \
	|| fail 'oversized capture exceeded the bounded evidence allowance'
grep -q '^capture_result=output-quota-exceeded$' "$fixture_dir/quota-output" \
	|| fail 'oversized capture did not record the quota failure'
destroy_fixture
pass 'oversized command output is bounded while it is produced'

run_command preflight 0 none read-only node-recovery --target-node node-a --interface lo \
	--evidence-dir /evidence --confirm NODE-RECOVERY-PREFLIGHT
preflight_bundle=$(bundle_from_output "$fixture_dir/output")
preflight_host_bundle=$(copy_bundle "$fixture_dir/output" "$preflight_bundle")
assert_capture_statuses "$preflight_host_bundle" interface.txt addresses.txt routes.txt neighbors.txt ethtool.txt resolver.txt kernel.txt
grep -q '^exit_status=0$' "$preflight_host_bundle/interface.txt" || fail 'preflight interface probe did not succeed'
grep -q 'command=node-recovery' "$preflight_host_bundle/metadata" || fail 'preflight metadata command mismatch'
grep -q 'target_node=node-a' "$preflight_host_bundle/metadata" || fail 'preflight metadata target mismatch'
grep -q 'interface=lo' "$preflight_host_bundle/metadata" || fail 'preflight metadata interface mismatch'
grep -q 'action=read-only' "$preflight_host_bundle/metadata" || fail 'preflight metadata action mismatch'
grep -q 'operation_id=operation-preflight' "$preflight_host_bundle/metadata" || fail 'preflight operation correlation mismatch'
grep -q 'recording_id=recording-preflight' "$preflight_host_bundle/metadata" || fail 'preflight recording correlation mismatch'
grep -q '"event":"operation-completed"' "$preflight_host_bundle/events.jsonl" || fail 'preflight completion recording hook is missing'
grep -Eq '(^|:) lo:' "$preflight_host_bundle/interface.txt" || fail 'preflight did not observe the loopback interface'
grep -q '^Linux ' "$preflight_host_bundle/kernel.txt" || fail 'preflight did not observe Linux kernel evidence'
grep -q '^exit_status=' "$preflight_host_bundle/resolver.txt" || fail 'preflight resolver evidence was not executed'
destroy_fixture
pass 'node-recovery runs in isolated namespace and records evidence'

run_repair() {
	action=$1
	expected_exit=$2
	run_command "repair-$action" "$expected_exit" NET_ADMIN "$action" network-repair --target-node node-a --interface lo \
		--action "$action" --evidence-dir /evidence --confirm NETWORK-REPAIR
	repair_bundle=$(bundle_from_output "$fixture_dir/output")
	repair_host_bundle=$(copy_bundle "$fixture_dir/output" "$repair_bundle")
	assert_capture_statuses "$repair_host_bundle" before-link.txt before-addresses.txt before-routes.txt before-neighbors.txt \
		after-link.txt after-addresses.txt after-routes.txt after-neighbors.txt
	grep -q '^exit_status=0$' "$repair_host_bundle/before-link.txt" || fail "$action before-link probe did not succeed"
	grep -q '^exit_status=0$' "$repair_host_bundle/after-link.txt" || fail "$action after-link probe did not succeed"
	grep -Eq '(^|:) lo:' "$repair_host_bundle/before-link.txt" || fail "$action did not observe the loopback interface before repair"
	grep -Eq '(^|:) lo:' "$repair_host_bundle/after-link.txt" || fail "$action did not observe the loopback interface after repair"
	grep -q "action=$action" "$repair_host_bundle/metadata" || fail "$action metadata action mismatch"
	if [ "$expected_exit" = 0 ]; then
		grep -q 'action_exit_status=0' "$repair_host_bundle/metadata" || fail "$action did not record success"
	else
		grep -Eq 'action_exit_status=[1-9][0-9]*' "$repair_host_bundle/metadata" || fail "$action did not record failure"
	fi
	destroy_fixture
	pass "network-repair action '$action' records before/after evidence"
}

run_repair link-cycle 0
# loopback has no auto-negotiation; this is the expected real-tool failure
# path and proves that failure evidence is retained rather than hidden.
run_repair restart-autonegotiation nonzero

run_network_fixture() {
	label=$1
	expected_exit=$2
	approved_action=$3
	shift 3
	new_fixture "$label"
	output_file="$fixture_dir/output"
	set +e
	"$docker_bin" run \
		--name "$container_name" --user 0 --env BREAKGLASS_NODE_NAME=node-a \
		--env BREAKGLASS_OPERATION_ID="operation-$label" \
		--env BREAKGLASS_RECORDING_ID="recording-$label" \
		--env BREAKGLASS_APPROVAL_ID="approval-$label" \
		--env BREAKGLASS_APPROVED_ACTION="$approved_action" \
		--network none --read-only --cap-drop ALL --cap-add NET_ADMIN \
		--security-opt no-new-privileges --security-opt seccomp=builtin \
		--mount "source=$volume_name,destination=/evidence" \
		--entrypoint /bin/sh "$image" -c '
			set -eu
			ip link set lo up
			ip link add repair0 type veth peer name repairpeer
			ip address add 192.0.2.1/24 dev repair0
			ip link set repair0 up
			ip link set repairpeer up
			ip link add br0 type bridge
			ip link set br0 type bridge vlan_filtering 1
			ip link set br0 up
			ip link add br1 type bridge
			ip link set br1 up
			ip link add fdb0 type veth peer name fdbpeer
			ip link set fdb0 master br0
			ip link set fdb0 up
			ip link set fdbpeer up
			bridge vlan add dev fdb0 vid 100
			bridge vlan add dev br0 vid 100 self
			exec /usr/local/bin/node-maintenance "$@"
		' fixture "$@" >"$output_file" 2>&1
	actual_exit=$?
	set -e
	cat "$output_file"
	assert_container_security "$container_name" NET_ADMIN
	if [ "$expected_exit" = nonzero ]; then
		[ "$actual_exit" -ne 0 ] || fail "$label unexpectedly succeeded"
	else
		[ "$actual_exit" -eq "$expected_exit" ] || fail "$label returned $actual_exit, expected $expected_exit"
	fi
}

run_network_fixture repair-neighbor-replace 0 neighbor-replace network-repair \
	--target-node node-a --interface repair0 --action neighbor-replace \
	--neighbor-address 192.0.2.2 --entry-mac 02:00:00:00:00:02 \
	--evidence-dir /evidence --confirm NETWORK-REPAIR
neighbor_bundle=$(bundle_from_output "$fixture_dir/output")
neighbor_host_bundle=$(copy_bundle "$fixture_dir/output" "$neighbor_bundle")
assert_capture_statuses "$neighbor_host_bundle" before-neighbor-route.txt before-neighbor-entry.txt \
	action-neighbor-replace.txt after-neighbor-entry.txt
grep -Eq '^192\.0\.2\.2 +lladdr +02:00:00:00:00:02 +REACHABLE' "$neighbor_host_bundle/after-neighbor-entry.txt" \
	|| fail 'neighbor-replace did not create the exact requested entry in the disposable namespace'
grep -q '^action_exit_status=0$' "$neighbor_host_bundle/metadata" || fail 'neighbor-replace did not record success'
grep -q '"result":"succeeded"' "$neighbor_host_bundle/events.jsonl" || fail 'neighbor-replace completion recording hook is missing'
destroy_fixture
pass 'neighbor-replace changes only the exact requested entry in a disposable Linux namespace'

run_network_fixture repair-bridge-fdb-replace 0 bridge-fdb-replace network-repair \
	--target-node node-a --interface fdb0 --bridge br0 --action bridge-fdb-replace \
	--entry-mac 02:00:00:00:01:00 --vlan 100 \
	--evidence-dir /evidence --confirm NETWORK-REPAIR
fdb_bundle=$(bundle_from_output "$fixture_dir/output")
fdb_host_bundle=$(copy_bundle "$fixture_dir/output" "$fdb_bundle")
assert_capture_statuses "$fdb_host_bundle" before-bridge.txt before-bridge-vlan.txt before-fdb-entry.txt \
	action-bridge-fdb-replace.txt after-bridge-vlan.txt after-fdb-entry.txt
grep -Ei '^02:00:00:00:01:00 .*vlan 100 .*static' "$fdb_host_bundle/after-fdb-entry.txt" \
	|| fail 'bridge-fdb-replace did not create the exact MAC/VLAN/port entry in the disposable namespace'
grep -q '^action_exit_status=0$' "$fdb_host_bundle/metadata" || fail 'bridge-fdb-replace did not record success'
destroy_fixture
pass 'bridge-fdb-replace changes only the exact bridge, port, MAC, and VLAN entry'

run_network_fixture guard-fdb-wrong-bridge nonzero bridge-fdb-replace network-repair \
	--target-node node-a --interface fdb0 --bridge br1 --action bridge-fdb-replace \
	--entry-mac 02:00:00:00:01:00 --vlan 100 \
	--evidence-dir /evidence --confirm NETWORK-REPAIR
grep -q 'not attached to exact bridge' "$fixture_dir/output" || fail 'wrong bridge target produced no exact-target denial'
destroy_fixture
pass 'FDB repair denies a port attached to a different bridge'

run_network_fixture guard-fdb-wrong-vlan nonzero bridge-fdb-replace network-repair \
	--target-node node-a --interface fdb0 --bridge br0 --action bridge-fdb-replace \
	--entry-mac 02:00:00:00:01:00 --vlan 200 \
	--evidence-dir /evidence --confirm NETWORK-REPAIR
grep -q 'VLAN.*is not configured' "$fixture_dir/output" || fail 'wrong VLAN target produced no exact-target denial'
destroy_fixture
pass 'FDB repair denies an unconfigured VLAN before mutation'

assert_volume_path_absent() {
	relative_path=$1
	# $1 is intentionally expanded by the isolated container shell.
	# shellcheck disable=SC2016
	"$docker_bin" run --rm --network none --read-only --cap-drop ALL \
		--security-opt no-new-privileges --security-opt seccomp=builtin \
		--mount "source=$volume_name,destination=/evidence" --entrypoint /bin/sh "$image" \
		-c 'test ! -e "/evidence/$1"' verify "$relative_path" \
		|| fail "unexpected evidence-volume path was created: $relative_path"
}

run_command guard-neighbor-injection 2 none neighbor-replace network-repair \
	--target-node node-a --interface lo --action neighbor-replace \
	--neighbor-address '192.0.2.2;touch-/evidence/injected' --entry-mac 02:00:00:00:00:02 \
	--evidence-dir /evidence --confirm NETWORK-REPAIR
grep -q 'neighbor address must be an IPv4 or IPv6 literal' "$fixture_dir/output" || fail 'neighbor argument injection produced no literal-address denial'
assert_volume_path_absent injected
destroy_fixture
pass 'neighbor-replace rejects command-like entry data without evaluation'

run_command guard-action-binding 2 none link-cycle network-repair \
	--target-node node-a --interface lo --action neighbor-replace \
	--neighbor-address 192.0.2.2 --entry-mac 02:00:00:00:00:02 \
	--evidence-dir /evidence --confirm NETWORK-REPAIR
grep -q 'does not match requested action' "$fixture_dir/output" || fail 'approval/action mismatch produced no denial'
destroy_fixture
pass 'each repair requires an independently bound exact approved action'

run_command guard-operation-lock 2 none read-only node-recovery --target-node node-a --interface lo \
	--evidence-dir /evidence --confirm NODE-RECOVERY-PREFLIGHT
grep -q 'another node-maintenance operation is active' "$fixture_dir/output" || fail 'concurrent-operation lease produced no denial'
destroy_fixture
pass 'a concurrent operation sharing the controller evidence lease is denied'

recovery_dir="$tmp_dir/recovery"
mkdir -p "$recovery_dir"
printf '%s\n' 'test-provider-kernel-payload' >"$recovery_dir/kernel"
printf '%s\n' 'test-provider-initrd-payload' >"$recovery_dir/initrd"
# The command-like text must remain literal to prove validation never evaluates it.
# shellcheck disable=SC2016
printf '%s\n' 'console=ttyS0 $(touch /evidence/kexec-executed)' >"$recovery_dir/cmdline"
printf '%s\n' '#!/bin/sh' 'touch /evidence/fake-kexec-executed' >"$recovery_dir/kexec"
chmod 0555 "$recovery_dir/kexec"
kernel_digest=$(sha256sum "$recovery_dir/kernel" | awk '{print $1}')
initrd_digest=$(sha256sum "$recovery_dir/initrd" | awk '{print $1}')
cmdline_digest=$(sha256sum "$recovery_dir/cmdline" | awk '{print $1}')

run_kexec_validation() {
	label=$1
	expected_exit=$2
	mount_access=$3
	approved_action=$4
	provider_profile=$5
	expected_kernel=$6
	expected_initrd=$7
	expected_cmdline=$8
	shift 8
	new_fixture "$label"
	output_file="$fixture_dir/output"
	mount_spec="type=bind,source=$recovery_dir,destination=/recovery"
	[ "$mount_access" = writable ] || mount_spec="$mount_spec,readonly"
	set +e
	"$docker_bin" run \
		--name "$container_name" --user 0 --env BREAKGLASS_NODE_NAME=node-a \
		--env BREAKGLASS_OPERATION_ID="operation-$label" \
		--env BREAKGLASS_RECORDING_ID="recording-$label" \
		--env BREAKGLASS_APPROVAL_ID="approval-$label" \
		--env BREAKGLASS_APPROVED_ACTION="$approved_action" \
		--env BREAKGLASS_KEXEC_PROFILE="$provider_profile" \
		--env BREAKGLASS_KEXEC_KERNEL_SHA256="$expected_kernel" \
		--env BREAKGLASS_KEXEC_INITRD_SHA256="$expected_initrd" \
		--env BREAKGLASS_KEXEC_CMDLINE_SHA256="$expected_cmdline" \
		--network none --read-only --cap-drop ALL \
		--security-opt no-new-privileges --security-opt seccomp=builtin \
		--mount "source=$volume_name,destination=/evidence" \
		--mount "$mount_spec" \
		"$image" "$@" >"$output_file" 2>&1
	actual_exit=$?
	set -e
	cat "$output_file"
	assert_container_security "$container_name" none
	if [ "$expected_exit" = nonzero ]; then
		[ "$actual_exit" -ne 0 ] || fail "$label unexpectedly succeeded"
	else
		[ "$actual_exit" -eq "$expected_exit" ] || fail "$label returned $actual_exit, expected $expected_exit"
	fi
}

run_kexec_validation kexec-validation 0 readonly kexec-recovery-validate rescue-a \
	"$kernel_digest" "$initrd_digest" "$cmdline_digest" \
	kexec-recovery-validate --target-node node-a --recovery-profile rescue-a \
	--evidence-dir /evidence --confirm KEXEC-RECOVERY-VALIDATE
kexec_bundle=$(bundle_from_output "$fixture_dir/output")
kexec_host_bundle=$(copy_bundle "$fixture_dir/output" "$kexec_bundle")
assert_capture_statuses "$kexec_host_bundle" kernel.sha256.txt initrd.sha256.txt cmdline.sha256.txt
grep -q '^validation_result=provider-inputs-verified$' "$kexec_host_bundle/validation-result.txt" \
	|| fail 'kexec validation did not record provider input verification'
grep -q '^execution_performed=false$' "$kexec_host_bundle/validation-result.txt" \
	|| fail 'kexec validation evidence did not explicitly deny execution'
grep -q '^provider_executor_required=true$' "$kexec_host_bundle/validation-result.txt" \
	|| fail 'kexec validation did not retain the provider executor dependency'
assert_volume_path_absent kexec-executed
assert_volume_path_absent fake-kexec-executed
destroy_fixture
pass 'fixed provider recovery inputs are validated without evaluating cmdline or invoking an executable'

bad_kernel_digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
run_kexec_validation guard-kexec-digest-mismatch nonzero readonly kexec-recovery-validate rescue-a \
	"$bad_kernel_digest" "$initrd_digest" "$cmdline_digest" \
	kexec-recovery-validate --target-node node-a --recovery-profile rescue-a \
	--evidence-dir /evidence --confirm KEXEC-RECOVERY-VALIDATE
grep -q 'kexec was not executed' "$fixture_dir/output" || fail 'digest mismatch did not explicitly deny kexec execution'
mismatch_bundle=$(bundle_from_output "$fixture_dir/output")
mismatch_host_bundle=$(copy_bundle "$fixture_dir/output" "$mismatch_bundle")
grep -q '^validation_result=digest-mismatch$' "$mismatch_host_bundle/validation-result.txt" \
	|| fail 'digest mismatch was not retained as evidence'
grep -q '^execution_performed=false$' "$mismatch_host_bundle/validation-result.txt" \
	|| fail 'digest mismatch evidence did not explicitly deny execution'
assert_volume_path_absent fake-kexec-executed
destroy_fixture
pass 'recovery digest mismatch fails closed with no execution'

run_kexec_validation guard-kexec-missing-digest 2 readonly kexec-recovery-validate rescue-a \
	'' "$initrd_digest" "$cmdline_digest" \
	kexec-recovery-validate --target-node node-a --recovery-profile rescue-a \
	--evidence-dir /evidence --confirm KEXEC-RECOVERY-VALIDATE
grep -q 'BREAKGLASS_KEXEC_KERNEL_SHA256 must be an exact SHA-256 digest' "$fixture_dir/output" \
	|| fail 'missing provider digest produced no denial'
assert_volume_path_absent fake-kexec-executed
destroy_fixture
pass 'missing provider recovery digest fails closed with no execution'

run_kexec_validation guard-kexec-caller-path 2 readonly kexec-recovery-validate rescue-a \
	"$kernel_digest" "$initrd_digest" "$cmdline_digest" \
	kexec-recovery-validate --target-node node-a --recovery-profile rescue-a \
	--kernel-path /recovery/kexec --evidence-dir /evidence --confirm KEXEC-RECOVERY-VALIDATE
grep -q "unsupported option '--kernel-path'" "$fixture_dir/output" || fail 'caller-selected recovery path produced no denial'
assert_volume_path_absent fake-kexec-executed
destroy_fixture
pass 'caller-selected recovery paths fail closed with no execution'

run_kexec_validation guard-kexec-profile-mismatch 2 readonly kexec-recovery-validate rescue-b \
	"$kernel_digest" "$initrd_digest" "$cmdline_digest" \
	kexec-recovery-validate --target-node node-a --recovery-profile rescue-a \
	--evidence-dir /evidence --confirm KEXEC-RECOVERY-VALIDATE
grep -q 'does not match the controller-provided profile' "$fixture_dir/output" || fail 'profile mismatch produced no denial'
assert_volume_path_absent fake-kexec-executed
destroy_fixture
pass 'recovery profile mismatch fails closed before reading provider assets'

run_kexec_validation guard-kexec-writable-mount 2 writable kexec-recovery-validate rescue-a \
	"$kernel_digest" "$initrd_digest" "$cmdline_digest" \
	kexec-recovery-validate --target-node node-a --recovery-profile rescue-a \
	--evidence-dir /evidence --confirm KEXEC-RECOVERY-VALIDATE
grep -q 'distinct read-only mount' "$fixture_dir/output" || fail 'writable recovery mount produced no denial'
assert_volume_path_absent fake-kexec-executed
destroy_fixture
pass 'writable provider recovery assets are rejected'

run_kexec_validation guard-kexec-action-binding 2 readonly neighbor-replace rescue-a \
	"$kernel_digest" "$initrd_digest" "$cmdline_digest" \
	kexec-recovery-validate --target-node node-a --recovery-profile rescue-a \
	--evidence-dir /evidence --confirm KEXEC-RECOVERY-VALIDATE
grep -q 'does not match requested action' "$fixture_dir/output" || fail 'kexec approval/action mismatch produced no denial'
assert_volume_path_absent fake-kexec-executed
destroy_fixture
pass 'kexec validation requires an independent exact approved action binding'

run_command guard-missing-confirmation 2 none neighbor-replace network-repair --target-node node-a --interface lo \
	--action neighbor-replace --neighbor-address 192.0.2.2 --entry-mac 02:00:00:00:00:02 --evidence-dir /evidence
grep -q 'confirmation' "$fixture_dir/output" || fail 'missing confirmation produced no actionable denial'
destroy_fixture
pass 'missing confirmation is denied'

run_command guard-target-mismatch 2 none read-only node-recovery --target-node node-b --interface lo \
	--evidence-dir /evidence --confirm NODE-RECOVERY-PREFLIGHT
grep -q 'does not match controller-provided node' "$fixture_dir/output" || fail 'target mismatch produced no actionable denial'
destroy_fixture
pass 'target mismatch is denied'

run_command guard-unsafe-path 2 none read-only node-recovery --target-node node-a --interface lo \
	--evidence-dir / --confirm NODE-RECOVERY-PREFLIGHT
grep -q 'evidence directory' "$fixture_dir/output" || fail 'unsafe evidence path produced no actionable denial'
destroy_fixture
pass 'unsafe evidence path is denied'

run_command guard-evidence-symlink 2 none read-only node-recovery --target-node node-a --interface lo \
	--evidence-dir /evidence/escaped --confirm NODE-RECOVERY-PREFLIGHT
grep -q 'symlink\|resolv' "$fixture_dir/output" || fail 'evidence symlink produced no actionable denial'
destroy_fixture
pass 'evidence symlink is denied'

run_command guard-evidence-rename 2 none read-only node-recovery --target-node node-a --interface lo \
	--evidence-dir /evidence/race --confirm NODE-RECOVERY-PREFLIGHT
grep -q 'symlink\|resolv' "$fixture_dir/output" || fail 'evidence rename attack produced no actionable denial'
destroy_fixture
pass 'evidence rename attack is denied'

run_command guard-unknown-command 2 none unsupported unsupported-command
grep -q 'Unsupported command' "$fixture_dir/output" || fail 'unknown command produced no actionable denial'
destroy_fixture
pass 'dispatcher rejects unknown commands'

printf 'PASS: node-maintenance integration contract completed with no host-network changes\n'
