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
	if [ -n "${container_name:-}" ]; then
		"$docker_bin" rm -f "$container_name" >/dev/null 2>&1 || true
	fi
	if [ -n "${volume_name:-}" ]; then
		"$docker_bin" volume rm "$volume_name" >/dev/null 2>&1 || true
	fi
	if [ "$built_image" -eq 1 ] && [ "$keep_image" != 1 ]; then
		"$docker_bin" image rm "$image" >/dev/null 2>&1 || true
	fi
	rm -rf "$tmp_dir"
	exit "$exit_code"
}
trap cleanup EXIT INT TERM

require_command() {
	command -v "$1" >/dev/null 2>&1 || fail "required command '$1' is not installed"
}

require_command "$docker_bin"
require_command mktemp
require_command grep
require_command sed

[ "$(uname -s)" = Linux ] || fail "integration requires Linux Docker namespaces; refusing to run on $(uname -s)"
"$docker_bin" info >/dev/null 2>&1 || fail "Docker daemon is unavailable; install/start Docker and rerun (no feature skip is allowed)"

docker_help=$($docker_bin run --help 2>&1) || fail "Docker cannot advertise run capabilities"
for required_flag in '--network' '--hostname' '--read-only' '--cap-drop' '--cap-add' '--security-opt' '--mount'; do
	printf '%s\n' "$docker_help" | grep -F -- "$required_flag" >/dev/null || fail "Docker lacks required '$required_flag' support"
done

if [ -z "$image" ]; then
	image="node-maintenance-integration:$$"
	build_image=1
fi
if [ "$build_image" = 1 ]; then
	printf 'Building integration image %s\n' "$image"
	"$docker_bin" build --pull=false -t "$image" "$root_dir" || fail "image build failed; integration cannot be skipped"
	built_image=1
else
	"$docker_bin" image inspect "$image" >/dev/null 2>&1 || fail "requested image '$image' is unavailable"
fi

new_fixture() {
	label=$1
	container_name="${prefix}-${label}"
	volume_name="${prefix}-volume-${label}"
	fixture_dir="$tmp_dir/$label"
	mkdir -p "$fixture_dir"
	"$docker_bin" volume create "$volume_name" >/dev/null || fail "could not create disposable volume '$volume_name'"
}

destroy_fixture() {
	"$docker_bin" rm -f "$container_name" >/dev/null 2>&1 || true
	"$docker_bin" volume rm "$volume_name" >/dev/null 2>&1 || fail "cleanup failed for volume '$volume_name'"
	"$docker_bin" volume inspect "$volume_name" >/dev/null 2>&1 && fail "disposable volume '$volume_name' survived cleanup"
	container_name=
	volume_name=
}

run_command() {
	label=$1
	expected_exit=$2
	shift 2
	new_fixture "$label"
	output_file="$fixture_dir/output"
	set +e
	"$docker_bin" run \
		--name "$container_name" \
		--user 0 \
		--hostname node-a \
		--network none \
		--read-only \
		--cap-drop ALL \
		--cap-add NET_ADMIN \
		--security-opt no-new-privileges \
		--mount "source=$volume_name,destination=/evidence" \
		"$image" "$@" >"$output_file" 2>&1
	actual_exit=$?
	set -e
	cat "$output_file"
	if [ "$expected_exit" = nonzero ]; then
		[ "$actual_exit" -ne 0 ] || fail "$label unexpectedly succeeded"
	else
		[ "$actual_exit" -eq "$expected_exit" ] || fail "$label returned $actual_exit, expected $expected_exit"
	fi
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
	[ -d "$host_bundle" ] || fail "copied evidence bundle is missing: '$host_bundle'"
	printf '%s\n' "$host_bundle"
}

assert_evidence() {
	host_bundle=$1
	shift
	for evidence_file in "$@"; do
		[ -s "$host_bundle/$evidence_file" ] || fail "evidence file is missing or empty: $host_bundle/$evidence_file"
	done
}

run_command preflight 0 node-recovery --target-node node-a --interface lo \
	--evidence-dir /evidence --confirm NODE-RECOVERY-PREFLIGHT
preflight_bundle=$(bundle_from_output "$fixture_dir/output")
preflight_host_bundle=$(copy_bundle "$fixture_dir/output" "$preflight_bundle")
assert_evidence "$preflight_host_bundle" interface.txt addresses.txt routes.txt neighbors.txt ethtool.txt resolver.txt kernel.txt metadata
grep -q 'target_node=node-a' "$preflight_host_bundle/metadata" || fail 'preflight metadata target mismatch'
destroy_fixture
pass 'node-recovery runs in isolated namespace and records evidence'

run_repair() {
	action=$1
	expected_exit=$2
	run_command "repair-$action" "$expected_exit" network-repair --target-node node-a --interface lo \
		--action "$action" --evidence-dir /evidence --confirm NETWORK-REPAIR
	repair_bundle=$(bundle_from_output "$fixture_dir/output")
	repair_host_bundle=$(copy_bundle "$fixture_dir/output" "$repair_bundle")
	assert_evidence "$repair_host_bundle" before-link.txt before-addresses.txt before-routes.txt before-neighbors.txt \
		after-link.txt after-addresses.txt after-routes.txt after-neighbors.txt metadata
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
run_repair flush-neighbors 0
# loopback has no auto-negotiation; this is the expected real-tool failure
# path and proves that failure evidence is retained rather than hidden.
run_repair restart-autonegotiation nonzero

run_command guard-missing-confirmation 2 network-repair --target-node node-a --interface lo \
	--action flush-neighbors --evidence-dir /evidence
grep -q 'confirmation' "$fixture_dir/output" || fail 'missing confirmation produced no actionable denial'
destroy_fixture
pass 'missing confirmation is denied'

run_command guard-target-mismatch 2 node-recovery --target-node node-b --interface lo \
	--evidence-dir /evidence --confirm NODE-RECOVERY-PREFLIGHT
grep -q 'does not match local node' "$fixture_dir/output" || fail 'target mismatch produced no actionable denial'
destroy_fixture
pass 'target mismatch is denied'

run_command guard-unsafe-path 2 node-recovery --target-node node-a --interface lo \
	--evidence-dir / --confirm NODE-RECOVERY-PREFLIGHT
grep -q 'evidence directory' "$fixture_dir/output" || fail 'unsafe evidence path produced no actionable denial'
destroy_fixture
pass 'unsafe evidence path is denied'

run_command guard-unknown-command 2 unsupported-command
grep -q 'Unsupported command' "$fixture_dir/output" || fail 'unknown command produced no actionable denial'
destroy_fixture
pass 'dispatcher rejects unknown commands'

printf 'PASS: node-maintenance integration contract completed with no host-network changes\n'
