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

[ "$(uname -s)" = Linux ] || fail "integration requires Linux Docker namespaces; refusing to run on $(uname -s); run the Linux CI workflow or a Linux Docker runner"
"$docker_bin" info >/dev/null 2>&1 || fail "Docker daemon is unavailable; install/start Docker and rerun (no feature skip is allowed)"

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
	>"$runbook_bundle/bundle.yaml"
printf '%s\n' '# Deployment runbook fixture' >"$runbook_bundle/INDEX.md"
docs_output=$(
	"$docker_bin" run --rm --network none --read-only --cap-drop ALL \
		--security-opt no-new-privileges --security-opt seccomp=builtin \
		--mount "type=bind,source=$runbook_bundle,destination=/usr/share/breakglass/runbooks/internal,readonly" \
		--entrypoint /bin/sh "$image" -c '
			test -r /usr/share/breakglass/runbooks/upstream/node-maintenance/README.md
			test -r /usr/share/breakglass/runbooks/upstream/node-maintenance/network-repair.md
			test -r /usr/share/breakglass/runbooks/internal/bundle.yaml
			cat /usr/share/breakglass/runbooks/internal/bundle.yaml
			if printf modified >>/usr/share/breakglass/runbooks/internal/bundle.yaml 2>/dev/null; then
				exit 70
			fi
		' 2>/dev/null
) || fail 'built-in and mounted runbooks were not readable with a read-only downstream bundle'
printf '%s\n' "$docs_output" | grep -q '^schema: breakglass.runbook/v1$' \
	|| fail 'mounted runbook bundle metadata was not discovered through the shared contract'
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
	shift 3
	new_fixture "$label"
	output_file="$fixture_dir/output"
	set +e
	if [ "$capability" = none ]; then
		"$docker_bin" run \
			--name "$container_name" --user 0 --env BREAKGLASS_NODE_NAME=node-a \
			--network none --read-only --cap-drop ALL \
			--security-opt no-new-privileges --security-opt seccomp=builtin \
			--mount "source=$volume_name,destination=/evidence" \
			"$image" "$@" >"$output_file" 2>&1
	else
		[ "$capability" = NET_ADMIN ] || fail "unsupported requested test capability '$capability'"
		"$docker_bin" run \
			--name "$container_name" --user 0 --env BREAKGLASS_NODE_NAME=node-a \
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

run_command preflight 0 none node-recovery --target-node node-a --interface lo \
	--evidence-dir /evidence --confirm NODE-RECOVERY-PREFLIGHT
preflight_bundle=$(bundle_from_output "$fixture_dir/output")
preflight_host_bundle=$(copy_bundle "$fixture_dir/output" "$preflight_bundle")
assert_capture_statuses "$preflight_host_bundle" interface.txt addresses.txt routes.txt neighbors.txt ethtool.txt resolver.txt kernel.txt
grep -q '^exit_status=0$' "$preflight_host_bundle/interface.txt" || fail 'preflight interface probe did not succeed'
grep -q 'command=node-recovery' "$preflight_host_bundle/metadata" || fail 'preflight metadata command mismatch'
grep -q 'target_node=node-a' "$preflight_host_bundle/metadata" || fail 'preflight metadata target mismatch'
grep -q 'interface=lo' "$preflight_host_bundle/metadata" || fail 'preflight metadata interface mismatch'
grep -q 'action=read-only' "$preflight_host_bundle/metadata" || fail 'preflight metadata action mismatch'
grep -Eq '(^|:) lo:' "$preflight_host_bundle/interface.txt" || fail 'preflight did not observe the loopback interface'
grep -q '^Linux ' "$preflight_host_bundle/kernel.txt" || fail 'preflight did not observe Linux kernel evidence'
grep -q '^exit_status=' "$preflight_host_bundle/resolver.txt" || fail 'preflight resolver evidence was not executed'
destroy_fixture
pass 'node-recovery runs in isolated namespace and records evidence'

run_repair() {
	action=$1
	expected_exit=$2
	run_command "repair-$action" "$expected_exit" NET_ADMIN network-repair --target-node node-a --interface lo \
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
run_repair flush-neighbors 0
# loopback has no auto-negotiation; this is the expected real-tool failure
# path and proves that failure evidence is retained rather than hidden.
run_repair restart-autonegotiation nonzero

run_command guard-missing-confirmation 2 none network-repair --target-node node-a --interface lo \
	--action flush-neighbors --evidence-dir /evidence
grep -q 'confirmation' "$fixture_dir/output" || fail 'missing confirmation produced no actionable denial'
destroy_fixture
pass 'missing confirmation is denied'

run_command guard-target-mismatch 2 none node-recovery --target-node node-b --interface lo \
	--evidence-dir /evidence --confirm NODE-RECOVERY-PREFLIGHT
grep -q 'does not match controller-provided node' "$fixture_dir/output" || fail 'target mismatch produced no actionable denial'
destroy_fixture
pass 'target mismatch is denied'

run_command guard-unsafe-path 2 none node-recovery --target-node node-a --interface lo \
	--evidence-dir / --confirm NODE-RECOVERY-PREFLIGHT
grep -q 'evidence directory' "$fixture_dir/output" || fail 'unsafe evidence path produced no actionable denial'
destroy_fixture
pass 'unsafe evidence path is denied'

run_command guard-evidence-symlink 2 none node-recovery --target-node node-a --interface lo \
	--evidence-dir /evidence/escaped --confirm NODE-RECOVERY-PREFLIGHT
grep -q 'symlink\|resolv' "$fixture_dir/output" || fail 'evidence symlink produced no actionable denial'
destroy_fixture
pass 'evidence symlink is denied'

run_command guard-evidence-rename 2 none node-recovery --target-node node-a --interface lo \
	--evidence-dir /evidence/race --confirm NODE-RECOVERY-PREFLIGHT
grep -q 'symlink\|resolv' "$fixture_dir/output" || fail 'evidence rename attack produced no actionable denial'
destroy_fixture
pass 'evidence rename attack is denied'

run_command guard-unknown-command 2 none unsupported-command
grep -q 'Unsupported command' "$fixture_dir/output" || fail 'unknown command produced no actionable denial'
destroy_fixture
pass 'dispatcher rejects unknown commands'

printf 'PASS: node-maintenance integration contract completed with no host-network changes\n'
