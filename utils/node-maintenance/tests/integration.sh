#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

# Integration proof for the node-maintenance image. Every container uses a
# disposable Docker network namespace (--network none) and an anonymous volume
# owned by a dedicated container. The
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
image_owned_id=
container_name=
volume_name=
volume_owner_name=
volume_owner_id=
holder_name=
container_id=
holder_id=

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
	if [ -n "${holder_name:-}" ]; then
		if [ -n "${holder_id:-}" ]; then docker_remove_resource_id "$docker_bin" container "$holder_id" >/dev/null 2>&1 || true; fi
		if [ -n "${holder_id:-}" ] && "$docker_bin" inspect "$holder_id" >/dev/null 2>&1; then
			printf 'FAIL: disposable holder container %s survived cleanup\n' "$holder_name" >&2
			cleanup_failed=1
		fi
	fi
	if [ -n "${container_name:-}" ]; then
		if [ -n "${container_id:-}" ]; then docker_remove_resource_id "$docker_bin" container "$container_id" >/dev/null 2>&1 || true; fi
		if [ -n "${container_id:-}" ] && "$docker_bin" inspect "$container_id" >/dev/null 2>&1; then
			printf 'FAIL: disposable container %s survived cleanup\n' "$container_name" >&2
			cleanup_failed=1
		fi
	fi
	if [ -n "${volume_owner_id:-}" ]; then
		docker_remove_resource_with_volumes "$docker_bin" container "$volume_owner_id" >/dev/null 2>&1 || true
		if ! remove_captured_volume; then
			printf 'FAIL: disposable volume %s survived cleanup\n' "$volume_name" >&2
			cleanup_failed=1
		fi
	fi
	if [ "$built_image" -eq 1 ] && [ "$image_owned" -eq 1 ] && [ "$keep_image" != 1 ]; then
		docker_remove_image_if_id "$docker_bin" "$image" "$image_owned_id" >/dev/null 2>&1 || true
	fi
	rm -rf "$tmp_dir"
	if [ "$cleanup_failed" -ne 0 ] && [ "$exit_code" -eq 0 ]; then
		exit_code=1
	fi
	exit "$exit_code"
}
trap cleanup EXIT

remove_captured_volume() {
	attempt=0
	while [ "$attempt" -lt 10 ]; do
		"$docker_bin" volume inspect "$volume_name" >/dev/null 2>&1 || return 0
		"$docker_bin" volume rm "$volume_name" >/dev/null 2>&1 || true
		attempt=$((attempt + 1))
		sleep 1
	done
	! "$docker_bin" volume inspect "$volume_name" >/dev/null 2>&1
}

# shellcheck disable=SC1091
. "$root_dir/../../hack/docker-image-ownership.sh"
# shellcheck disable=SC1091
. "$root_dir/../../hack/docker-resource-ownership.sh"

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
	image_owned_id=$("$docker_bin" image inspect --format '{{.Id}}' "$image") || fail "could not capture built image ID"
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
	volume_owner_name="${prefix}-volume-owner-${label}"
	container_id=
	holder_id=
	volume_owner_id=
	fixture_dir="$tmp_dir/$label"
	mkdir -p "$fixture_dir"
	"$docker_bin" run -d --name "$volume_owner_name" --user 0 --network none --read-only --cap-drop ALL \
		--security-opt no-new-privileges --security-opt seccomp=builtin \
		--mount type=volume,destination=/evidence --entrypoint /bin/sh "$image" \
		-c 'while :; do sleep 60; done' >/dev/null || fail "could not create disposable volume owner '$volume_owner_name'"
	volume_owner_id=$(docker_capture_resource_id "$docker_bin" container "$volume_owner_name") || {
		"$docker_bin" rm -fv "$volume_owner_name" >/dev/null 2>&1 || true
		fail "could not capture volume owner ID for '$volume_owner_name'"
	}
	volume_name=$("$docker_bin" inspect --format '{{range .Mounts}}{{if eq .Destination "/evidence"}}{{.Name}}{{end}}{{end}}' "$volume_owner_id") || fail "could not resolve anonymous volume for '$volume_owner_name'"
	[ -n "$volume_name" ] || fail "volume owner '$volume_owner_name' did not expose an anonymous volume"
	case "$label" in
		stale-temporary-recovery)
			# A constrained production container has no CHOWN capability. Seed the
			# foreign-owned control first with an explicitly privileged, disposable
			# setup container, then let the real image prove it preserves that file.
			"$docker_bin" run --rm --user 0 --network none --cap-drop ALL --cap-add CHOWN \
				--mount "source=$volume_name,destination=/evidence" --entrypoint /bin/sh "$image" \
				-c 'mkdir -m 0700 /evidence/child; printf foreign >/evidence/.evidence-0000000000000000000000000000000000000000000000000000000000000000-write.foreign; chown 65534 /evidence/.evidence-0000000000000000000000000000000000000000000000000000000000000000-write.foreign' \
				|| fail 'could not seed the foreign-owned stale-candidate fixture'
			;;
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
	if [ -n "${holder_name:-}" ]; then
		if [ -n "${holder_id:-}" ]; then docker_remove_resource_id "$docker_bin" container "$holder_id" >/dev/null 2>&1 || true; fi
		if [ -n "${holder_id:-}" ] && "$docker_bin" inspect "$holder_id" >/dev/null 2>&1; then
			fail "disposable holder container '$holder_name' survived cleanup"
		fi
	fi
	if [ -n "${container_id:-}" ]; then docker_remove_resource_id "$docker_bin" container "$container_id" >/dev/null 2>&1 || true; fi
	if [ -n "${container_id:-}" ] && "$docker_bin" inspect "$container_id" >/dev/null 2>&1; then
		fail "disposable container '$container_name' survived cleanup"
	fi
	docker_remove_resource_with_volumes "$docker_bin" container "$volume_owner_id" >/dev/null || fail "cleanup failed for volume '$volume_name'"
	remove_captured_volume || fail "cleanup failed for volume '$volume_name'"
	container_name=
	container_id=
	volume_name=
	volume_owner_name=
	volume_owner_id=
	holder_name=
	holder_id=
}

approved_network_request() {
	[ "$1" = network-repair ] || { printf '%s' not-a-network-repair; return; }
	shift
	target='' interface='' action='' neighbor='' bridge='' mac='' vlan='' confirmation=''
	while [ "$#" -gt 0 ]; do
		case "$1" in
			--target-node) target=$2; shift 2 ;;
			--interface) interface=$2; shift 2 ;;
			--action) action=$2; shift 2 ;;
			--neighbor-address) neighbor=$2; shift 2 ;;
			--bridge) bridge=$2; shift 2 ;;
			--entry-mac) mac=$2; shift 2 ;;
			--vlan) vlan=$2; shift 2 ;;
			--confirm) confirmation=$2; shift 2 ;;
			--evidence-dir) shift 2 ;;
			*) shift ;;
		esac
	done
	printf 'target_node=%s&interface=%s&action=%s&neighbor_address=%s&bridge=%s&entry_mac=%s&vlan=%s&confirmation=%s' \
		"$target" "$interface" "$action" "$neighbor" "$bridge" "$mac" "$vlan" "$confirmation"
}

run_command() {
	label=$1
	expected_exit=$2
	capability=$3
	approved_action=$4
	shift 4
	approved_request=$(approved_network_request "$@")
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
			--env BREAKGLASS_APPROVED_NETWORK_REQUEST="$approved_request" \
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
			--env BREAKGLASS_APPROVED_NETWORK_REQUEST="$approved_request" \
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
	if [ -z "${container_id:-}" ] && [ "$name" = "${container_name:-}" ]; then
		container_id=$(docker_capture_resource_id "$docker_bin" container "$name") || fail "could not capture immutable ID for '$name'"
	fi
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
	bundle=$(sed -n \
		-e 's|.*Evidence: \(/evidence/[^[:space:])]*\)$|\1|p' \
		-e 's|.*(evidence: \(/evidence/[^[:space:])]*\))$|\1|p' \
		"$output_file" | tail -n 1)
	case "$bundle" in
		/evidence/*) ;;
		*) fail "output did not contain a safe evidence bundle path: '$bundle'" ;;
	esac
	bundle_suffix=${bundle#/evidence/}
	case "$bundle_suffix" in
		''|/*|*/|*//*|*/*/*|*[!A-Za-z0-9_./-]*)
			fail "output did not contain a canonical evidence bundle path: '$bundle'"
			;;
	esac
	bundle_ifs=$IFS
	IFS=/
	# shellcheck disable=SC2086
	set -- $bundle_suffix
	IFS=$bundle_ifs
	for bundle_component do
		case "$bundle_component" in
			''|.|..|*[!A-Za-z0-9_.-]*)
				fail "output did not contain a canonical evidence bundle path: '$bundle'"
				;;
		esac
	done
	printf '%s\n' "$bundle"
}

assert_bundle_from_output_formats() {
	expected_bundle=/evidence/network-repair-20260828T052000Z-ABC123
	success_output="$tmp_dir/success-evidence-output"
	failure_output="$tmp_dir/failure-evidence-output"
	printf 'Target: node-a Interface: eth0 Action: link-cycle Evidence: %s\nRepair completed; inspect before/after evidence at %s\n' \
		"$expected_bundle" "$expected_bundle" >"$success_output"
	printf 'node-maintenance: failed (evidence: %s)\n' "$expected_bundle" >"$failure_output"
	[ "$(bundle_from_output "$success_output")" = "$expected_bundle" ] \
		|| fail 'bundle parser did not accept the success Evidence format'
	[ "$(bundle_from_output "$failure_output")" = "$expected_bundle" ] \
		|| fail 'bundle parser did not strip punctuation from parenthesized evidence'
	for invalid_suffix in ../etc a/../../etc '' ./bundle a//bundle a/b/c 'bundle?'; do
		invalid_output="$tmp_dir/invalid-evidence-output"
		printf 'node-maintenance: failed (evidence: /evidence/%s)\n' "$invalid_suffix" >"$invalid_output"
		if (bundle_from_output "$invalid_output" >/dev/null 2>&1); then
			fail "bundle parser accepted noncanonical evidence path '/evidence/$invalid_suffix'"
		fi
	done
	pass 'bundle parser accepts valid formats and rejects noncanonical evidence paths'
}

assert_bundle_from_output_formats

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

new_fixture final-event-quota
set +e
# Exercise the image-owned atomic event writer against an actual mounted volume
# already at its fixed quota. The seed event occupies one filesystem block; the
# completion event would require a second block, so a failure must leave the
# original JSON record byte-for-byte intact and no candidate behind.
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
		operation_id=quota-operation
		recording_id=quota-recording
		target_node=node-a
		printf "{\"event\":\"seed\",\"padding\":\"" >"$bundle/events.jsonl"
		head -c 3900 /dev/zero | tr "\000" p >>"$bundle/events.jsonl"
		printf "\"}\n" >>"$bundle/events.jsonl"
		: >"$bundle/fill"
		maximum_kib=$((evidence_max_bytes / 1024))
		while [ "$(du -sk "$bundle" | awk "NR == 1 { print \$1 }")" -lt "$maximum_kib" ]; do
			dd if=/dev/zero of="$bundle/fill" bs=1024 count=1 oflag=append conv=notrunc status=none
		done
		[ "$(du -sk "$bundle" | awk "NR == 1 { print \$1 }")" -eq "$maximum_kib" ]
		before=$(sha256sum "$bundle/events.jsonl")
		set +e
		(record_event operation-completed succeeded)
		status=$?
		set -e
		[ "$status" -eq 2 ]
		after=$(sha256sum "$bundle/events.jsonl")
		[ "$before" = "$after" ]
		[ "$(wc -l <"$bundle/events.jsonl" | tr -d " ")" -eq 1 ]
		[ "$(du -sk "$bundle" | awk "NR == 1 { print \$1 }")" -eq "$maximum_kib" ]
		test -z "$(find /evidence -maxdepth 1 \( -name ".evidence-*" -o -name ".capture.*" \) -print)"
	' >"$fixture_dir/output" 2>&1
quota_event_status=$?
set -e
cat "$fixture_dir/output"
assert_container_security "$container_name" none
[ "$quota_event_status" -eq 0 ] || fail 'full evidence bundle permitted a partial completion event or left a candidate behind'
destroy_fixture
pass 'full evidence bundle rejects final event atomically without corruption or temporary-file leakage'

new_fixture near-quota-event-append
set +e
# A retained one-block headroom must permit the same atomic replacement path:
# the completed event remains in the initial events.jsonl allocation and the
# final bundle remains within the documented 384 KiB quota.
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
		operation_id=quota-operation
		recording_id=quota-recording
		target_node=node-a
		printf "{\"event\":\"seed\"}\n" >"$bundle/events.jsonl"
		: >"$bundle/fill"
		maximum_kib=$((evidence_max_bytes / 1024))
		target_kib=$((maximum_kib - 4))
		while [ "$(du -sk "$bundle" | awk "NR == 1 { print \$1 }")" -lt "$target_kib" ]; do
			dd if=/dev/zero of="$bundle/fill" bs=1024 count=1 oflag=append conv=notrunc status=none
		done
		[ "$(du -sk "$bundle" | awk "NR == 1 { print \$1 }")" -eq "$target_kib" ]
		record_event operation-completed succeeded
		[ "$(wc -l <"$bundle/events.jsonl" | tr -d " ")" -eq 2 ]
		[ "$(du -sk "$bundle" | awk "NR == 1 { print \$1 }")" -le "$maximum_kib" ]
		test -z "$(find /evidence -maxdepth 1 \( -name ".evidence-*" -o -name ".capture.*" \) -print)"
	' >"$fixture_dir/output" 2>&1
near_quota_status=$?
set -e
cat "$fixture_dir/output"
assert_container_security "$container_name" none
[ "$near_quota_status" -eq 0 ] || fail 'near-quota event append did not atomically preserve the evidence budget'
destroy_fixture
pass 'near-quota event append succeeds through the atomic quota-checked path'

new_fixture stale-temporary-recovery
set +e
# Seed only helper-shaped files, including a FIFO, in both allowed evidence
# locations. A fresh operation must acquire the volume-root lock first and then
# recover those stale candidates without touching the committed lock record.
# shellcheck disable=SC2016
"$docker_bin" run \
	--name "$container_name" --user 0 --network none --read-only --cap-drop ALL \
	--security-opt no-new-privileges --security-opt seccomp=builtin \
	--mount "source=$volume_name,destination=/evidence" \
	--entrypoint /bin/sh "$image" -c '
		set -eu
		. /usr/local/libexec/node-maintenance/common.sh
		printf orphan >/evidence/.capture-0000000000000000000000000000000000000000000000000000000000000000.orphan
		printf orphan >/evidence/child/.evidence-0000000000000000000000000000000000000000000000000000000000000000-write.orphan
		mkfifo -m 0600 /evidence/child/.capture-0000000000000000000000000000000000000000000000000000000000000000-fifo.orphan
		printf legacy >/evidence/child/.capture-status.legacy
		mkdir -m 0700 /evidence/child/completed-bundle
		printf complete >/evidence/child/completed-bundle/.evidence-0000000000000000000000000000000000000000000000000000000000000000-write.complete
		EVIDENCE_DIR=/evidence/child
		operation_id=stale-operation
		recording_id=stale-recording
		operation_digest=$(sha256_text stale-operation)
		prepare_evidence_dir "$EVIDENCE_DIR"
		acquire_operation_lock "$EVIDENCE_DIR" "$operation_digest"
		cleanup_evidence_temporary_candidates
		test ! -e /evidence/.capture-0000000000000000000000000000000000000000000000000000000000000000.orphan
		test ! -e /evidence/child/.evidence-0000000000000000000000000000000000000000000000000000000000000000-write.orphan
		test ! -e /evidence/child/.capture-0000000000000000000000000000000000000000000000000000000000000000-fifo.orphan
		test -f /evidence/child/.capture-status.legacy
		test "$(cat /evidence/.evidence-0000000000000000000000000000000000000000000000000000000000000000-write.foreign)" = foreign
		test "$(stat -c %u /evidence/.evidence-0000000000000000000000000000000000000000000000000000000000000000-write.foreign)" = 65534
		test "$(cat /evidence/child/completed-bundle/.evidence-0000000000000000000000000000000000000000000000000000000000000000-write.complete)" = complete
		test -f /evidence/.node-maintenance-operation.lock
		release_operation_lock
	' >"$fixture_dir/output" 2>&1
stale_status=$?
set -e
cat "$fixture_dir/output"
assert_container_security "$container_name" none
[ "$stale_status" -eq 0 ] || fail 'stale helper candidates were not recovered under the volume-root lock'
destroy_fixture
pass 'stale evidence candidates are recovered across safe child directories without deleting the lock record'

new_fixture final-metadata-quota
set +e
# Metadata replacement must use the same final-size check as events: a full
# bundle keeps the prior complete metadata file and removes its candidate.
# shellcheck disable=SC2016
"$docker_bin" run \
	--name "$container_name" --user 0 --network none --read-only --cap-drop ALL \
	--security-opt no-new-privileges --security-opt seccomp=builtin \
	--mount "source=$volume_name,destination=/evidence" \
	--entrypoint /bin/sh "$image" -c '
		set -eu
		. /usr/local/libexec/node-maintenance/common.sh
		EVIDENCE_DIR=/evidence
		bundle=/evidence/quota
		mkdir -m 0700 "$bundle"
		operation_id=quota-operation
		recording_id=quota-recording
		operation_artifact_id=$(sha256_text "$operation_id")
		tuple_digest=$(sha256_text quota-operation)
		acquire_operation_lock /evidence "$tuple_digest"
		trap '\''cleanup_evidence_temporary_candidates || true; release_operation_lock || true'\'' EXIT
		printf seed >"$bundle/metadata"
		# Measure an actual filesystem allocation boundary. The payload passed to
		# append_evidence is grown until the exact candidate is larger on disk than
		# the current metadata, avoiding a filesystem-block-size assumption.
		payload_file=/evidence/append-payload
		: >"$payload_file"
		output_kib=$(du -sk "$bundle/metadata" | awk "NR == 1 { print \$1 }")
		measure_candidate="$EVIDENCE_DIR/.evidence-$operation_artifact_id-append.measure"
		while :; do
			rm -f "$measure_candidate"
			cat "$bundle/metadata" "$payload_file" >"$measure_candidate"
			candidate_kib=$(du -sk "$measure_candidate" | awk "NR == 1 { print \$1 }")
			[ "$candidate_kib" -gt "$output_kib" ] && break
			printf x >>"$payload_file"
		done
		rm -f "$measure_candidate"
		maximum_kib=$((evidence_max_bytes / 1024))
		: >"$bundle/fill"
		while [ "$(du -sk "$bundle" | awk "NR == 1 { print \$1 }")" -lt "$maximum_kib" ]; do
			dd if=/dev/zero of="$bundle/fill" bs=1024 count=1 oflag=append conv=notrunc status=none
		done
		before=$(sha256sum "$bundle/metadata")
		# append_evidence is deliberately run as the terminal stage of a pipeline.
		# Use an exec shell for the expected fatal error: a shell function on the
		# right side can run in the calling shell and invoke its EXIT trap. The
		# external shell has no caller trap, while the assertion below proves the
		# parent still holds its flock after the failed atomic replacement.
		set +e
		helper=/evidence/append-from-pipe
		cat >"$helper" <<EOF
#!/bin/sh
set -eu
. /usr/local/libexec/node-maintenance/common.sh
EVIDENCE_DIR=/evidence
bundle=/evidence/quota
operation_id=quota-operation
recording_id=quota-recording
operation_artifact_id=$(sha256_text "$operation_id")
append_evidence "\$1"
EOF
		chmod 0700 "$helper"
		cat "$payload_file" | "$helper" "$bundle/metadata"
		status=$?
		[ "$status" -eq 2 ]
		rm -f "$helper"
		flock -n /evidence/.node-maintenance-operation.lock true
		lock_status=$?
		set -e
		[ "$lock_status" -ne 0 ]
		after=$(sha256sum "$bundle/metadata")
		[ "$before" = "$after" ]
		[ "$(du -sk "$bundle" | awk "NR == 1 { print \$1 }")" -eq "$maximum_kib" ]
		rm -f "$payload_file"
		test -z "$(find /evidence -maxdepth 1 \( -name ".evidence-*" -o -name ".capture-*" -o -name ".capture.*" \) -print)"
	' >"$fixture_dir/output" 2>&1
metadata_quota_status=$?
set -e
cat "$fixture_dir/output"
assert_container_security "$container_name" none
[ "$metadata_quota_status" -eq 0 ] || fail 'full bundle corrupted metadata or leaked its replacement candidate'
destroy_fixture
pass 'full bundle rejects metadata replacement atomically without corruption or leakage'

new_fixture capture-existing-destination
set +e
# A full bundle must reject a large replacement while preserving the existing
# destination; the capture path is intentionally exercised, not just its file
# existence.
# shellcheck disable=SC2016
"$docker_bin" run \
	--name "$container_name" --user 0 --network none --read-only --cap-drop ALL \
	--security-opt no-new-privileges --security-opt seccomp=builtin \
	--mount "source=$volume_name,destination=/evidence" \
	--entrypoint /bin/sh "$image" -c '
		set -eu
		. /usr/local/libexec/node-maintenance/common.sh
		EVIDENCE_DIR=/evidence
		bundle=/evidence/quota
		mkdir -m 0700 "$bundle"
		operation_id=quota-operation
		recording_id=quota-recording
		tuple_digest=$(sha256_text quota-operation)
		acquire_operation_lock /evidence "$tuple_digest"
		trap '\''cleanup_evidence_temporary_candidates || true; release_operation_lock || true'\'' EXIT
		printf old-destination >"$bundle/output"
		maximum_kib=$((evidence_max_bytes / 1024))
		: >"$bundle/fill"
		while [ "$(du -sk "$bundle" | awk "NR == 1 { print \$1 }")" -lt "$maximum_kib" ]; do
			dd if=/dev/zero of="$bundle/fill" bs=1024 count=1 oflag=append conv=notrunc status=none
		done
		before=$(sha256sum "$bundle/output")
		set +e
		(capture "$bundle/output" awk '\''BEGIN { for (i = 0; i < 40000; i++) printf "x" }'\'')
		status=$?
		set -e
		[ "$status" -eq 2 ]
		after=$(sha256sum "$bundle/output")
		[ "$before" = "$after" ]
		test "$(cat "$bundle/output")" = old-destination
		test -z "$(find /evidence -maxdepth 1 \( -name ".evidence-*" -o -name ".capture-*" -o -name ".capture.*" \) -print)"
	' >"$fixture_dir/output" 2>&1
capture_full_status=$?
set -e
cat "$fixture_dir/output"
assert_container_security "$container_name" none
[ "$capture_full_status" -eq 0 ] || fail 'full bundle corrupted an existing capture destination or leaked a candidate'
destroy_fixture
pass 'full bundle preserves an existing capture destination after atomic rejection'

new_fixture capture-near-destination
set +e
# With one filesystem-block of logical headroom, replacing an existing capture
# succeeds and the committed content is the new bounded result.
# shellcheck disable=SC2016
"$docker_bin" run \
	--name "$container_name" --user 0 --network none --read-only --cap-drop ALL \
	--security-opt no-new-privileges --security-opt seccomp=builtin \
	--mount "source=$volume_name,destination=/evidence" \
	--entrypoint /bin/sh "$image" -c '
		set -eu
		. /usr/local/libexec/node-maintenance/common.sh
		EVIDENCE_DIR=/evidence
		bundle=/evidence/quota
		mkdir -m 0700 "$bundle"
		operation_id=quota-operation
		recording_id=quota-recording
		tuple_digest=$(sha256_text quota-operation)
		acquire_operation_lock /evidence "$tuple_digest"
		trap '\''cleanup_evidence_temporary_candidates || true; release_operation_lock || true'\'' EXIT
		printf old-destination >"$bundle/output"
		maximum_kib=$((evidence_max_bytes / 1024))
		target_kib=$((maximum_kib - 4))
		: >"$bundle/fill"
		while [ "$(du -sk "$bundle" | awk "NR == 1 { print \$1 }")" -lt "$target_kib" ]; do
			dd if=/dev/zero of="$bundle/fill" bs=1024 count=1 oflag=append conv=notrunc status=none
		done
		capture "$bundle/output" awk '\''BEGIN { print "replacement" }'\''
		grep -q "^replacement" "$bundle/output"
		grep -q "exit_status=0" "$bundle/output"
		[ "$(du -sk "$bundle" | awk "NR == 1 { print \$1 }")" -le "$maximum_kib" ]
		test -z "$(find /evidence -maxdepth 1 \( -name ".evidence-*" -o -name ".capture-*" -o -name ".capture.*" \) -print)"
	' >"$fixture_dir/output" 2>&1
capture_near_status=$?
set -e
cat "$fixture_dir/output"
assert_container_security "$container_name" none
[ "$capture_near_status" -eq 0 ] || fail 'near-quota capture replacement did not commit within the final quota'
destroy_fixture
pass 'near-quota capture replacement commits atomically within the evidence quota'

new_fixture injected-evidence-failures
set +e
# Inject setup and trailer failures after lock acquisition. The production EXIT
# trap must remove the partially-created candidates before the container exits.
# shellcheck disable=SC2016
"$docker_bin" run \
	--name "$container_name" --user 0 --network none --read-only --cap-drop ALL \
	--security-opt no-new-privileges --security-opt seccomp=builtin \
	--mount "source=$volume_name,destination=/evidence" \
	--entrypoint /bin/sh "$image" -c '
		set -eu
		. /usr/local/libexec/node-maintenance/common.sh
		EVIDENCE_DIR=/evidence
		operation_id=quota-operation
		recording_id=quota-recording
		bundle=/evidence/quota
		mkdir -m 0700 "$bundle"
		tuple_digest=$(sha256_text quota-operation)
		operation_artifact_id=$(sha256_text "$operation_id")
		acquire_operation_lock /evidence "$tuple_digest"
		trap '\''cleanup_evidence_temporary_candidates || true; release_operation_lock || true'\'' EXIT
		mktemp() {
			case "$1" in "$EVIDENCE_DIR/.capture-$operation_artifact_id-status.XXXXXX") return 1 ;; esac
			command mktemp "$@"
		}
		capture "$bundle/setup" awk '\''BEGIN { print "setup" }'\'' || true
	' >"$fixture_dir/setup-output" 2>&1
setup_status=$?
set -e
cat "$fixture_dir/setup-output"
assert_container_security "$container_name" none
[ "$setup_status" -eq 2 ] || fail 'injected capture setup failure returned an unexpected status'
# shellcheck disable=SC2016
if "$docker_bin" run --rm --network none --read-only --cap-drop ALL \
	--security-opt no-new-privileges --security-opt seccomp=builtin \
	--mount "source=$volume_name,destination=/evidence" --entrypoint /bin/sh "$image" -c \
	'test ! -e /evidence/quota/setup && test -z "$(find /evidence -maxdepth 1 \( -name ".evidence-*" -o -name ".capture-*" -o -name ".capture.*" \) -print)"' ; then
	:
else
	fail 'injected capture setup failure leaked a temporary candidate'
fi
docker_remove_resource_id "$docker_bin" container "$container_id" >/dev/null || fail 'could not remove setup-failure fixture container'
container_name=
container_id=
set +e
# shellcheck disable=SC2016
"$docker_bin" run \
	--name "${prefix}-injected-trailer" --user 0 --network none --read-only --cap-drop ALL \
	--security-opt no-new-privileges --security-opt seccomp=builtin \
	--mount "source=$volume_name,destination=/evidence" \
	--entrypoint /bin/sh "$image" -c '
		set -eu
		. /usr/local/libexec/node-maintenance/common.sh
		EVIDENCE_DIR=/evidence
		operation_id=quota-operation
		recording_id=quota-recording
		bundle=/evidence/quota
		mkdir -m 0700 "$bundle" 2>/dev/null || [ -d "$bundle" ]
		tuple_digest=$(sha256_text quota-operation)
		acquire_operation_lock /evidence "$tuple_digest"
		trap '\''cleanup_evidence_temporary_candidates || true; release_operation_lock || true'\'' EXIT
		printf() {
			case "$1" in *exit_status=*) return 1 ;; esac
			command printf "$@"
		}
		capture "$bundle/trailer" awk '\''BEGIN { print "trailer" }'\'' || true
	' >"$fixture_dir/trailer-output" 2>&1
trailer_status=$?
set -e
cat "$fixture_dir/trailer-output"
container_name="${prefix}-injected-trailer"
assert_container_security "$container_name" none
[ "$trailer_status" -eq 2 ] || fail 'injected capture trailer failure returned an unexpected status'
# shellcheck disable=SC2016
if "$docker_bin" run --rm --network none --read-only --cap-drop ALL \
	--security-opt no-new-privileges --security-opt seccomp=builtin \
	--mount "source=$volume_name,destination=/evidence" --entrypoint /bin/sh "$image" -c \
	'test ! -e /evidence/quota/trailer && test -z "$(find /evidence -maxdepth 1 \( -name ".evidence-*" -o -name ".capture-*" -o -name ".capture.*" \) -print)"' ; then
	:
else
	fail 'injected capture trailer failure leaked a temporary candidate'
fi
docker_remove_resource_id "$docker_bin" container "$container_id" >/dev/null || fail 'could not remove trailer-failure fixture container'
container_name=
container_id=
set +e
# shellcheck disable=SC2016
"$docker_bin" run \
	--name "${prefix}-injected-sync" --user 0 --network none --read-only --cap-drop ALL \
	--security-opt no-new-privileges --security-opt seccomp=builtin \
	--mount "source=$volume_name,destination=/evidence" \
	--entrypoint /bin/sh "$image" -c '
		set -eu
		. /usr/local/libexec/node-maintenance/common.sh
		EVIDENCE_DIR=/evidence
		operation_id=quota-operation
		recording_id=quota-recording
		bundle=/evidence/quota
		mkdir -m 0700 "$bundle" 2>/dev/null || [ -d "$bundle" ]
		tuple_digest=$(sha256_text quota-operation)
		acquire_operation_lock /evidence "$tuple_digest"
		trap '\''cleanup_evidence_temporary_candidates || true; release_operation_lock || true'\'' EXIT
		sync() { return 1; }
		capture "$bundle/sync" awk '\''BEGIN { print "sync" }'\'' || true
	' >"$fixture_dir/sync-output" 2>&1
sync_status=$?
set -e
cat "$fixture_dir/sync-output"
container_name="${prefix}-injected-sync"
assert_container_security "$container_name" none
[ "$sync_status" -eq 2 ] || fail 'injected evidence sync failure returned an unexpected status'
# shellcheck disable=SC2016
if "$docker_bin" run --rm --network none --read-only --cap-drop ALL \
	--security-opt no-new-privileges --security-opt seccomp=builtin \
	--mount "source=$volume_name,destination=/evidence" --entrypoint /bin/sh "$image" -c \
	'test ! -e /evidence/quota/sync && test -z "$(find /evidence -maxdepth 1 \( -name ".evidence-*" -o -name ".capture-*" -o -name ".capture.*" \) -print)"' ; then
	:
else
	fail 'injected evidence sync failure leaked a temporary candidate'
fi
destroy_fixture
pass 'injected capture setup, trailer, and sync failures clean partial candidates'

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
	approved_request=$(approved_network_request "$@")
	new_fixture "$label"
	bridge_test_mode=0
	bridge_mount_arg=
	if [ "$label" = guard-fdb-vlan-output-quota ]; then
		bridge_test_mode=1
		bridge_wrapper="$tmp_dir/fake-bridge"
		# The wrapper delegates every normal operation to Alpine's fixed bridge
		# binary. One fixture enables a deliberately oversized show response to
		# prove VLAN preflight consumes only persisted bounded capture output.
		# shellcheck disable=SC2016
		printf '%s\n' \
			'#!/bin/sh' \
			'if [ "${NODE_MAINTENANCE_TEST_BRIDGE_OUTPUT_QUOTA:-0}" = 1 ] && [ "$#" -eq 4 ] && [ "$1" = vlan ] && [ "$2" = show ] && [ "$3" = dev ] && [ "$4" = fdb0 ]; then' \
			'printf "%s\n" "port    vlan ids" "fdb0     100"' \
				'awk '\''BEGIN { for (i = 0; i < 40000; i++) print "oversized" }'\''' \
				'exit 0' \
			'fi' \
			'if [ -x /usr/sbin/bridge ]; then exec /usr/sbin/bridge "$@"; fi' \
			'if [ -x /usr/bin/bridge ]; then exec /usr/bin/bridge "$@"; fi' \
			'if [ -x /sbin/bridge ]; then exec /sbin/bridge "$@"; fi' \
			'exit 127' >"$bridge_wrapper"
		chmod 0555 "$bridge_wrapper"
		bridge_mount_arg="--mount=type=bind,source=$bridge_wrapper,destination=/usr/local/bin/bridge,readonly"
	fi
	output_file="$fixture_dir/output"
	set +e
	"$docker_bin" run \
		--name "$container_name" --user 0 --env BREAKGLASS_NODE_NAME=node-a \
		--env BREAKGLASS_OPERATION_ID="operation-$label" \
		--env BREAKGLASS_RECORDING_ID="recording-$label" \
		--env BREAKGLASS_APPROVAL_ID="approval-$label" \
		--env BREAKGLASS_APPROVED_ACTION="$approved_action" \
		--env BREAKGLASS_APPROVED_NETWORK_REQUEST="$approved_request" \
		--env NODE_MAINTENANCE_TEST_BRIDGE_OUTPUT_QUOTA="$bridge_test_mode" \
		--network none --read-only --cap-drop ALL --cap-add NET_ADMIN \
		--security-opt no-new-privileges --security-opt seccomp=builtin \
		--mount "source=$volume_name,destination=/evidence" \
		${bridge_mount_arg:+"$bridge_mount_arg"} \
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
neighbor_tuple_digest=$(printf '%s' "$approved_request" | sha256sum | awk '{print $1}')
lock_record=$("$docker_bin" run --rm --network none --read-only --cap-drop ALL \
	--security-opt no-new-privileges --security-opt seccomp=builtin \
	--mount "source=$volume_name,destination=/evidence" --entrypoint /bin/cat "$image" \
	/evidence/.node-maintenance-operation.lock) || fail 'could not read persistent operation lock record'
printf '%s\n' "$lock_record" | grep -Fqx "tuple_sha256=$neighbor_tuple_digest" \
	|| fail 'operation lock record was not bound to the exact approved tuple digest'
printf '%s\n' "$lock_record" | grep -Fqx 'approval_id=approval-repair-neighbor-replace' \
	|| fail 'operation lock record omitted the exact approval identity'
destroy_fixture
pass 'neighbor-replace changes only the exact requested entry and binds its lock record to the approval tuple'

# 63 + 1 + 63 + 1 + 63 + 1 + 61 = a real 253-byte RFC 1123 subdomain.
max_node=$(awk 'BEGIN { for (label = 1; label <= 4; label++) { limit = (label == 4 ? 61 : 63); for (i = 0; i < limit; i++) printf "n"; if (label < 4) printf "." } }')
[ "${#max_node}" -eq 253 ] || fail 'maximum Kubernetes node fixture is not 253 bytes'
max_interface=repairport12345
max_neighbor=2001:0db8:0000:0000:ffff:ffff:ffff:ffff
max_tuple="target_node=$max_node&interface=$max_interface&action=neighbor-replace&neighbor_address=$max_neighbor&bridge=&entry_mac=02:00:00:00:00:02&vlan=&confirmation=NETWORK-REPAIR"
[ "${#max_interface}" -eq 15 ] || fail 'maximum-interface fixture is not 15 bytes'
[ "${#max_neighbor}" -eq 39 ] || fail 'maximum-IPv6 fixture is not 39 bytes'
[ "${#max_tuple}" -eq 442 ] || fail 'maximum public network tuple did not match its derived bound'
new_fixture maximum-public-network-tuple
output_file="$fixture_dir/output"
set +e
"$docker_bin" run \
	--name "$container_name" --user 0 --env BREAKGLASS_NODE_NAME="$max_node" \
	--env BREAKGLASS_OPERATION_ID=operation-maximum-public-network-tuple \
	--env BREAKGLASS_RECORDING_ID=recording-maximum-public-network-tuple \
	--env BREAKGLASS_APPROVAL_ID=approval-maximum-public-network-tuple \
	--env BREAKGLASS_APPROVED_ACTION=neighbor-replace \
	--env BREAKGLASS_APPROVED_NETWORK_REQUEST="$max_tuple" \
	--network none --read-only --cap-drop ALL --cap-add NET_ADMIN \
	--security-opt no-new-privileges --security-opt seccomp=builtin \
	--mount "source=$volume_name,destination=/evidence" \
	--entrypoint /bin/sh "$image" -c '
		set -eu
		ip link add repairport12345 type veth peer name repairpeer1234
		ip -6 address add 2001:db8::1/64 dev repairport12345
		ip link set repairport12345 up
		ip link set repairpeer1234 up
		exec /usr/local/bin/node-maintenance "$@"
	' fixture network-repair --target-node "$max_node" --interface "$max_interface" --action neighbor-replace \
	--neighbor-address "$max_neighbor" --entry-mac 02:00:00:00:00:02 \
	--evidence-dir /evidence --confirm NETWORK-REPAIR >"$output_file" 2>&1
max_tuple_status=$?
set -e
cat "$output_file"
assert_container_security "$container_name" NET_ADMIN
[ "$max_tuple_status" -eq 0 ] || fail "maximum public network tuple returned $max_tuple_status"
max_tuple_bundle=$(bundle_from_output "$output_file")
max_tuple_host_bundle=$(copy_bundle "$output_file" "$max_tuple_bundle")
grep -Eq 'lladdr +02:00:00:00:00:02 +REACHABLE' "$max_tuple_host_bundle/after-neighbor-entry.txt" \
	|| fail 'maximum public network tuple did not create its exact IPv6 neighbor entry'
destroy_fixture
pass 'maximum valid node, interface, and action-specific network tuple runs through the public helper'

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

run_network_fixture guard-fdb-vlan-output-quota nonzero bridge-fdb-replace network-repair \
	--target-node node-a --interface fdb0 --bridge br0 --action bridge-fdb-replace \
	--entry-mac 02:00:00:00:01:00 --vlan 100 \
	--evidence-dir /evidence --confirm NETWORK-REPAIR
grep -q 'could not capture VLAN membership' "$fixture_dir/output" \
	|| fail 'oversized VLAN output did not fail closed at bounded capture'
quota_bundle=$(bundle_from_output "$fixture_dir/output")
quota_host_bundle=$(copy_bundle "$fixture_dir/output" "$quota_bundle")
assert_capture_statuses "$quota_host_bundle" before-bridge-vlan.txt
[ "$(wc -c <"$quota_host_bundle/before-bridge-vlan.txt" | tr -d ' ')" -le 32832 ] \
	|| fail 'oversized VLAN evidence exceeded the bounded capture allowance'
grep -q '^capture_result=output-quota-exceeded$' "$quota_host_bundle/before-bridge-vlan.txt" \
	|| fail 'oversized VLAN evidence did not record the quota failure'
[ ! -e "$quota_host_bundle/action-bridge-fdb-replace.txt" ] \
	|| fail 'oversized VLAN output reached the mutating FDB action'
destroy_fixture
pass 'oversized VLAN preflight output is bounded, persisted, and fails closed before mutation'

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

run_network_tuple_mismatch() {
	field=$1
	approved_tuple=$2
	label="guard-approved-tuple-$field"
	new_fixture "$label"
	set +e
	"$docker_bin" run --name "$container_name" --user 0 \
		--env BREAKGLASS_NODE_NAME=node-a \
		--env BREAKGLASS_OPERATION_ID="operation-$label" \
		--env BREAKGLASS_RECORDING_ID="recording-$label" \
		--env BREAKGLASS_APPROVAL_ID="approval-$label" \
		--env BREAKGLASS_APPROVED_ACTION=link-cycle \
		--env BREAKGLASS_APPROVED_NETWORK_REQUEST="$approved_tuple" \
		--network none --read-only --cap-drop ALL \
		--security-opt no-new-privileges --security-opt seccomp=builtin \
		--mount "source=$volume_name,destination=/evidence" \
		"$image" network-repair --target-node node-a --interface lo --action link-cycle \
		--evidence-dir /evidence --confirm NETWORK-REPAIR >"$fixture_dir/output" 2>&1
	mismatch_exit=$?
	set -e
	[ "$mismatch_exit" -eq 2 ] || { cat "$fixture_dir/output"; fail "$field approval mismatch returned $mismatch_exit, expected 2"; }
	grep -q 'controller-approved network request does not exactly match' "$fixture_dir/output" \
		|| fail "$field approval mismatch produced no exact-tuple denial"
	assert_container_security "$container_name" none
	destroy_fixture
}

run_network_tuple_mismatch target-node \
	'target_node=node-b&interface=lo&action=link-cycle&neighbor_address=&bridge=&entry_mac=&vlan=&confirmation=NETWORK-REPAIR'
run_network_tuple_mismatch interface \
	'target_node=node-a&interface=eth0&action=link-cycle&neighbor_address=&bridge=&entry_mac=&vlan=&confirmation=NETWORK-REPAIR'
run_network_tuple_mismatch action \
	'target_node=node-a&interface=lo&action=restart-autonegotiation&neighbor_address=&bridge=&entry_mac=&vlan=&confirmation=NETWORK-REPAIR'
run_network_tuple_mismatch neighbor-address \
	'target_node=node-a&interface=lo&action=link-cycle&neighbor_address=192.0.2.9&bridge=&entry_mac=&vlan=&confirmation=NETWORK-REPAIR'
run_network_tuple_mismatch bridge \
	'target_node=node-a&interface=lo&action=link-cycle&neighbor_address=&bridge=br0&entry_mac=&vlan=&confirmation=NETWORK-REPAIR'
run_network_tuple_mismatch entry-mac \
	'target_node=node-a&interface=lo&action=link-cycle&neighbor_address=&bridge=&entry_mac=02:00:00:00:00:09&vlan=&confirmation=NETWORK-REPAIR'
run_network_tuple_mismatch vlan \
	'target_node=node-a&interface=lo&action=link-cycle&neighbor_address=&bridge=&entry_mac=&vlan=100&confirmation=NETWORK-REPAIR'
run_network_tuple_mismatch confirmation \
	'target_node=node-a&interface=lo&action=link-cycle&neighbor_address=&bridge=&entry_mac=&vlan=&confirmation=DIFFERENT'
pass 'every field in the exact approved network tuple has an independent mismatch denial'

# The kernel-held flock is authoritative for liveness. An active holder remains
# exclusive even when its informational timestamp is older than the removed
# 300-second lease threshold; SIGKILL releases it immediately.
new_fixture guard-operation-lock
holder_name="${container_name}-holder"
holder_tuple='target_node=node-a&interface=lo&action=link-cycle&neighbor_address=&bridge=&entry_mac=&vlan=&confirmation=NETWORK-REPAIR'
holder_digest=$(printf '%s' "$holder_tuple" | sha256sum | awk '{print $1}')
# The isolated container, not this harness, expands controller values.
# shellcheck disable=SC2016
"$docker_bin" run -d --name "$holder_name" --user 0 \
	--env BREAKGLASS_OPERATION_ID=operation-guard-operation-lock \
	--env BREAKGLASS_RECORDING_ID=recording-guard-operation-lock \
	--env BREAKGLASS_APPROVAL_ID=approval-guard-operation-lock \
	--env BREAKGLASS_TUPLE_DIGEST="$holder_digest" \
	--network none --read-only --cap-drop ALL \
	--security-opt no-new-privileges --security-opt seccomp=builtin \
	--mount "source=$volume_name,destination=/evidence" --entrypoint /bin/sh "$image" \
	-c '. /usr/local/libexec/node-maintenance/common.sh; mkdir -m 0700 /evidence/holder; EVIDENCE_DIR=/evidence/holder; operation_id=$BREAKGLASS_OPERATION_ID; recording_id=$BREAKGLASS_RECORDING_ID; approval_id=$BREAKGLASS_APPROVAL_ID; acquire_operation_lock /evidence/holder "$BREAKGLASS_TUPLE_DIGEST"; : >/evidence/holder-ready; while :; do sleep 60; done' \
	>/dev/null || fail 'could not start flock holder'
holder_id=$(docker_capture_resource_id "$docker_bin" container "$holder_name") || fail 'could not capture flock holder ID'
holder_ready=false
attempt=0
while [ "$attempt" -lt 20 ]; do
	if "$docker_bin" run --rm --network none --read-only --cap-drop ALL \
		--security-opt no-new-privileges --security-opt seccomp=builtin \
		--mount "source=$volume_name,destination=/evidence" --entrypoint /bin/sh "$image" \
		-c 'test -f /evidence/holder-ready'; then
		holder_ready=true
		break
	fi
	attempt=$((attempt + 1))
done
[ "$holder_ready" = true ] || fail 'flock holder did not report readiness'
# The isolated container expands its positional tuple digest.
# shellcheck disable=SC2016
"$docker_bin" run --rm --network none --read-only --cap-drop ALL \
	--security-opt no-new-privileges --security-opt seccomp=builtin \
	--mount "source=$volume_name,destination=/evidence" --entrypoint /bin/sh "$image" \
	-c 'printf "schema=node-maintenance-lock/v2\noperation_id=operation-guard-operation-lock\nrecording_id=recording-guard-operation-lock\napproval_id=approval-guard-operation-lock\ntuple_sha256=%s\nholder_pid=1\nacquired_epoch=1\n" "$1" >/evidence/.node-maintenance-operation.lock' aged "$holder_digest" \
	|| fail 'could not age active flock record in place'
set +e
"$docker_bin" run --name "$container_name" --user 0 \
	--env BREAKGLASS_NODE_NAME=node-a \
	--env BREAKGLASS_OPERATION_ID=operation-competing-lock \
	--env BREAKGLASS_RECORDING_ID=recording-competing-lock \
	--network none --read-only --cap-drop ALL \
	--security-opt no-new-privileges --security-opt seccomp=builtin \
	--mount "source=$volume_name,destination=/evidence" "$image" node-recovery \
	--target-node node-a --interface lo --evidence-dir /evidence --confirm NODE-RECOVERY-PREFLIGHT \
	>"$fixture_dir/output" 2>&1
active_holder_exit=$?
set -e
[ "$active_holder_exit" -eq 2 ] || { cat "$fixture_dir/output"; fail "active flock competitor returned $active_holder_exit, expected 2"; }
grep -q 'another node-maintenance operation is active' "$fixture_dir/output" \
	|| fail 'aged active holder produced no concurrency denial'
assert_container_security "$container_name" none
	docker_remove_resource_id "$docker_bin" container "$container_id" >/dev/null || fail 'could not remove denied lock competitor'
	container_id=
	"$docker_bin" kill --signal KILL "$holder_id" >/dev/null || fail 'could not SIGKILL flock holder'
	"$docker_bin" wait "$holder_id" >/dev/null 2>&1 || true
	docker_remove_resource_id "$docker_bin" container "$holder_id" >/dev/null || fail 'could not remove killed flock holder'
holder_name=
holder_id=
# A pre-volume-root image used one lock per child. A live legacy descriptor must
# block the new helper after it acquires the volume-root lock, while its
# legacy temporary names remain untouched for operator-led migration.
legacy_holder_name="${prefix}-legacy-holder"
holder_name="$legacy_holder_name"
"$docker_bin" run -d --name "$legacy_holder_name" --user 0 --network none --read-only --cap-drop ALL \
	--security-opt no-new-privileges --security-opt seccomp=builtin \
	--mount "source=$volume_name,destination=/evidence" --entrypoint /bin/sh "$image" \
	-c 'mkdir -m 0700 /evidence/legacy; exec 8>>/evidence/legacy/.node-maintenance-operation.lock; flock -n 8 || exit 71; printf legacy >/evidence/legacy/.capture-status.legacy; printf legacy >/evidence/legacy-ready; while :; do sleep 60; done' \
	>/dev/null || fail 'could not start legacy flock holder'
holder_id=$(docker_capture_resource_id "$docker_bin" container "$holder_name") || fail 'could not capture legacy flock holder ID'
legacy_ready=false
attempt=0
while [ "$attempt" -lt 20 ]; do
	if "$docker_bin" run --rm --network none --read-only --cap-drop ALL \
		--security-opt no-new-privileges --security-opt seccomp=builtin \
		--mount "source=$volume_name,destination=/evidence" --entrypoint /bin/sh "$image" \
		-c 'test -f /evidence/legacy-ready'; then
		legacy_ready=true
		break
	fi
	attempt=$((attempt + 1))
done
[ "$legacy_ready" = true ] || fail 'legacy flock holder did not report readiness'
set +e
"$docker_bin" run --name "$container_name" --user 0 \
	--env BREAKGLASS_NODE_NAME=node-a \
	--env BREAKGLASS_OPERATION_ID=operation-legacy-competitor \
	--env BREAKGLASS_RECORDING_ID=recording-legacy-competitor \
	--network none --read-only --cap-drop ALL \
	--security-opt no-new-privileges --security-opt seccomp=builtin \
	--mount "source=$volume_name,destination=/evidence" "$image" node-recovery \
	--target-node node-a --interface lo --evidence-dir /evidence/legacy --confirm NODE-RECOVERY-PREFLIGHT \
	>"$fixture_dir/legacy-output" 2>&1
legacy_competitor_exit=$?
set -e
[ "$legacy_competitor_exit" -eq 2 ] || { cat "$fixture_dir/legacy-output"; fail 'legacy lock competitor returned an unexpected status'; }
# shellcheck disable=SC2016
if ! "$docker_bin" run --rm --network none --read-only --cap-drop ALL \
	--security-opt no-new-privileges --security-opt seccomp=builtin \
	--mount "source=$volume_name,destination=/evidence" --entrypoint /bin/sh "$image" -c \
	'test "$(cat /evidence/legacy/.capture-status.legacy)" = legacy'; then
	fail 'legacy writer artifact was altered while the mixed-version competitor was denied'
fi
assert_container_security "$container_name" none
	docker_remove_resource_id "$docker_bin" container "$container_id" >/dev/null || fail 'could not remove legacy lock competitor'
	"$docker_bin" kill --signal KILL "$holder_id" >/dev/null || fail 'could not SIGKILL legacy flock holder'
	"$docker_bin" wait "$holder_id" >/dev/null 2>&1 || true
	docker_remove_resource_id "$docker_bin" container "$holder_id" >/dev/null || fail 'could not remove legacy flock holder'
holder_name=
holder_id=
set +e
"$docker_bin" run --name "$container_name" --user 0 \
	--env BREAKGLASS_NODE_NAME=node-a \
	--env BREAKGLASS_OPERATION_ID=operation-after-crash \
	--env BREAKGLASS_RECORDING_ID=recording-after-crash \
	--network none --read-only --cap-drop ALL \
	--security-opt no-new-privileges --security-opt seccomp=builtin \
	--mount "source=$volume_name,destination=/evidence" "$image" node-recovery \
	--target-node node-a --interface lo --evidence-dir /evidence --confirm NODE-RECOVERY-PREFLIGHT \
	>"$fixture_dir/retry-output" 2>&1
crash_retry_exit=$?
set -e
[ "$crash_retry_exit" -eq 0 ] || { cat "$fixture_dir/retry-output"; fail 'flock was not released immediately after SIGKILL'; }
assert_container_security "$container_name" none
destroy_fixture
pass 'kernel flock denies an arbitrarily old live holder and releases immediately on SIGKILL'

new_fixture guard-kernel-interface-identities
# The isolated container expands only its literal namespace fixture values.
# shellcheck disable=SC2016
identity_output=$("$docker_bin" run --rm --user 0 --network none --read-only --cap-drop ALL --cap-add NET_ADMIN \
	--security-opt no-new-privileges --security-opt seccomp=builtin --entrypoint /bin/sh "$image" -c '
		set -eu
		ip link add race0 type veth peer name racepeer0
		ip address add 198.51.100.1/24 dev race0
		ip link set race0 up
		original_ifindex=$(cat /sys/class/net/race0/ifindex)
		ip link set race0 name pinned-original
		ip link add race0 type veth peer name racepeer1
		ip link set race0 up
		network-action neighbor-replace "$original_ifindex" 4 198.51.100.2 02:00:00:00:00:22
		ip neigh show to 198.51.100.2 dev pinned-original | grep -q "02:00:00:00:00:22"
		if ip neigh show to 198.51.100.2 dev race0 | grep -q "02:00:00:00:00:22"; then exit 70; fi
		printf "replacement-name-untouched\n"

		ip link add br0 type bridge
		ip link add br1 type bridge
		ip link set br0 type bridge vlan_filtering 1
		ip link set br1 type bridge vlan_filtering 1
		ip link set br0 up
		ip link set br1 up
		ip link add fdb0 type veth peer name fdbpeer0
		ip link set fdb0 master br0
		ip link set fdb0 up
		bridge vlan add dev fdb0 vid 100
		port_ifindex=$(cat /sys/class/net/fdb0/ifindex)
		approved_master_ifindex=$(cat /sys/class/net/br0/ifindex)
		test "$(basename "$(readlink -f /sys/class/net/fdb0/master)")" = br0
		ip link set fdb0 nomaster
		ip link set fdb0 master br1
		if network-action bridge-fdb-replace "$port_ifindex" "$approved_master_ifindex" 02:00:00:00:01:22 100; then exit 71; fi
		if bridge fdb show br br1 | grep -qi "02:00:00:00:01:22"; then exit 72; fi
		printf "changed-master-rejected\n"
	') || fail 'kernel interface identity adversarial fixture did not execute'
printf '%s\n' "$identity_output" | grep -Fx 'replacement-name-untouched' >/dev/null \
	|| fail 'a replacement interface inherited a mutation addressed to the pinned kernel identity'
printf '%s\n' "$identity_output" | grep -Fx 'changed-master-rejected' >/dev/null \
	|| fail 'changed bridge membership was not rejected using the approved master ifindex'
destroy_fixture
pass 'kernel-index actions avoid replacement names and reject changed bridge membership'

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

assert_metadata_value() {
	metadata_file=$1
	metadata_key=$2
	expected_value=$3
	actual_value=$(awk -v wanted_key="$metadata_key" '
		{
			separator = index($0, "=")
			if (separator == 0) next
			key = substr($0, 1, separator - 1)
			if (key != wanted_key) next
			if (++matches != 1) invalid = 1
			value = substr($0, separator + 1)
		}
		END {
			if (invalid || matches != 1) exit 1
			print value
		}
	' "$metadata_file") || fail "metadata key '$metadata_key' was not recorded exactly once"
	[ "$actual_value" = "$expected_value" ] \
		|| fail "metadata key '$metadata_key' was '$actual_value', expected '$expected_value'"
}

assert_metadata_key_absent() {
	metadata_file=$1
	metadata_key=$2
	if awk -v wanted_key="$metadata_key" '
		{
			separator = index($0, "=")
			if (separator > 0 && substr($0, 1, separator - 1) == wanted_key) exit 1
		}
	' "$metadata_file"; then
		return
	fi
	fail "metadata unexpectedly recorded '$metadata_key'"
}

assert_kexec_outcome() {
	result_file=$1
	expected_result=$2
	expected_execution=$3
	expected_executor=$4
	actual_outcome=$(awk '
		{
			separator = index($0, "=")
			if (separator == 0) {
				invalid = 1
				next
			}
			key = substr($0, 1, separator - 1)
			value = substr($0, separator + 1)
			if (key == "validation_result") {
				if (++result_count != 1) invalid = 1
				result = value
			}
			if (key == "execution_performed") {
				if (++execution_count != 1) invalid = 1
				execution = value
			}
			if (key == "provider_executor_required") {
				if (++executor_count != 1) invalid = 1
				executor = value
			}
		}
		END {
			if (invalid || result_count != 1 || execution_count != 1) exit 1
			if (executor_count == 0) executor = "absent"
			print result "|" execution "|" executor
		}
	' "$result_file") || fail 'kexec validation result is not a well-formed single outcome'
	[ "$actual_outcome" = "$expected_result|$expected_execution|$expected_executor" ] \
		|| fail "kexec outcome was '$actual_outcome', expected '$expected_result|$expected_execution|$expected_executor'"
}

run_kexec_duplicate_option() {
	label=$1
	expected_message=$2
	shift 2
	new_fixture "$label"
	set +e
	"$docker_bin" run --name "$container_name" --user 0 \
		--env BREAKGLASS_NODE_NAME=node-a \
		--network none --read-only --cap-drop ALL \
		--security-opt no-new-privileges --security-opt seccomp=builtin \
		--mount "source=$volume_name,destination=/evidence" \
		"$image" kexec-recovery-validate "$@" \
		--evidence-dir /evidence --confirm KEXEC-RECOVERY-VALIDATE \
		>"$fixture_dir/output" 2>&1
	duplicate_kexec_exit=$?
	set -e
	cat "$fixture_dir/output"
	assert_container_security "$container_name" none
	[ "$duplicate_kexec_exit" -eq 2 ] || fail "duplicate kexec option returned $duplicate_kexec_exit, expected 2"
	grep -q -- "$expected_message" "$fixture_dir/output" \
		|| fail 'duplicate kexec option did not fail during argument parsing'
	if "$docker_bin" run --rm --network none --read-only --cap-drop ALL \
		--security-opt no-new-privileges --security-opt seccomp=builtin \
		--mount "source=$volume_name,destination=/evidence" --entrypoint /bin/sh "$image" \
		-c '! find /evidence -mindepth 1 -maxdepth 1 -print | grep -q .'; then
		:
	else
		fail 'duplicate kexec option created evidence before argument validation'
	fi
	destroy_fixture
	pass "$label is rejected before provider validation and evidence creation"
}

run_kexec_duplicate_option guard-kexec-duplicate-target-node \
	'--target-node may be supplied only once' \
	--target-node node-a --target-node node-a --recovery-profile rescue-a
run_kexec_duplicate_option guard-kexec-duplicate-recovery-profile \
	'--recovery-profile may be supplied only once' \
	--target-node node-a --recovery-profile rescue-a --recovery-profile rescue-a
run_kexec_duplicate_option guard-kexec-duplicate-evidence-dir \
	'--evidence-dir may be supplied only once' \
	--target-node node-a --recovery-profile rescue-a --evidence-dir /evidence --evidence-dir /evidence
run_kexec_duplicate_option guard-kexec-duplicate-confirm \
	'--confirm may be supplied only once' \
	--target-node node-a --recovery-profile rescue-a --confirm KEXEC-RECOVERY-VALIDATE --confirm KEXEC-RECOVERY-VALIDATE

run_kexec_validation kexec-validation 0 readonly kexec-recovery-validate rescue-a \
	"$kernel_digest" "$initrd_digest" "$cmdline_digest" \
	kexec-recovery-validate --target-node node-a --recovery-profile rescue-a \
	--evidence-dir /evidence --confirm KEXEC-RECOVERY-VALIDATE
kexec_bundle=$(bundle_from_output "$fixture_dir/output")
kexec_host_bundle=$(copy_bundle "$fixture_dir/output" "$kexec_bundle")
assert_capture_statuses "$kexec_host_bundle" kernel.sha256.txt initrd.sha256.txt cmdline.sha256.txt
assert_kexec_outcome "$kexec_host_bundle/validation-result.txt" provider-inputs-verified false true
assert_metadata_value "$kexec_host_bundle/metadata" kernel_digest_status verified
assert_metadata_value "$kexec_host_bundle/metadata" initrd_digest_status verified
assert_metadata_value "$kexec_host_bundle/metadata" cmdline_digest_status verified
assert_volume_path_absent kexec-executed
assert_volume_path_absent fake-kexec-executed
destroy_fixture
pass 'fixed provider recovery inputs are validated without evaluating cmdline or invoking an executable'

uppercase_kernel_digest=$(printf '%s' "$kernel_digest" | LC_ALL=C tr '[:lower:]' '[:upper:]')
uppercase_initrd_digest=$(printf '%s' "$initrd_digest" | LC_ALL=C tr '[:lower:]' '[:upper:]')
uppercase_cmdline_digest=$(printf '%s' "$cmdline_digest" | LC_ALL=C tr '[:lower:]' '[:upper:]')
[ "$uppercase_kernel_digest$uppercase_initrd_digest$uppercase_cmdline_digest" \
	!= "$kernel_digest$initrd_digest$cmdline_digest" ] \
	|| fail 'uppercase digest fixture did not exercise hexadecimal case normalization'
run_kexec_validation kexec-uppercase-digests 0 readonly kexec-recovery-validate rescue-a \
	"$uppercase_kernel_digest" "$uppercase_initrd_digest" "$uppercase_cmdline_digest" \
	kexec-recovery-validate --target-node node-a --recovery-profile rescue-a \
	--evidence-dir /evidence --confirm KEXEC-RECOVERY-VALIDATE
uppercase_bundle=$(bundle_from_output "$fixture_dir/output")
uppercase_host_bundle=$(copy_bundle "$fixture_dir/output" "$uppercase_bundle")
assert_kexec_outcome "$uppercase_host_bundle/validation-result.txt" provider-inputs-verified false true
assert_metadata_value "$uppercase_host_bundle/metadata" kernel_expected_sha256 "$kernel_digest"
assert_metadata_value "$uppercase_host_bundle/metadata" initrd_expected_sha256 "$initrd_digest"
assert_metadata_value "$uppercase_host_bundle/metadata" cmdline_expected_sha256 "$cmdline_digest"
assert_metadata_value "$uppercase_host_bundle/metadata" kernel_digest_status verified
assert_metadata_value "$uppercase_host_bundle/metadata" initrd_digest_status verified
assert_metadata_value "$uppercase_host_bundle/metadata" cmdline_digest_status verified
assert_volume_path_absent fake-kexec-executed
destroy_fixture
pass 'uppercase controller digests canonicalize to the verified recovery inputs'

bad_kernel_digest=aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa
run_kexec_validation guard-kexec-digest-mismatch 1 readonly kexec-recovery-validate rescue-a \
	"$bad_kernel_digest" "$initrd_digest" "$cmdline_digest" \
	kexec-recovery-validate --target-node node-a --recovery-profile rescue-a \
	--evidence-dir /evidence --confirm KEXEC-RECOVERY-VALIDATE
mismatch_bundle=$(bundle_from_output "$fixture_dir/output")
mismatch_host_bundle=$(copy_bundle "$fixture_dir/output" "$mismatch_bundle")
assert_kexec_outcome "$mismatch_host_bundle/validation-result.txt" digest-mismatch false absent
assert_metadata_value "$mismatch_host_bundle/metadata" kernel_digest_status mismatch
assert_metadata_key_absent "$mismatch_host_bundle/metadata" kernel_verification_error
assert_volume_path_absent fake-kexec-executed
destroy_fixture
pass 'recovery digest mismatch fails closed with no execution'

sha256sum_wrapper_dir="$tmp_dir/sha256sum-wrapper"
mkdir -p "$sha256sum_wrapper_dir"
# The single-quoted lines are the literal, disposable in-container wrapper.
# shellcheck disable=SC2016
printf '%s\n' \
	'#!/bin/sh' \
	'set -eu' \
	'state=/evidence/.sha256sum-wrapper-calls' \
	'calls=0' \
	'if [ -f "$state" ]; then calls=$(cat "$state"); fi' \
	'case "$calls" in ""|*[!0-9]*) exit 125 ;; esac' \
	'calls=$((calls + 1))' \
	'printf "%s\\n" "$calls" >"$state"' \
	'if [ "$calls" -le 2 ]; then' \
	'  exec /bin/busybox sha256sum "$@"' \
	'fi' \
	'printf "%s\\n" "deliberate sha256sum verification fixture failure" >&2' \
	'exit 77' \
	>"$sha256sum_wrapper_dir/sha256sum"
chmod 0555 "$sha256sum_wrapper_dir/sha256sum"
# The single-quoted command must run inside the disposable image unchanged.
# shellcheck disable=SC2016
sha256sum_path=$("$docker_bin" run --rm --network none --read-only --cap-drop ALL \
	--security-opt no-new-privileges --security-opt seccomp=builtin \
	--entrypoint /bin/sh "$image" -c '
		set -eu
		sha256sum_path=$(command -v sha256sum)
		case "$sha256sum_path" in
			/bin/sha256sum|/usr/bin/sha256sum) ;;
			*) exit 1 ;;
		esac
		test -x "$sha256sum_path"
		printf "%s\\n" "$sha256sum_path"
	') || fail 'could not resolve the image-owned sha256sum executable for the verification-failure fixture'
case "$sha256sum_path" in
	/usr/bin/sha256sum|/bin/sha256sum) ;;
	*) fail "unexpected image-owned sha256sum executable '$sha256sum_path'" ;;
esac
# Alpine's image-owned sha256sum is a BusyBox symlink, so replacing that file
# would also replace the shell interpreter. The immutable common helper resets
# PATH with /usr/local/sbin first; mount only this disposable test directory
# there to exercise the same fixed command lookup without caller PATH input.
sha256sum_wrapper_mount=/usr/local/sbin
new_fixture guard-kexec-verification-failure
set +e
"$docker_bin" run \
	--name "$container_name" --user 0 --env BREAKGLASS_NODE_NAME=node-a \
	--env BREAKGLASS_OPERATION_ID=operation-guard-kexec-verification-failure \
	--env BREAKGLASS_RECORDING_ID=recording-guard-kexec-verification-failure \
	--env BREAKGLASS_APPROVAL_ID=approval-guard-kexec-verification-failure \
	--env BREAKGLASS_APPROVED_ACTION=kexec-recovery-validate \
	--env BREAKGLASS_KEXEC_PROFILE=rescue-a \
	--env BREAKGLASS_KEXEC_KERNEL_SHA256="$kernel_digest" \
	--env BREAKGLASS_KEXEC_INITRD_SHA256="$initrd_digest" \
	--env BREAKGLASS_KEXEC_CMDLINE_SHA256="$cmdline_digest" \
	--network none --read-only --cap-drop ALL \
	--security-opt no-new-privileges --security-opt seccomp=builtin \
	--mount "source=$volume_name,destination=/evidence" \
	--mount "type=bind,source=$recovery_dir,destination=/recovery,readonly" \
	--mount "type=bind,source=$sha256sum_wrapper_dir,destination=$sha256sum_wrapper_mount,readonly" \
	"$image" kexec-recovery-validate --target-node node-a --recovery-profile rescue-a \
	--evidence-dir /evidence --confirm KEXEC-RECOVERY-VALIDATE \
	>"$fixture_dir/output" 2>&1
verification_failure_exit=$?
set -e
cat "$fixture_dir/output"
assert_container_security "$container_name" none
[ "$verification_failure_exit" -eq 1 ] \
	|| fail "verification failure returned $verification_failure_exit, expected 1"
verification_failure_bundle=$(bundle_from_output "$fixture_dir/output")
verification_failure_host_bundle=$(copy_bundle "$fixture_dir/output" "$verification_failure_bundle")
assert_kexec_outcome "$verification_failure_host_bundle/validation-result.txt" verification-failed false absent
assert_metadata_value "$verification_failure_host_bundle/metadata" kernel_digest_status verification-failed
assert_metadata_value "$verification_failure_host_bundle/metadata" kernel_verification_error capture-failed
assert_volume_path_absent fake-kexec-executed
destroy_fixture
pass 'recovery verification failure is distinct from a digest mismatch and fails closed'

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
