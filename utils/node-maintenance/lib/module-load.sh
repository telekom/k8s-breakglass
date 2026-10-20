#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

set -eu

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
# shellcheck disable=SC1091
. "$script_dir/common.sh"

usage() {
	cat >&2 <<'USAGE'
Usage:
  module-load --target-node NODE --module MODULE \
    --evidence-dir /evidence[/SAFE_CHILD] --confirm MODULE-LOAD

Loads exactly one kernel module of the running kernel from the host module
tree (mounted read-only at /lib/modules) with modprobe, including the
dependencies and soft dependencies the host module tree lists for it. The
image's modprobe.d is replaced by an empty configuration directory, so no
alias, option or install command applies, and the name must resolve to the
module itself. The load is not persistent: it is gone after the next reboot.
A module that is already loaded or built in is recorded and left unchanged.

The controller must bind BREAKGLASS_APPROVED_ACTION=module-load and the exact
BREAKGLASS_APPROVED_MODULE_REQUEST tuple.
USAGE
}

target_node=
module=
evidence_dir=
confirmation=
target_node_seen=false
module_seen=false
evidence_dir_seen=false
confirmation_seen=false
while [ "$#" -gt 0 ]; do
	case "$1" in
		--target-node) [ "$target_node_seen" = false ] || die "--target-node may be supplied only once"; [ "$#" -ge 2 ] || die "--target-node needs a value"; target_node_seen=true; target_node=$2; shift 2 ;;
		--module) [ "$module_seen" = false ] || die "--module may be supplied only once"; [ "$#" -ge 2 ] || die "--module needs a value"; module_seen=true; module=$2; shift 2 ;;
		--evidence-dir) [ "$evidence_dir_seen" = false ] || die "--evidence-dir may be supplied only once"; [ "$#" -ge 2 ] || die "--evidence-dir needs a value"; evidence_dir_seen=true; evidence_dir=$2; shift 2 ;;
		--confirm) [ "$confirmation_seen" = false ] || die "--confirm may be supplied only once"; [ "$#" -ge 2 ] || die "--confirm needs a value"; confirmation_seen=true; confirmation=$2; shift 2 ;;
		-h|--help) usage; exit 0 ;;
		*) die "unsupported option '$1'" ;;
	esac
done

validate_target "$target_node"
case "$module" in
	''|*[!a-z0-9_]*) die "module must be an exact kernel module name ([a-z0-9_])" ;;
esac
[ "${#module}" -le 56 ] || die "module name exceeds 56 bytes"
validate_confirmation MODULE-LOAD "$confirmation"
validate_recording_context
validate_approved_action module-load
approved_request=${BREAKGLASS_APPROVED_MODULE_REQUEST:-}
[ "$approved_request" = "target_node=$target_node&module=$module&confirmation=MODULE-LOAD" ] \
	|| die "controller-approved module request does not exactly match the requested tuple"
validate_action_deadline
prepare_evidence_dir "$evidence_dir"
acquire_operation_lock "$evidence_dir" "$(sha256_text "$approved_request")"
trap 'cleanup_evidence_temporary_candidates || true; release_operation_lock || true' EXIT
assert_no_active_legacy_locks || die "an older node-maintenance operation is active or requires migration"
cleanup_evidence_temporary_candidates || die "cannot clean stale evidence temporary files"

bundle=$(new_bundle "$evidence_dir" module-load)
write_metadata "$bundle/metadata" module-load "$target_node" "" module-load
release=$(uname -r)
# An empty configuration directory: no alias, option, softdep or install line
# from the image applies.
modprobe_config=/usr/share/breakglass/modprobe.d
printf 'module=%s\nkernel_release=%s\n' "$module" "$release" | append_evidence "$bundle/metadata"
record_event operation-started accepted

if [ -d "/sys/module/$module" ]; then
	printf 'already_loaded=true\n' | append_evidence "$bundle/metadata"
	record_event operation-completed succeeded
	printf 'Module %s is already loaded; nothing was changed (evidence: %s)\n' "$module" "$bundle"
	exit 0
fi
if [ ! -f "/lib/modules/$release/modules.dep" ]; then
	record_event operation-completed preflight-failed
	die "the host module tree for kernel $release is not mounted at /lib/modules; nothing was loaded (evidence: $bundle)"
fi
# capture appends an exit_status trailer; the name must resolve to exactly itself.
if ! capture "$bundle/before-resolve.txt" modprobe -C "$modprobe_config" --resolve-alias -- "$module" ||
	[ "$(grep -v '^exit_status=' "$bundle/before-resolve.txt" | grep .)" != "$module" ]; then
	record_event operation-completed preflight-failed
	die "module '$module' does not resolve to itself for kernel $release; nothing was loaded (evidence: $bundle)"
fi
if ! capture "$bundle/before-depends.txt" modprobe -C "$modprobe_config" --show-depends --ignore-install -- "$module"; then
	record_event operation-completed preflight-failed
	die "module '$module' is not available for kernel $release; nothing was loaded (evidence: $bundle)"
fi
if grep -q "^builtin $module\$" "$bundle/before-depends.txt"; then
	printf 'builtin=true\n' | append_evidence "$bundle/metadata"
	record_event operation-completed succeeded
	printf 'Module %s is built into kernel %s; nothing was changed (evidence: %s)\n' "$module" "$release" "$bundle"
	exit 0
fi

validate_action_deadline
set +e
capture "$bundle/action-modprobe.txt" modprobe -C "$modprobe_config" --ignore-install -- "$module"
action_status=$?
set -e
loaded=false
[ -d "/sys/module/$module" ] && loaded=true
assert_safe_bundle "$bundle"
printf 'action_exit_status=%s\nloaded=%s\ncompleted_at_utc=%s\n' "$action_status" "$loaded" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" | append_evidence "$bundle/metadata"
# finit_module cannot be interrupted, so a capture timeout can still end with
# the module loaded: the kernel state decides.
if [ "$loaded" != true ]; then
	record_event operation-completed failed
	printf 'Module %s was not loaded; recommend replacing the node or fixing its configuration (evidence: %s)\n' "$module" "$bundle" >&2
	exit 1
fi
record_event operation-completed succeeded
printf 'Module %s loaded until the next reboot; persist it through node configuration (evidence: %s)\n' "$module" "$bundle"
