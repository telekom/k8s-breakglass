#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

set -eu

script_dir=$(cd -- "$(dirname -- "$0")" && pwd)
# shellcheck disable=SC1091
. "$script_dir/common.sh"

kernel_path=/recovery/kernel
initrd_path=/recovery/initrd
cmdline_path=/recovery/cmdline
kernel_max_bytes=268435456
initrd_max_bytes=536870912
cmdline_max_bytes=4096

usage() {
	cat >&2 <<'EOF'
Usage:
  kexec-recovery-validate --target-node NODE --recovery-profile PROFILE \
    --evidence-dir /evidence[/SAFE_CHILD] --confirm KEXEC-RECOVERY-VALIDATE

This command only validates provider-owned files at the fixed read-only paths
/recovery/kernel, /recovery/initrd, and /recovery/cmdline against immutable
controller-provided SHA-256 digests. It never loads or executes a kernel.
EOF
}

validate_recovery_mount() {
	[ -d /recovery ] || die "/recovery must be a provider-owned read-only mount"
	[ ! -L /recovery ] || die "/recovery may not be a symlink"
	resolved_recovery=$(readlink -f /recovery 2>/dev/null || true)
	[ "$resolved_recovery" = /recovery ] || die "/recovery did not resolve safely"
	awk '
		$5 == "/recovery" {
			n = split($6, options, ",")
			for (i = 1; i <= n; i++) if (options[i] == "ro") readonly = 1
		}
		END { exit(readonly ? 0 : 1) }
	' /proc/self/mountinfo || die "/recovery must be a distinct read-only mount"
}

validate_recovery_file() {
	label=$1
	path=$2
	max_bytes=$3
	[ -f "$path" ] || die "$label is missing from its fixed provider path"
	[ ! -L "$path" ] || die "$label may not be a symlink"
	resolved_file=$(readlink -f "$path" 2>/dev/null || true)
	[ "$resolved_file" = "$path" ] || die "$label did not resolve to its fixed provider path"
	asset_bytes=$(stat -c %s "$path") || die "cannot determine bounded size for $label"
	[ "$asset_bytes" -gt 0 ] || die "$label may not be empty"
	[ "$asset_bytes" -le "$max_bytes" ] || die "$label exceeds its fixed size limit"
}

verify_digest() {
	label=$1
	path=$2
	expected=$3
	output_file="$bundle/$label.sha256.txt"
	if ! capture "$output_file" sha256sum "$path"; then
		printf '%s_digest_status=capture-failed\n' "$label" >>"$bundle/metadata"
		return 1
	fi
	actual=$(awk 'NR == 1 { print $1 }' "$output_file")
	printf '%s_expected_sha256=%s\n%s_actual_sha256=%s\n' "$label" "$expected" "$label" "$actual" >>"$bundle/metadata"
	[ "$actual" = "$expected" ]
}

target_node=
profile=
evidence_dir=
confirmation=
while [ "$#" -gt 0 ]; do
	case "$1" in
		--target-node) [ "$#" -ge 2 ] || die "--target-node needs a value"; target_node=$2; shift 2 ;;
		--recovery-profile) [ "$#" -ge 2 ] || die "--recovery-profile needs a value"; profile=$2; shift 2 ;;
		--evidence-dir) [ "$#" -ge 2 ] || die "--evidence-dir needs a value"; evidence_dir=$2; shift 2 ;;
		--confirm) [ "$#" -ge 2 ] || die "--confirm needs a value"; confirmation=$2; shift 2 ;;
		-h|--help) usage; exit 0 ;;
		*) die "unsupported option '$1'" ;;
	esac
done

validate_target "$target_node"
validate_value "recovery profile" "$profile"
validate_confirmation KEXEC-RECOVERY-VALIDATE "$confirmation"
validate_recording_context
validate_approved_action kexec-recovery-validate

provider_profile=${BREAKGLASS_KEXEC_PROFILE:-}
kernel_sha256=${BREAKGLASS_KEXEC_KERNEL_SHA256:-}
initrd_sha256=${BREAKGLASS_KEXEC_INITRD_SHA256:-}
cmdline_sha256=${BREAKGLASS_KEXEC_CMDLINE_SHA256:-}
validate_value "BREAKGLASS_KEXEC_PROFILE" "$provider_profile"
[ "$profile" = "$provider_profile" ] || die "requested recovery profile does not match the controller-provided profile"
validate_sha256 "BREAKGLASS_KEXEC_KERNEL_SHA256" "$kernel_sha256"
validate_sha256 "BREAKGLASS_KEXEC_INITRD_SHA256" "$initrd_sha256"
validate_sha256 "BREAKGLASS_KEXEC_CMDLINE_SHA256" "$cmdline_sha256"
validate_recovery_mount
validate_recovery_file kernel "$kernel_path" "$kernel_max_bytes"
kernel_bytes=$asset_bytes
validate_recovery_file initrd "$initrd_path" "$initrd_max_bytes"
initrd_bytes=$asset_bytes
validate_recovery_file cmdline "$cmdline_path" "$cmdline_max_bytes"
cmdline_bytes=$asset_bytes

prepare_evidence_dir "$evidence_dir"
trap 'release_operation_lock || true' EXIT
acquire_operation_lock "$evidence_dir"
bundle=$(new_bundle "$evidence_dir" kexec-recovery-validate)
write_metadata "$bundle/metadata" kexec-recovery-validate "$target_node" not-applicable validation-only
{
	printf 'recovery_profile=%s\n' "$profile"
	printf 'kernel_path=%s\nkernel_bytes=%s\n' "$kernel_path" "$kernel_bytes"
	printf 'initrd_path=%s\ninitrd_bytes=%s\n' "$initrd_path" "$initrd_bytes"
	printf 'cmdline_path=%s\ncmdline_bytes=%s\n' "$cmdline_path" "$cmdline_bytes"
	printf 'execution_performed=false\n'
} >>"$bundle/metadata"
record_event operation-started accepted

validation_status=0
verify_digest kernel "$kernel_path" "$kernel_sha256" || validation_status=1
verify_digest initrd "$initrd_path" "$initrd_sha256" || validation_status=1
verify_digest cmdline "$cmdline_path" "$cmdline_sha256" || validation_status=1

if [ "$validation_status" -ne 0 ]; then
	printf 'validation_result=digest-mismatch\ncompleted_at_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$bundle/metadata"
	printf 'validation_result=digest-mismatch\nexecution_performed=false\n' >"$bundle/validation-result.txt"
	record_event operation-completed validation-failed
	printf 'Recovery inputs were rejected; kexec was not executed. Evidence: %s\n' "$bundle" >&2
	exit 1
fi

printf 'validation_result=provider-inputs-verified\ncompleted_at_utc=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" >>"$bundle/metadata"
printf 'validation_result=provider-inputs-verified\nexecution_performed=false\nprovider_executor_required=true\n' >"$bundle/validation-result.txt"
record_event operation-completed validated-not-executed
printf 'Provider-owned recovery inputs matched their immutable digests; kexec was NOT executed. Evidence: %s\n' "$bundle"
