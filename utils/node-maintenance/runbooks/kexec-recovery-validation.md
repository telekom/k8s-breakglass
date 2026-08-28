<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: CC-BY-4.0
-->

# Kexec recovery input validation

This procedure verifies an immutable provider recovery bundle. It does not
load a kernel, call kexec, reboot, or claim that the bundle will boot. Generic
kexec execution is intentionally unavailable because kernel signatures,
lockdown, measured boot, crash-kernel reservations, device quiescence, and
rollback are platform-specific safety decisions.

Obtain an approval dedicated to `kexec-recovery-validate`; approval of node
preflight or network repair does not authorize it. The controller-owned
immutable workload must provide all of these values, not user input:

* `BREAKGLASS_NODE_NAME` from Downward API `spec.nodeName`;
* unique `BREAKGLASS_OPERATION_ID`, `BREAKGLASS_APPROVAL_ID`, and
  `BREAKGLASS_RECORDING_ID` correlations;
* `BREAKGLASS_APPROVED_ACTION=kexec-recovery-validate`;
* `BREAKGLASS_KEXEC_PROFILE` and exact SHA-256 values in
  `BREAKGLASS_KEXEC_KERNEL_SHA256`, `BREAKGLASS_KEXEC_INITRD_SHA256`, and
  `BREAKGLASS_KEXEC_CMDLINE_SHA256`.

Mount the provider-owned bundle as a distinct read-only mount at `/recovery`.
Its only consumed paths are `/recovery/kernel`, `/recovery/initrd`, and
`/recovery/cmdline`; symlinks, empty files, writable mounts, caller-selected
paths, and over-limit inputs are rejected. Run with a read-only root, all
capabilities dropped, RuntimeDefault seccomp, no host PID namespace, and no
host filesystem mount. Pin the node-maintenance image itself by digest in the
immutable template.

Run:

```text
kexec-recovery-validate \
  --target-node NODE_NAME \
  --recovery-profile PROVIDER_PROFILE \
  --evidence-dir /evidence \
  --confirm KEXEC-RECOVERY-VALIDATE
```

Success means only that the fixed files match the controller-provided digests
and size/path/mount checks. Preserve `metadata`, `events.jsonl`, the three
bounded digest captures, and `validation-result.txt`. The latter always says
`execution_performed=false` and `provider_executor_required=true` on a valid
bundle. Do not interpret exit zero as a successful recovery.

On a non-zero result, inspect `validation-result.txt` and `metadata` before
handling the incident. `validation_result=digest-mismatch` means a digest was
successfully calculated but differs from its controller-provided value.
`validation_result=verification-failed` means the digest could not be
captured, read, or parsed. Both outcomes preserve
`execution_performed=false`; neither authorizes a recovery execution.

Any eventual executor is an unresolved provider responsibility. It needs its
own separately approved immutable workload, kernel/platform compatibility and
signature policy, boot-health and rollback contract, node exclusivity, bounded
timeout, complete recording, and cleanup. Do not add that executor by passing
commands, arguments, paths, or images to this validation helper.
