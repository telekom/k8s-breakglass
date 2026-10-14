<!--
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG

SPDX-License-Identifier: CC-BY-4.0
-->

# Kexec recovery input validation and execution

`kexec-recovery-validate` verifies an immutable provider recovery bundle. It
does not load a kernel, call kexec, reboot, or claim that the bundle will boot.
`kexec-recovery` is the separately approved execution of the same bundle; see
[Execution](#execution). Kernel signatures, lockdown, measured boot and the
bundle's own rollback remain platform-specific provider decisions.

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

Each digest must contain exactly 64 hexadecimal characters. Uppercase and
lowercase hexadecimal values are equivalent: the helper canonicalizes them to
lowercase before it binds the recovery-validation operation and records the
evidence.

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

## Execution

`kexec-recovery` needs its own approval and runs only from the typed
node-maintenance controller (`nodeMaintenance.action: kexec-recovery`), never
from a hand-written workload. Before the executor exists the controller records
the Node boot ID, cordons the Node and evicts its Pods within
`drainTimeoutSeconds`. The executor then receives, in addition to the
validation inputs:

* `BREAKGLASS_APPROVED_ACTION=kexec-recovery` and `--confirm KEXEC-RECOVERY`;
* `BREAKGLASS_KEXEC_BOOT_ID`, the boot ID recorded before the drain;
* `BREAKGLASS_ACTION_DEADLINE_UNIX`, the session expiry.

It runs with `SYS_BOOT` only, the host PID namespace and an unconfined seccomp
profile. After the digest checks it verifies the deadline and records a
`kexec-requested` event. The fixed `kexec-action` helper re-reads
`/proc/sys/kernel/random/boot_id`, copies each file into a sealed private
memfd while hashing it, loads exactly those verified copies with
`kexec_file_load` (a later write to the host file cannot change them), confirms
`/sys/kernel/kexec_loaded`, syncs and reboots with `LINUX_REBOOT_CMD_KEXEC`.
It re-checks the approved deadline immediately before the load and again before
the reboot, unloading the kernel if the deadline passed. The reboot works
like `kexec -e`: user space is not shut down cleanly, which is why the Node is
drained first. On any failure it unloads the kernel, records
`execution_result=failed` and exits 1 while the Node keeps running. On every
exit the executor writes `kexec_loaded=0|1|unknown` from
`/sys/kernel/kexec_loaded` and the current `boot_id` to `/dev/termination-log`.

The controller decides the outcome only on a Ready Node: a terminated executor
that reported `kexec_loaded=0` in the approved boot is `failed`; otherwise a
new boot ID is `succeeded`, which proves a reboot, not which kernel booted. An
executor killed without that report may have left a kernel loaded, so its
outcome stays unknown.
Evidence in `/evidence` is lost with a successful reboot; the audited result
and boot IDs are the receipt. Cleanup uncordons the Node only for a proven
outcome. An unknown or interrupted kexec leaves the Node cordoned with the
`breakglass.t-caas.telekom.com/maintenance-cordon` annotation for an operator
to inspect, for example through the out-of-band console; if
`/sys/kernel/kexec_loaded` is `1`, unload it with `kexec -u` or reboot before
uncordoning. Do not add another
executor by passing commands, arguments, paths, or images to these helpers.
