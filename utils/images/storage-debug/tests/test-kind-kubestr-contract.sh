#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail

script=$(cd -- "$(dirname -- "$0")/.." && pwd)/tests/kind-kubestr.sh
pv_manifest=$(grep -n '^kind: PersistentVolume$' "$script" | tail -1 | cut -d: -f1)
pv_uid=$(grep -n '^ATTACHED_PV_UID=' "$script" | tail -1 | cut -d: -f1)
[ -n "$pv_manifest" ] && [ -n "$pv_uid" ] && [ "$pv_uid" -gt "$pv_manifest" ] || {
	printf '%s\n' 'attached PV UID is captured before the PV manifest is applied' >&2
	exit 1
}
grep -F 'kubernetes_delete_uid' "$script" >/dev/null
pod_wait=$(grep -n "pod/\"\$ATTACHED_POD_NAME\".*--namespace" "$script" | cut -d: -f1 | head -1)
pvc_delete=$(grep -n 'persistentvolumeclaims/' "$script" | cut -d: -f1 | head -1)
pvc_wait=$(grep -n "pvc/\"\$ATTACHED_PVC_NAME\".*--namespace" "$script" | cut -d: -f1 | head -1)
pv_delete=$(grep -n "persistentvolumes/\$ATTACHED_PV_NAME" "$script" | cut -d: -f1 | head -1)
[ -n "$pod_wait" ] && [ -n "$pvc_delete" ] && [ -n "$pvc_wait" ] && [ -n "$pv_delete" ] || {
	printf '%s\n' 'storage cleanup does not contain all ordered deletion waits' >&2
	exit 1
}
[ "$pod_wait" -lt "$pvc_delete" ] && [ "$pvc_wait" -lt "$pv_delete" ] || {
	printf '%s\n' 'storage cleanup can delete PVC/PV before the prior object is gone' >&2
	exit 1
}
grep -F -- '--for=delete' "$script" >/dev/null
grep -F -- '--timeout=120s' "$script" >/dev/null
printf '%s\n' 'storage kubestr UID capture order contract passed'
