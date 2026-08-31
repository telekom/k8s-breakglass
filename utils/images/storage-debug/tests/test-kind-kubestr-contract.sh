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
printf '%s\n' 'storage kubestr UID capture order contract passed'
