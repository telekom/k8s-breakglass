#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail

repo=$(cd -- "$(dirname -- "$0")/../../../.." && pwd)
cleanup_helper=${repo}/hack/kubernetes-storage-cleanup.sh

fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
cat >"$fixture/kubectl" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
object=
for arg in "$@"; do
	case "$arg" in
		pod/*|pvc/*|pv/*) object=$arg ;;
	esac
done
printf 'wait %s\n' "$object" >>"${STORAGE_CLEANUP_LOG:?}"
[ "${STORAGE_CLEANUP_WAIT_FAIL:-}" != "$object" ]
EOF
chmod +x "$fixture/kubectl"
# shellcheck disable=SC1090 # fixture selects the repository helper under test
# Exercise the same UID-fenced cleanup helper used by the Kind proof. The
# contract test intentionally verifies observable delete/wait behavior rather
# than depending on the production script's source layout.
source "$cleanup_helper"

current_pod=pod-original
current_pvc=pvc-original
current_pv=pv-original
kubernetes_delete_uid() {
	local path=$2 uid=$3 object
	case "$path" in
		*/pods/attached) object=pod/attached; [ "$uid" = "$current_pod" ] || return 1; current_pod=gone ;;
		*/persistentvolumeclaims/attached) object=pvc/attached; [ "$uid" = "$current_pvc" ] || return 1; current_pvc=gone ;;
		*/persistentvolumes/attached) object=pv/attached; [ "$uid" = "$current_pv" ] || return 1; current_pv=gone ;;
		*) return 2 ;;
	esac
	printf 'delete %s uid=%s\n' "$object" "$uid" >>"${STORAGE_CLEANUP_LOG:?}"
	if [ "$object" = pod/attached ] && [ "${STORAGE_CLEANUP_REPLACE_PVC:-false}" = true ]; then
		current_pvc=pvc-replacement
	fi
}

STORAGE_CLEANUP_LOG=$fixture/ordered.log
export STORAGE_CLEANUP_LOG
kubernetes_cleanup_uid_chain "$fixture/config" "$fixture/kubectl" ns attached pod-original attached pvc-original attached pv-original
expected=$'delete pod/attached uid=pod-original\nwait pod/attached\ndelete pvc/attached uid=pvc-original\nwait pvc/attached\ndelete pv/attached uid=pv-original\nwait pv/attached'
[ "$(cat "$STORAGE_CLEANUP_LOG")" = "$expected" ] || {
	printf '%s\n' 'main cleanup chain did not delete and wait in Pod/PVC/PV order' >&2
	exit 1
}
[ "$current_pod" = gone ] && [ "$current_pvc" = gone ] && [ "$current_pv" = gone ]

rm -f "$STORAGE_CLEANUP_LOG"
current_pod=pod-original
current_pvc=pvc-original
current_pv=pv-original
if STORAGE_CLEANUP_REPLACE_PVC=true kubernetes_cleanup_uid_chain \
	"$fixture/config" "$fixture/kubectl" ns attached pod-original attached pvc-original attached pv-original; then
	printf '%s\n' 'same-name PVC replacement unexpectedly passed UID cleanup' >&2
	exit 1
fi
grep -Fx 'delete pod/attached uid=pod-original' "$STORAGE_CLEANUP_LOG" >/dev/null
grep -Fx 'wait pod/attached' "$STORAGE_CLEANUP_LOG" >/dev/null
if grep -F 'pv/attached' "$STORAGE_CLEANUP_LOG" >/dev/null; then
	printf '%s\n' 'PV cleanup ran after PVC takeover' >&2
	exit 1
fi
[ "$current_pvc" = pvc-replacement ] || {
	printf '%s\n' 'PVC replacement was not preserved after UID mismatch' >&2
	exit 1
}

rm -f "$STORAGE_CLEANUP_LOG"
current_pod=pod-original
current_pvc=pvc-original
current_pv=pv-original
if STORAGE_CLEANUP_WAIT_FAIL=pvc/attached kubernetes_cleanup_uid_chain \
	"$fixture/config" "$fixture/kubectl" ns attached pod-original attached pvc-original attached pv-original; then
	printf '%s\n' 'PVC wait failure unexpectedly allowed PV cleanup' >&2
	exit 1
fi
if grep -F 'pv/attached' "$STORAGE_CLEANUP_LOG" >/dev/null; then
	printf '%s\n' 'PV cleanup ran after PVC remained present' >&2
	exit 1
fi
printf '%s\n' 'storage kubestr UID capture order contract passed'
