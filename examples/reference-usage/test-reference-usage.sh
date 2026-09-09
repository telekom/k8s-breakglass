#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
script="${script_dir}/reference-usage.sh"
test_root=$(mktemp -d "${TMPDIR:-/tmp}/reference-usage-test.XXXXXX")
trap 'rm -rf "$test_root"' EXIT HUP INT TERM
fake_bin="${test_root}/bin"
mkdir -p "${fake_bin}"
log_file="${test_root}/kubectl.log"

cat >"${fake_bin}/kubectl" <<'SH'
#!/bin/sh
printf 'kubectl %s\n' "$*" >>"${REFERENCE_KUBECTL_LOG}"
exit 0
SH
chmod +x "${fake_bin}/kubectl"

# Load the production functions without starting the full reference flow.
script_without_main="${test_root}/reference-usage-functions.sh"
sed '$d' "${script}" >"${script_without_main}"
REFERENCE_KUBECTL_LOG="${log_file}" PATH="${fake_bin}:${PATH}" \
  KUBECONFIG="${test_root}/kubeconfig" bash -c '
    source "$1"
    trap - EXIT
    KUBECONFIG_FILE="$KUBECONFIG"
    AUDIT_CONFIG_CREATED=true
    DEBUG_NAMESPACE_CREATED=true
    SESSION_NAME=session-a
    REJECTED_SESSION_NAME=session-b
    DEBUG_SESSION_NAME=debug-a
    ELEVATED_DEBUG_SESSION_NAME=debug-b
    cleanup
    assert_zero_residual
  ' bash "${script_without_main}"

while IFS= read -r line; do
  case "${line}" in
    *"kubectl delete"*--wait=false*)
      ;;
    *"kubectl delete"*--wait*--timeout\ *60s*)
      ;;
    *"kubectl delete"*)
      echo "unbounded delete: ${line}" >&2
      exit 1
      ;;
  esac
done <"${log_file}"

echo "reference usage cleanup behavior passed"
