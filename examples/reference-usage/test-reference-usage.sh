#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
script="${script_dir}/reference-usage.sh"
test_root=$(mktemp -d "${TMPDIR:-/tmp}/reference-usage-test.XXXXXX")
trap 'rm -rf "$test_root"' EXIT HUP INT TERM
fake_bin="${test_root}/bin"
mkdir -p "${fake_bin}"
log_file="${test_root}/kubectl.log"
stdin_log_file="${test_root}/kubectl-stdin.log"

cat >"${fake_bin}/kubectl" <<'SH'
#!/bin/sh
printf 'kubectl %s\n' "$*" >>"${REFERENCE_KUBECTL_LOG}"
if [ "$1" = "apply" ] && [ "$2" = "-f" ] && [ "$3" = "-" ]; then
  cat >>"${REFERENCE_KUBECTL_STDIN_LOG}"
fi
exit 0
SH
chmod +x "${fake_bin}/kubectl"

cat >"${fake_bin}/helm" <<'SH'
#!/bin/sh
exit 0
SH
chmod +x "${fake_bin}/helm"

cat >"${fake_bin}/kind" <<'SH'
#!/bin/sh
exit 0
SH
chmod +x "${fake_bin}/kind"

# Load the production functions without starting the full reference flow.
script_without_main="${test_root}/reference-usage-functions.sh"
sed '$d' "${script}" >"${script_without_main}"
REFERENCE_KUBECTL_LOG="${log_file}" REFERENCE_KUBECTL_STDIN_LOG="${stdin_log_file}" PATH="${fake_bin}:${PATH}" \
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

REFERENCE_KUBECTL_LOG="${log_file}" REFERENCE_KUBECTL_STDIN_LOG="${stdin_log_file}" PATH="${fake_bin}:${PATH}" \
  KUBECONFIG="${test_root}/kubeconfig" bash -c '
    source "$1"
    trap - EXIT
    REFERENCE_AUDIT_WEBHOOK_URL="https://audit.example.com/collect"
    REFERENCE_REQUESTER_GROUP="platform:team/ops"
    REFERENCE_ESCALATED_GROUP="security-admins@example.com"
    validate_inputs
  ' bash "${script_without_main}"

invalid_group_stderr="${test_root}/invalid-group.stderr"
if REFERENCE_KUBECTL_LOG="${log_file}" REFERENCE_KUBECTL_STDIN_LOG="${stdin_log_file}" PATH="${fake_bin}:${PATH}" \
  KUBECONFIG="${test_root}/kubeconfig" bash -c '
    source "$1"
    trap - EXIT
    REFERENCE_AUDIT_WEBHOOK_URL="https://audit.example.com/collect"
    REFERENCE_REQUESTER_GROUP="invalid group"
    validate_inputs
  ' bash "${script_without_main}" 2>"${invalid_group_stderr}"; then
  echo "expected invalid requester group to fail validation" >&2
  exit 1
fi
grep -Fq "REFERENCE_REQUESTER_GROUP must be a valid Breakglass identifier" "${invalid_group_stderr}" || {
  cat "${invalid_group_stderr}" >&2
  exit 1
}

REFERENCE_KUBECTL_LOG="${log_file}" REFERENCE_KUBECTL_STDIN_LOG="${stdin_log_file}" PATH="${fake_bin}:${PATH}" \
  KUBECONFIG="${test_root}/kubeconfig" bash -c '
    source "$1"
    trap - EXIT
    REFERENCE_AUDIT_WEBHOOK_URL="https://audit.example.com/collect"
    BREAKGLASS_API_URL="http://127.0.0.1:8080"
    REFERENCE_REQUESTER_GROUP="platform:team/ops"
    REFERENCE_ESCALATED_GROUP="security-admins@example.com"
    install_stack
    grep -F "groups: ['\''platform:team/ops'\'']" "${CATALOGUE_VALUES_FILE}" >/dev/null
    grep -F "users: ['\''reference-approver@example.com'\'']" "${CATALOGUE_VALUES_FILE}" >/dev/null
    grep -F "clusters: ['\''tenant-a'\'']" "${CATALOGUE_VALUES_FILE}" >/dev/null
    grep -F "targetNamespace: '\''reference-debug'\''" "${CATALOGUE_VALUES_FILE}" >/dev/null
    grep -F "fullnameOverride: '\''debug-catalogue'\''" "${CATALOGUE_VALUES_FILE}" >/dev/null
  ' bash "${script_without_main}"

echo "reference usage script checks passed"
