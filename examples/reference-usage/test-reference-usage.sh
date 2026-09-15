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
cosign_log_file="${test_root}/cosign.log"
namespace_uid_file="${test_root}/namespace.uid"

cat >"${fake_bin}/kubectl" <<'SH'
#!/bin/sh
printf 'kubectl %s\n' "$*" >>"${REFERENCE_KUBECTL_LOG}"
if [ "$1" = "apply" ] && [ "$2" = "-f" ] && [ "$3" = "-" ]; then
  cat >>"${REFERENCE_KUBECTL_STDIN_LOG}"
fi
if [ "$1" = "get" ] && [ "$2" = "namespace" ]; then
  if [ -e "${REFERENCE_NAMESPACE_UID_FILE}" ]; then
    namespace_uid=$(cat "${REFERENCE_NAMESPACE_UID_FILE}")
    if [ "${4:-}" = "jsonpath={.metadata.uid}" ]; then
      printf '%s\n' "${namespace_uid}"
    else
      printf '%s\n' "{\"metadata\":{\"uid\":\"${namespace_uid}\"}}"
    fi
    exit 0
  fi
  case " $* " in
    *" --ignore-not-found "*) exit 0 ;;
  esac
  printf 'Error from server (NotFound): namespaces "reference-debug" not found\n' >&2
  exit 1
fi
if [ "$1" = "create" ] && [ "$2" = "namespace" ]; then
  printf '%s\n' 'uid-reference' >"${REFERENCE_NAMESPACE_UID_FILE}"
  case " $* " in
    *" -o json "*) printf '%s\n' '{"metadata":{"uid":"uid-reference"}}' ;;
  esac
  exit 0
fi
if [ "$1" = "delete" ] && [ "$2" = "namespace" ] && [ "${REFERENCE_NAMESPACE_DELETE_FAIL:-0}" = 1 ]; then
  exit 1
fi
if [ "$1" = "delete" ] && [ "$2" = "--raw" ]; then
  delete_options=''
  while [ "$#" -gt 0 ]; do
    if [ "${1:-}" = "-f" ]; then delete_options="${2:?}"; break; fi
    shift
  done
  if [ "${REFERENCE_NAMESPACE_DELETE_FAIL:-0}" = 1 ]; then
    exit 1
  fi
  if [ "${REFERENCE_NAMESPACE_RACE:-0}" = 1 ]; then
    printf '%s\n' 'uid-foreign' >"${REFERENCE_NAMESPACE_UID_FILE}"
    exit 1
  fi
  grep -Fq '"uid":"uid-reference"' "${delete_options:?}" || exit 1
  rm -f "${REFERENCE_NAMESPACE_UID_FILE}"
  exit 0
fi
if [ "$1" = "wait" ]; then
  exit 0
fi
if [ "$1" = "delete" ] && [ "$2" = "namespace" ]; then
  rm -f "${REFERENCE_NAMESPACE_UID_FILE}"
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

cat >"${fake_bin}/cosign" <<'SH'
#!/bin/sh
printf '%s\n' "$*" >>"${REFERENCE_COSIGN_LOG}"
exit 0
SH
chmod +x "${fake_bin}/cosign"

# Load the production functions without starting the full reference flow.
script_without_main="${test_root}/reference-usage-functions.sh"
sed '$d' "${script}" >"${script_without_main}"
printf '%s\n' 'uid-reference' >"${namespace_uid_file}"
REFERENCE_KUBECTL_LOG="${log_file}" REFERENCE_KUBECTL_STDIN_LOG="${stdin_log_file}" REFERENCE_NAMESPACE_UID_FILE="${namespace_uid_file}" PATH="${fake_bin}:${PATH}" \
  KUBECONFIG="${test_root}/kubeconfig" bash -c '
    source "$1"
    trap - EXIT
    KUBECONFIG_FILE="$KUBECONFIG"
    AUDIT_CONFIG_CREATED=true
    DEBUG_NAMESPACE_CREATED=true
    DEBUG_NAMESPACE_UID="uid-reference"
    SESSION_NAME=session-a
    REJECTED_SESSION_NAME=session-b
    DEBUG_SESSION_NAME=debug-a
    ELEVATED_DEBUG_SESSION_NAME=debug-b
    cleanup
    assert_zero_residual
  ' bash "${script_without_main}"

REFERENCE_COSIGN_LOG="${cosign_log_file}" PATH="${fake_bin}:${PATH}" bash -c '
  source "$1"
  MODE=published
  VERIFY_SUPPLY_CHAIN=true
  PUBLISHED_IMAGE_DIGEST_REF="ghcr.io/telekom/k8s-breakglass@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
  CATALOGUE_CHART_DIGEST="sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
  verify_public_artifacts
' bash "${script_without_main}"
test "$(grep -c -- '--type slsaprovenance1' "${cosign_log_file}")" -eq 2
if grep -Fq -- '--type slsaprovenance ' "${cosign_log_file}"; then
  echo "legacy SLSA provenance type was used" >&2
  exit 1
fi

while IFS= read -r line; do
  case "${line}" in
    *"kubectl delete"*--wait=false*)
      ;;
    *"kubectl delete --raw"*--request-timeout\ *60s*)
      ;;
    *"kubectl delete"*--wait*--timeout\ *60s*)
      ;;
    *"kubectl delete"*)
      echo "unbounded delete: ${line}" >&2
      exit 1
      ;;
  esac
done <"${log_file}"
grep -F "kubectl delete --raw /api/v1/namespaces/reference-debug --request-timeout 60s" "${log_file}" >/dev/null
test "$(grep -c "kubectl get namespace reference-debug --ignore-not-found --request-timeout 60s -o json" "${log_file}")" -ge 2

printf '%s\n' 'uid-reference' >"${namespace_uid_file}"
if REFERENCE_KUBECTL_LOG="${log_file}" REFERENCE_KUBECTL_STDIN_LOG="${stdin_log_file}" REFERENCE_NAMESPACE_UID_FILE="${namespace_uid_file}" \
  REFERENCE_NAMESPACE_DELETE_FAIL=1 PATH="${fake_bin}:${PATH}" \
  KUBECONFIG="${test_root}/kubeconfig" bash -c '
    source "$1"
    trap - EXIT
    KUBECONFIG_FILE="$KUBECONFIG"
    DEBUG_NAMESPACE_CREATED=true
    DEBUG_NAMESPACE_UID="uid-reference"
    cleanup
  ' bash "${script_without_main}"; then
  echo "namespace cleanup failure unexpectedly succeeded" >&2
  exit 1
fi

printf '%s\n' 'uid-foreign' >"${namespace_uid_file}"
if REFERENCE_KUBECTL_LOG="${log_file}" REFERENCE_KUBECTL_STDIN_LOG="${stdin_log_file}" REFERENCE_NAMESPACE_UID_FILE="${namespace_uid_file}" \
  PATH="${fake_bin}:${PATH}" KUBECONFIG="${test_root}/kubeconfig" bash -c '
    source "$1"
    trap - EXIT
    KUBECONFIG_FILE="$KUBECONFIG"
    DEBUG_NAMESPACE_CREATED=true
    DEBUG_NAMESPACE_UID="uid-reference"
    cleanup
  ' bash "${script_without_main}"; then
  echo "namespace replacement unexpectedly succeeded" >&2
  exit 1
fi
test "$(cat "${namespace_uid_file}")" = uid-foreign

printf '%s\n' 'uid-reference' >"${namespace_uid_file}"
if REFERENCE_KUBECTL_LOG="${log_file}" REFERENCE_KUBECTL_STDIN_LOG="${stdin_log_file}" REFERENCE_NAMESPACE_UID_FILE="${namespace_uid_file}" \
  REFERENCE_NAMESPACE_RACE=1 PATH="${fake_bin}:${PATH}" KUBECONFIG="${test_root}/kubeconfig" bash -c '
    source "$1"
    trap - EXIT
    KUBECONFIG_FILE="$KUBECONFIG"
    DEBUG_NAMESPACE_CREATED=true
    DEBUG_NAMESPACE_UID="uid-reference"
    cleanup
  ' bash "${script_without_main}"; then
  echo "namespace UID race unexpectedly succeeded" >&2
  exit 1
fi
test "$(cat "${namespace_uid_file}")" = uid-foreign

printf '%s\n' 'uid-reference' >"${namespace_uid_file}"
success_state_marker="${test_root}/success-state-dir"
REFERENCE_KUBECTL_LOG="${log_file}" REFERENCE_KUBECTL_STDIN_LOG="${stdin_log_file}" REFERENCE_NAMESPACE_UID_FILE="${namespace_uid_file}" \
  PATH="${fake_bin}:${PATH}" KUBECONFIG="${test_root}/kubeconfig" bash -c '
    source "$1"
    KUBECONFIG_FILE="$KUBECONFIG"
    DEBUG_NAMESPACE_CREATED=true
    DEBUG_NAMESPACE_UID="uid-reference"
    printf "%s" "$STATE_DIR" >"$2"
    exit 0
  ' bash "${script_without_main}" "${success_state_marker}"
success_state_dir=$(cat "${success_state_marker}")
test ! -e "${success_state_dir}"
test ! -e "${namespace_uid_file}"

printf '%s\n' 'uid-reference' >"${namespace_uid_file}"
failure_state_marker="${test_root}/failure-state-dir"
if REFERENCE_KUBECTL_LOG="${log_file}" REFERENCE_KUBECTL_STDIN_LOG="${stdin_log_file}" REFERENCE_NAMESPACE_UID_FILE="${namespace_uid_file}" \
  REFERENCE_NAMESPACE_DELETE_FAIL=1 PATH="${fake_bin}:${PATH}" KUBECONFIG="${test_root}/kubeconfig" bash -c '
    source "$1"
    KUBECONFIG_FILE="$KUBECONFIG"
    DEBUG_NAMESPACE_CREATED=true
    DEBUG_NAMESPACE_UID="uid-reference"
    printf "%s" "$STATE_DIR" >"$2"
    exit 7
  ' bash "${script_without_main}" "${failure_state_marker}"; then
  echo "cleanup unexpectedly changed failed command to success" >&2
  exit 1
else
  test "$?" -eq 7
fi
failure_state_dir=$(cat "${failure_state_marker}")
test ! -e "${failure_state_dir}"
test -e "${namespace_uid_file}"

REFERENCE_KUBECTL_LOG="${log_file}" REFERENCE_KUBECTL_STDIN_LOG="${stdin_log_file}" REFERENCE_NAMESPACE_UID_FILE="${namespace_uid_file}" PATH="${fake_bin}:${PATH}" \
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

REFERENCE_KUBECTL_LOG="${log_file}" REFERENCE_KUBECTL_STDIN_LOG="${stdin_log_file}" REFERENCE_NAMESPACE_UID_FILE="${namespace_uid_file}" PATH="${fake_bin}:${PATH}" \
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

rm -f "${namespace_uid_file}"
REFERENCE_KUBECTL_LOG="${log_file}" REFERENCE_KUBECTL_STDIN_LOG="${stdin_log_file}" REFERENCE_NAMESPACE_UID_FILE="${namespace_uid_file}" PATH="${fake_bin}:${PATH}" \
  KUBECONFIG="${test_root}/kubeconfig" bash -c '
    source "$1"
    trap - EXIT
    REFERENCE_AUDIT_WEBHOOK_URL="https://audit.example.com/collect"
    BREAKGLASS_API_URL="http://127.0.0.1:8080"
    install_stack
  ' bash "${script_without_main}"
grep -F "kubectl create namespace reference-debug --request-timeout 60s -o json" "${log_file}" >/dev/null

echo "reference usage script checks passed"
