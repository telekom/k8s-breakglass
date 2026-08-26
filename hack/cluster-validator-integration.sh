#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

# Run the validator image against a real, disposable kind cluster. This is a
# required integration test: missing tools, a failed cluster, a failed RBAC
# assertion, or an unexpected report is an error and never a silent skip.
set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
cd "${ROOT_DIR}"
CLUSTER_NAME="${VALIDATOR_INTEGRATION_CLUSTER:-cluster-validator-integration}"
NAMESPACE="validator-integration"
IMAGE="${VALIDATOR_INTEGRATION_IMAGE:-cluster-validator-integration:${GITHUB_SHA:-local}}"
KIND_NODE_IMAGE="${KIND_NODE_IMAGE:-kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5}"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cluster-validator-integration.XXXXXX")"
KUBECONFIG_FILE="${WORK_DIR}/kind.kubeconfig"
HELPER_KUBECONFIG="${WORK_DIR}/extension.kubeconfig"
SERVICE_ACCOUNT="system:serviceaccount:${NAMESPACE}:cluster-validator"
CLUSTER_ROLE="cluster-validator-integration"
CLUSTER_ROLE_BINDING="cluster-validator-integration"
SECRET_NAME="validator-secret-sentinel"
SECRET_MARKER="validator-secret-marker-${RANDOM}-${RANDOM}"
SERVICE_ACCOUNT_TOKEN=""
CLUSTER_CREATED=false
IMAGE_BUILT=false

# These are the public values emitted by the built image. The JSON contract is
# documentation for those values, not an oracle consulted by this test.
EXPECTED_CHECKS='["api-discovery","api-server","namespaces-healthy","nodes-ready","pods-ready"]'
EXPECTED_EXTENSION_CHECKS='["api-discovery","api-server","integration-extension","namespaces-healthy","nodes-ready","pods-ready"]'

die() {
  printf 'cluster-validator-integration: %s\n' "$*" >&2
  exit 1
}

log() {
  printf 'cluster-validator-integration: %s\n' "$*"
}

cleanup() {
  local exit_code=$?
  set +e
  if [[ "${CLUSTER_CREATED}" == true && -f "${KUBECONFIG_FILE}" ]]; then
    KUBECONFIG="${KUBECONFIG_FILE}" kubectl delete namespace "${NAMESPACE}" --ignore-not-found --wait --timeout=60s >/dev/null 2>&1
    KUBECONFIG="${KUBECONFIG_FILE}" kubectl delete clusterrolebinding "${CLUSTER_ROLE_BINDING}" --ignore-not-found --wait >/dev/null 2>&1
    KUBECONFIG="${KUBECONFIG_FILE}" kubectl delete clusterrole "${CLUSTER_ROLE}" --ignore-not-found --wait >/dev/null 2>&1
  fi
  if [[ "${CLUSTER_CREATED}" == true ]]; then
    kind delete cluster --name "${CLUSTER_NAME}" >/dev/null 2>&1
  fi
  if [[ "${IMAGE_BUILT}" == true ]]; then
    docker image rm "${IMAGE}" >/dev/null 2>&1
  fi
  rm -rf "${WORK_DIR}"
  exit "${exit_code}"
}
trap cleanup EXIT

require_tools() {
  local tool
  for tool in docker kind kubectl jq go; do
    command -v "${tool}" >/dev/null 2>&1 || die "required tool is missing: ${tool}"
  done
  docker info >/dev/null 2>&1 || die "Docker daemon is unavailable"
}

build_image() {
  log "Building ${IMAGE} for linux/amd64"
  docker build --pull --platform linux/amd64 --file "${ROOT_DIR}/Dockerfile.validator" --tag "${IMAGE}" "${ROOT_DIR}"
  IMAGE_BUILT=true
}

create_cluster() {
  log "Creating disposable kind cluster ${CLUSTER_NAME}"
  kind create cluster --name "${CLUSTER_NAME}" --image "${KIND_NODE_IMAGE}" \
    --kubeconfig "${KUBECONFIG_FILE}" --wait 180s
  CLUSTER_CREATED=true
  export KUBECONFIG="${KUBECONFIG_FILE}"
  kubectl wait --for=condition=Ready nodes --all --timeout=180s >/dev/null
  kubectl wait --for=condition=Ready pods --all --all-namespaces --timeout=180s >/dev/null
  kind load docker-image "${IMAGE}" --name "${CLUSTER_NAME}"
}

install_rbac() {
  kubectl apply -f - <<YAML
apiVersion: v1
kind: Namespace
metadata:
  name: ${NAMESPACE}
---
apiVersion: v1
kind: ServiceAccount
metadata:
  name: cluster-validator
  namespace: ${NAMESPACE}
automountServiceAccountToken: true
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ${CLUSTER_ROLE}
rules:
  - apiGroups: [""]
    resources: ["nodes", "namespaces", "pods"]
    verbs: ["get", "list"]
  - nonResourceURLs: ["/version", "/api", "/api/*", "/apis", "/apis/*"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ${CLUSTER_ROLE_BINDING}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: ${CLUSTER_ROLE}
subjects:
  - kind: ServiceAccount
    name: cluster-validator
    namespace: ${NAMESPACE}
YAML
  for resource in nodes namespaces pods; do
    [[ "$(kubectl auth can-i list "${resource}" --as="${SERVICE_ACCOUNT}")" == yes ]] || \
      die "least-privilege service account cannot list ${resource}"
  done
  [[ "$(kubectl auth can-i create configmaps -n "${NAMESPACE}" --as="${SERVICE_ACCOUNT}")" == no ]] || \
    die "least-privilege service account can mutate configmaps"
  [[ "$(kubectl auth can-i get secrets -n "${NAMESPACE}" --as="${SERVICE_ACCOUNT}")" == no ]] || \
    die "least-privilege service account can read secrets"
  kubectl -n "${NAMESPACE}" create secret generic "${SECRET_NAME}" --from-literal=marker="${SECRET_MARKER}" >/dev/null
}

create_service_account_kubeconfig() {
  SERVICE_ACCOUNT_TOKEN="$(kubectl create token cluster-validator -n "${NAMESPACE}")"
  [[ -n "${SERVICE_ACCOUNT_TOKEN}" ]] || die "kind did not issue a service-account token"
  local server ca_data
  server="$(kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.server}')"
  ca_data="$(kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}')"
  [[ -n "${server}" && -n "${ca_data}" ]] || die "kind kubeconfig did not contain server and CA data"
  cat >"${HELPER_KUBECONFIG}" <<YAML
apiVersion: v1
kind: Config
clusters:
  - name: integration
    cluster:
      server: ${server}
      certificate-authority-data: ${ca_data}
users:
  - name: cluster-validator
    user:
      token: ${SERVICE_ACCOUNT_TOKEN}
contexts:
  - name: integration
    context:
      cluster: integration
      user: cluster-validator
current-context: integration
YAML
  chmod 600 "${HELPER_KUBECONFIG}"
}

assert_forbidden_operations() {
  local configmap_name="validator-forbidden-${RANDOM}"
  if kubectl create configmap "${configmap_name}" -n "${NAMESPACE}" \
    --from-literal=marker=forbidden --as="${SERVICE_ACCOUNT}" \
    >/dev/null 2>"${WORK_DIR}/configmap-denied.log"; then
    kubectl delete configmap "${configmap_name}" -n "${NAMESPACE}" --ignore-not-found >/dev/null 2>&1
    die "service account unexpectedly created a configmap"
  fi
  grep -qi forbidden "${WORK_DIR}/configmap-denied.log" || die "configmap mutation did not fail with an RBAC denial"
  if kubectl get secret "${SECRET_NAME}" -n "${NAMESPACE}" -o json --as="${SERVICE_ACCOUNT}" \
    >/dev/null 2>"${WORK_DIR}/secret-denied.log"; then
    die "service account unexpectedly read the sentinel secret"
  fi
  grep -qi forbidden "${WORK_DIR}/secret-denied.log" || die "secret access did not fail with an RBAC denial"
  assert_no_leaks "${WORK_DIR}/configmap-denied.log" "${WORK_DIR}/secret-denied.log"
}

assert_no_leaks() {
  local file
  for file in "$@"; do
    if grep -Fq "${SECRET_MARKER}" "${file}" 2>/dev/null; then
      die "secret marker leaked into ${file}"
    fi
    if [[ -n "${SERVICE_ACCOUNT_TOKEN}" ]] && grep -Fq "${SERVICE_ACCOUNT_TOKEN}" "${file}" 2>/dev/null; then
      die "service-account token leaked into ${file}"
    fi
  done
}

wait_for_pod_result() {
  local pod="$1" phase=""
  for _ in $(seq 1 180); do
    if ! phase="$(kubectl get pod "${pod}" -n "${NAMESPACE}" -o jsonpath='{.status.phase}' 2>/dev/null)"; then
      phase=""
    fi
    case "${phase}" in
      Succeeded|Failed) printf '%s' "${phase}"; return 0 ;;
    esac
    sleep 1
  done
  die "timed out waiting for pod ${pod} (last phase: ${phase})"
}

run_image_case() {
  local name="$1" mode="$2"
  local pod_file="${WORK_DIR}/${name}.yaml" log_file="${WORK_DIR}/${name}.log"
  cat >"${pod_file}" <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: ${name}
  namespace: ${NAMESPACE}
spec:
  serviceAccountName: cluster-validator
  automountServiceAccountToken: true
  restartPolicy: Never
  containers:
    - name: validator
      image: ${IMAGE}
      imagePullPolicy: Never
      command: ["/cluster-validator"]
      args: ["--mode", "${mode}", "--report", "-"]
YAML
  kubectl apply -f "${pod_file}" >/dev/null
  local phase exit_code
  phase="$(wait_for_pod_result "${name}")"
  kubectl logs "${name}" -n "${NAMESPACE}" >"${log_file}" 2>/dev/null || die "could not read ${name} log"
  [[ "${phase}" == Succeeded ]] || die "${name} did not succeed; report saved at ${log_file}"
  exit_code="$(kubectl get pod "${name}" -n "${NAMESPACE}" -o jsonpath='{.status.containerStatuses[0].state.terminated.exitCode}')"
  [[ "${exit_code}" == 0 ]] || die "${name} returned exit code ${exit_code}; report saved at ${log_file}"
  assert_report "${log_file}" "${mode}"
  assert_no_leaks "${log_file}"
}

assert_report() {
  local report_file="$1" mode="$2" expected_checks
  expected_checks="${EXPECTED_CHECKS}"
  jq -e --arg api "cluster-validator.telekom.com/v1alpha1" \
    --arg kind "ClusterValidationReport" --arg mode "${mode}" --argjson expected "${expected_checks}" '
      .apiVersion == $api and .kind == $kind and .mode == $mode and .status == "ready" and
      ([.checks[].name] == $expected) and all(.checks[]; .status == "ready") and
      (.generatedAt == null)
    ' "${report_file}" >/dev/null || die "${report_file} is not the expected deterministic ready report"
}

run_not_ready_case() {
  local bad_pod="validator-not-ready-${RANDOM}" pod_file="${WORK_DIR}/not-ready.yaml"
  cat >"${pod_file}" <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: ${bad_pod}
  namespace: ${NAMESPACE}
spec:
  restartPolicy: Never
  containers:
    - name: unavailable
      image: validator-integration-image-does-not-exist
      imagePullPolicy: Never
YAML
  kubectl apply -f "${pod_file}" >/dev/null
  local phase=""
  for _ in $(seq 1 60); do
    phase="$(kubectl get pod "${bad_pod}" -n "${NAMESPACE}" -o jsonpath='{.status.phase}' 2>/dev/null || true)"
    [[ "${phase}" == Pending || "${phase}" == Failed ]] && break
    sleep 1
  done
  [[ "${phase}" == Pending || "${phase}" == Failed ]] || die "not-ready fixture did not become unhealthy (phase: ${phase})"

  local validator_pod="validator-not-ready-run" validator_file="${WORK_DIR}/not-ready-run.yaml" log_file="${WORK_DIR}/not-ready.log"
  cat >"${validator_file}" <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: ${validator_pod}
  namespace: ${NAMESPACE}
spec:
  serviceAccountName: cluster-validator
  automountServiceAccountToken: true
  restartPolicy: Never
  containers:
    - name: validator
      image: ${IMAGE}
      imagePullPolicy: Never
      command: ["/cluster-validator"]
      args: ["--mode", "one-time", "--report", "-"]
YAML
  kubectl apply -f "${validator_file}" >/dev/null
  phase="$(wait_for_pod_result "${validator_pod}")"
  kubectl logs "${validator_pod}" -n "${NAMESPACE}" >"${log_file}" 2>/dev/null || die "could not read not-ready validator log"
  [[ "${phase}" == Failed ]] || die "not-ready validator unexpectedly succeeded"
  local exit_code expected_exit
  exit_code="$(kubectl get pod "${validator_pod}" -n "${NAMESPACE}" -o jsonpath='{.status.containerStatuses[0].state.terminated.exitCode}')"
  expected_exit=1
  [[ "${exit_code}" == "${expected_exit}" ]] || die "not-ready validator returned exit code ${exit_code}, expected ${expected_exit}"
  local expected_checks
  expected_checks="${EXPECTED_CHECKS}"
  jq -e --argjson expected "${expected_checks}" '
    .status == "not-ready" and ([.checks[].name] == $expected) and
    (any(.checks[]; .name == "pods-ready" and .status == "not-ready")) and
    (.generatedAt == null)
  ' "${log_file}" >/dev/null || die "not-ready report did not identify the unhealthy pod check"
  assert_no_leaks "${log_file}"
  kubectl delete pod "${bad_pod}" "${validator_pod}" -n "${NAMESPACE}" --ignore-not-found --wait >/dev/null
}

run_invalid_mode_case() {
  local output_file="${WORK_DIR}/invalid-mode.log" exit_code
  set +e
  docker run --rm --entrypoint /cluster-validator "${IMAGE}" --mode unsupported --report - >"${output_file}" 2>&1
  exit_code=$?
  set -e
  [[ "${exit_code}" == 2 ]] || die "invalid mode returned ${exit_code}, expected documented exit code 2"
  grep -Fq 'invalid mode' "${output_file}" || die "invalid mode did not report a configuration error"
  assert_no_leaks "${output_file}"
}

run_extension_case() {
  local binary="${WORK_DIR}/cluster-validator-extension" report_file="${WORK_DIR}/extension.log"
  go build -trimpath -o "${binary}" ./hack/cluster-validator-extension
  local expected_exit actual_exit
  expected_exit=0
  set +e
  "${binary}" --kubeconfig "${HELPER_KUBECONFIG}" --mode one-time >"${report_file}" 2>"${WORK_DIR}/extension.stderr"
  actual_exit=$?
  set -e
  [[ "${actual_exit}" == "${expected_exit}" ]] || die "extension contract returned exit code ${actual_exit}, expected ${expected_exit}"
  local expected_checks
  expected_checks="${EXPECTED_EXTENSION_CHECKS}"
  jq -e --argjson expected "${expected_checks}" '
    .apiVersion == "cluster-validator.telekom.com/v1alpha1" and
    .kind == "ClusterValidationReport" and .status == "ready" and .mode == "one-time" and
    ([.checks[].name] | sort) == $expected and
    any(.checks[]; .name == "integration-extension" and .status == "ready")
  ' "${report_file}" >/dev/null || die "extension contract report was not ready and complete"
  assert_no_leaks "${report_file}" "${WORK_DIR}/extension.stderr"
}

assert_determinism() {
  local first second normalized_first normalized_second
  first="${WORK_DIR}/one-time-1.log"
  second="${WORK_DIR}/one-time-2.log"
  cmp -s "${first}" "${second}" || die "identical one-time runs produced different reports"
  normalized_first="${WORK_DIR}/one-time-normalized.json"
  normalized_second="${WORK_DIR}/post-upgrade-normalized.json"
  jq -S 'del(.mode)' "${first}" >"${normalized_first}"
  jq -S 'del(.mode)' "${WORK_DIR}/post-upgrade.log" >"${normalized_second}"
  cmp -s "${normalized_first}" "${normalized_second}" || die "one-time and post-upgrade reports differ beyond mode"
}

assert_zero_residuals() {
  kubectl delete pod --all -n "${NAMESPACE}" --ignore-not-found --wait >/dev/null
  kubectl delete secret "${SECRET_NAME}" -n "${NAMESPACE}" --ignore-not-found --wait >/dev/null
  kubectl delete namespace "${NAMESPACE}" --ignore-not-found --wait --timeout=60s >/dev/null
  kubectl get namespace "${NAMESPACE}" >/dev/null 2>&1 && die "integration namespace remains"
  kubectl delete clusterrolebinding "${CLUSTER_ROLE_BINDING}" --ignore-not-found --wait >/dev/null
  kubectl delete clusterrole "${CLUSTER_ROLE}" --ignore-not-found --wait >/dev/null
  kubectl get clusterrolebinding "${CLUSTER_ROLE_BINDING}" >/dev/null 2>&1 && die "integration ClusterRoleBinding remains"
  kubectl get clusterrole "${CLUSTER_ROLE}" >/dev/null 2>&1 && die "integration ClusterRole remains"
  log "real-cluster integration left no validator resources"
}

main() {
  require_tools
  build_image
  create_cluster
  install_rbac
  create_service_account_kubeconfig
  assert_forbidden_operations
  run_invalid_mode_case
  run_image_case one-time-1 one-time
  run_image_case one-time-2 one-time
  run_image_case post-upgrade post-upgrade
  run_not_ready_case
  run_extension_case
  assert_determinism
  assert_zero_residuals
  log "real kind validator integration passed"
}

main "$@"
