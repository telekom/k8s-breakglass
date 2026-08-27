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
RUN_ID="$(od -An -N8 -tx1 /dev/urandom | tr -d ' \n')"
CLUSTER_NAME_BASE="${VALIDATOR_INTEGRATION_CLUSTER:-cluster-validator-integration}"
CLUSTER_NAME="${CLUSTER_NAME_BASE:0:40}-${RUN_ID}"
NAMESPACE="validator-integration"
IMAGE_BASE="${VALIDATOR_INTEGRATION_IMAGE:-cluster-validator-integration:${GITHUB_SHA:-local}}"
IMAGE="${IMAGE_BASE}-${RUN_ID}"
KIND_NODE_IMAGE="${KIND_NODE_IMAGE:-kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5}"
WORK_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cluster-validator-integration.XXXXXX")"
ARTIFACT_DIR="${VALIDATOR_INTEGRATION_ARTIFACT_DIR:-${RUNNER_TEMP:-/tmp}/cluster-validator-integration-artifacts}"
ARTIFACT_STAGE_DIR="$(mktemp -d "${TMPDIR:-/tmp}/cluster-validator-integration-artifacts.XXXXXX")"
KUBECONFIG_FILE="${WORK_DIR}/kind.kubeconfig"
HELPER_KUBECONFIG="${WORK_DIR}/extension.kubeconfig"
SERVICE_ACCOUNT="system:serviceaccount:${NAMESPACE}:cluster-validator"
CLUSTER_ROLE="cluster-validator-integration"
CLUSTER_ROLE_BINDING="cluster-validator-integration"
SECRET_NAME="validator-secret-sentinel"
SECRET_MARKER="validator-secret-marker-${RANDOM}-${RANDOM}"
SERVICE_ACCOUNT_TOKEN=""
CLUSTER_CREATED=false
CLUSTER_ATTEMPTED=false
IMAGE_BUILT=false
IMAGE_BUILD_ATTEMPTED=false
IMAGE_BUILT_ID=""
CLUSTER_NODE_IDS=""
WORK_DIR_ID=""
ARTIFACT_STAGE_ID=""
ARTIFACT_OUTPUT_ID=""
ARTIFACT_OUTPUT_CREATED=false
ARTIFACT_OUTPUT_KEEP=false

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
  local current_image_id remaining_clusters
  set +e
  if [[ "${exit_code}" != 0 ]]; then
    preserve_diagnostics
    if [[ "${ARTIFACT_OUTPUT_KEEP}" == true ]]; then
      printf 'Diagnostics preserved at %s\n' "${ARTIFACT_DIR}" >&2
    else
      printf 'Diagnostics were not published because the requested artifact path was unsafe or already existed.\n' >&2
    fi
  fi
  if [[ "${CLUSTER_CREATED}" == true && -f "${KUBECONFIG_FILE}" ]]; then
    if cluster_is_owned; then
      KUBECONFIG="${KUBECONFIG_FILE}" kubectl delete namespace "${NAMESPACE}" --ignore-not-found --wait --timeout=60s >/dev/null 2>&1
      KUBECONFIG="${KUBECONFIG_FILE}" kubectl delete clusterrolebinding "${CLUSTER_ROLE_BINDING}" --ignore-not-found --wait >/dev/null 2>&1
      KUBECONFIG="${KUBECONFIG_FILE}" kubectl delete clusterrole "${CLUSTER_ROLE}" --ignore-not-found --wait >/dev/null 2>&1
    fi
  fi
  if [[ "${CLUSTER_CREATED}" == true ]]; then
    if cluster_is_owned; then
      kind delete cluster --name "${CLUSTER_NAME}" >/dev/null 2>&1
      if ! remaining_clusters="$(kind get clusters 2>/dev/null)"; then
        printf 'cluster-validator-integration: unable to verify kind cluster removal: %s\n' "${CLUSTER_NAME}" >&2
        exit_code=1
      elif grep -Fqx -- "${CLUSTER_NAME}" <<<"${remaining_clusters}"; then
        printf 'cluster-validator-integration: owned kind cluster was not removed: %s\n' "${CLUSTER_NAME}" >&2
        exit_code=1
      fi
    else
      printf 'cluster-validator-integration: refusing to delete kind cluster with changed ownership: %s\n' "${CLUSTER_NAME}" >&2
      exit_code=1
    fi
  elif [[ "${CLUSTER_ATTEMPTED}" == true ]]; then
    if ! remaining_clusters="$(kind get clusters 2>/dev/null)"; then
      printf 'cluster-validator-integration: unable to verify failed kind creation left no cluster: %s\n' "${CLUSTER_NAME}" >&2
      exit_code=1
    elif grep -Fqx -- "${CLUSTER_NAME}" <<<"${remaining_clusters}"; then
      printf 'cluster-validator-integration: failed kind creation left a cluster without ownership proof: %s\n' "${CLUSTER_NAME}" >&2
      exit_code=1
    fi
  fi
  if [[ "${IMAGE_BUILD_ATTEMPTED}" == true && "${IMAGE_BUILT}" != true ]] &&
    docker image inspect "${IMAGE}" >/dev/null 2>&1; then
    printf 'cluster-validator-integration: failed image build left an image without ownership proof: %s\n' "${IMAGE}" >&2
    exit_code=1
  fi
  if [[ "${IMAGE_BUILT}" == true && -n "${IMAGE_BUILT_ID}" ]]; then
    current_image_id="$(docker image inspect --format '{{.Id}}' "${IMAGE}" 2>/dev/null || true)"
    if [[ "${current_image_id}" == "${IMAGE_BUILT_ID}" ]]; then
      docker image rm "${IMAGE}" >/dev/null 2>&1
      if docker image inspect "${IMAGE}" >/dev/null 2>&1; then
        printf 'cluster-validator-integration: owned image tag was not removed: %s\n' "${IMAGE}" >&2
        exit_code=1
      fi
    else
      printf 'cluster-validator-integration: refusing to remove image tag changed after build: %s\n' "${IMAGE}" >&2
      exit_code=1
    fi
  fi
  if [[ "${ARTIFACT_OUTPUT_CREATED}" == true && "${ARTIFACT_OUTPUT_KEEP}" != true ]]; then
    if remove_owned_directory "${ARTIFACT_DIR}" "${ARTIFACT_OUTPUT_ID}"; then
      ARTIFACT_OUTPUT_CREATED=false
    else
      printf 'cluster-validator-integration: refusing to remove changed artifact directory: %s\n' "${ARTIFACT_DIR}" >&2
      exit_code=1
    fi
  fi
  if ! remove_owned_directory "${ARTIFACT_STAGE_DIR}" "${ARTIFACT_STAGE_ID}"; then
    printf 'cluster-validator-integration: owned artifact staging directory was not removed: %s\n' "${ARTIFACT_STAGE_DIR}" >&2
    exit_code=1
  fi
  if ! remove_owned_directory "${WORK_DIR}" "${WORK_DIR_ID}"; then
    printf 'cluster-validator-integration: refusing to remove changed work directory: %s\n' "${WORK_DIR}" >&2
    exit_code=1
  fi
  exit "${exit_code}"
}
trap cleanup EXIT

directory_identity() {
  local path="$1"
  local identity
  if identity="$(stat -c '%d:%i' "${path}" 2>/dev/null)"; then
    printf '%s' "${identity}"
    return 0
  fi
  stat -f '%d:%i' "${path}"
}

owned_directory() {
  local path="$1" expected_identity="$2"
  [[ -n "${expected_identity}" && -d "${path}" && ! -L "${path}" && -O "${path}" ]] || return 1
  [[ "$(directory_identity "${path}")" == "${expected_identity}" ]]
}

remove_owned_directory() {
  local path="$1" expected_identity="$2"
  owned_directory "${path}" "${expected_identity}" || return 1
  rm -rf -- "${path}" || return 1
  [[ ! -e "${path}" && ! -L "${path}" ]]
}

cluster_node_ids() {
  local node id nodes
  nodes="$(kind get nodes --name "${CLUSTER_NAME}" 2>/dev/null)" || return 1
  while IFS= read -r node; do
    [[ -n "${node}" ]] || continue
    id="$(docker inspect --format '{{.Id}}' "${node}" 2>/dev/null)" || return 1
    printf '%s\n' "${id}"
  done <<<"${nodes}"
}

cluster_is_owned() {
  local current_cluster_ids
  [[ -n "${CLUSTER_NODE_IDS}" ]] || return 1
  current_cluster_ids="$(cluster_node_ids | LC_ALL=C sort)" || return 1
  [[ "${current_cluster_ids}" == "${CLUSTER_NODE_IDS}" ]]
}

preserve_diagnostics() {
  local source base
  local copy_failed=false
  local unsafe=false
  local grep_status

  # Diagnostics are first assembled in a private mktemp directory. A caller
  # supplied output path is never read, recursively cleaned, or treated as a
  # trusted staging area. The final directory is created only when absent and
  # receives only the verified allowlist below.
  if [[ -e "${ARTIFACT_DIR}" || -L "${ARTIFACT_DIR}" ]]; then
    printf 'refusing diagnostic publication into an existing or symlinked path: %s\n' "${ARTIFACT_DIR}" >&2
    return 0
  fi
  if ! mkdir -- "${ARTIFACT_DIR}" 2>/dev/null || [[ ! -d "${ARTIFACT_DIR}" || -L "${ARTIFACT_DIR}" ]]; then
    printf 'refusing diagnostic publication into unsafe path: %s\n' "${ARTIFACT_DIR}" >&2
    return 0
  fi
  chmod 700 "${ARTIFACT_DIR}" || return 0
  ARTIFACT_OUTPUT_CREATED=true
  ARTIFACT_OUTPUT_ID="$(directory_identity "${ARTIFACT_DIR}")"

  # Only the fixed, credential-free diagnostics produced by this script leave
  # the temporary directory. Never glob arbitrary future logs: a new command's
  # output must be explicitly reviewed before it can become an artifact.
  local allowed_sources=(
    "${WORK_DIR}/configmap-denied.log"
    "${WORK_DIR}/secret-denied.log"
    "${WORK_DIR}/one-time-1.log"
    "${WORK_DIR}/one-time-2.log"
    "${WORK_DIR}/post-upgrade.log"
    "${WORK_DIR}/not-ready.log"
    "${WORK_DIR}/extension.log"
    "${WORK_DIR}/extension.stderr"
    "${WORK_DIR}/events.txt"
    "${WORK_DIR}/one-time-1-status.txt"
    "${WORK_DIR}/one-time-1-describe.txt"
    "${WORK_DIR}/one-time-2-status.txt"
    "${WORK_DIR}/one-time-2-describe.txt"
    "${WORK_DIR}/post-upgrade-status.txt"
    "${WORK_DIR}/post-upgrade-describe.txt"
  )
  for source in "${allowed_sources[@]}"; do
    [[ -f "${source}" ]] || continue
    [[ ! -L "${source}" ]] || { copy_failed=true; continue; }
    base="$(basename "${source}")"
    # Hard-linking from the private stage cannot follow a destination symlink
    # and cannot overwrite a pre-existing destination file. This also avoids a
    # copy-then-replace race on diagnostics that may contain sensitive output.
    if ! cp -P -- "${source}" "${ARTIFACT_STAGE_DIR}/${base}" >/dev/null 2>&1 ||
      [[ ! -f "${ARTIFACT_STAGE_DIR}/${base}" ]] || [[ -L "${ARTIFACT_STAGE_DIR}/${base}" ]]; then
      copy_failed=true
    fi
  done
  # Prove the allowlist did not leak credentials. A suspicious artifact is not
  # uploaded, and the complete artifact set is discarded so a partial upload
  # cannot be mistaken for a safe diagnostic bundle.
  local sensitive_pattern='BEGIN [A-Z0-9 ]*PRIVATE KEY|client-(certificate|key)-data:|(^|[[:space:]])(token|password|passwd|secret)[[:space:]]*[:=]|authorization:[[:space:]]*bearer[[:space:]]'
  while IFS= read -r -d '' source; do
    grep -Eiq "${sensitive_pattern}" "${source}"
    grep_status=$?
    if [[ "${grep_status}" -eq 0 || "${grep_status}" -gt 1 ]]; then
      unsafe=true
    fi
    if [[ -n "${SERVICE_ACCOUNT_TOKEN}" ]]; then
      grep -Fq "${SERVICE_ACCOUNT_TOKEN}" "${source}"
      grep_status=$?
      if [[ "${grep_status}" -eq 0 || "${grep_status}" -gt 1 ]]; then unsafe=true; fi
    fi
    grep -Fq "${SECRET_MARKER}" "${source}"
    grep_status=$?
    if [[ "${grep_status}" -eq 0 || "${grep_status}" -gt 1 ]]; then unsafe=true; fi
  done < <(find "${ARTIFACT_STAGE_DIR}" -mindepth 1 -maxdepth 1 -type f -print0)
  if find "${ARTIFACT_STAGE_DIR}" -mindepth 1 -maxdepth 1 ! -type f -print -quit | grep -q .; then
    unsafe=true
  fi
  if ! find "${ARTIFACT_STAGE_DIR}" -mindepth 1 -maxdepth 1 -type f -print -quit | grep -q .; then
    printf 'no allowlisted diagnostics were produced; refusing empty artifact publication\n' >&2
    if remove_owned_directory "${ARTIFACT_DIR}" "${ARTIFACT_OUTPUT_ID}"; then
      ARTIFACT_OUTPUT_CREATED=false
    fi
    return 0
  fi
  if [[ "${unsafe}" == true || "${copy_failed}" == true ]]; then
    printf 'unsafe or incomplete diagnostic artifact set; refusing diagnostic upload\n' >&2
    if remove_owned_directory "${ARTIFACT_DIR}" "${ARTIFACT_OUTPUT_ID}"; then
      ARTIFACT_OUTPUT_CREATED=false
    else
      printf 'refusing to remove changed artifact directory: %s\n' "${ARTIFACT_DIR}" >&2
    fi
    return 0
  fi

  while IFS= read -r -d '' source; do
    base="$(basename "${source}")"
    if ! owned_directory "${ARTIFACT_DIR}" "${ARTIFACT_OUTPUT_ID}" ||
      [[ -e "${ARTIFACT_DIR}/${base}" || -L "${ARTIFACT_DIR}/${base}" ]] ||
      ! ln -- "${source}" "${ARTIFACT_DIR}/${base}" 2>/dev/null; then
      printf 'unsafe or incomplete diagnostic artifact set; refusing diagnostic upload\n' >&2
      if remove_owned_directory "${ARTIFACT_DIR}" "${ARTIFACT_OUTPUT_ID}"; then
        ARTIFACT_OUTPUT_CREATED=false
      else
        printf 'refusing to remove changed artifact directory: %s\n' "${ARTIFACT_DIR}" >&2
      fi
      return 0
    fi
  done < <(find "${ARTIFACT_STAGE_DIR}" -mindepth 1 -maxdepth 1 -type f -print0)
  ARTIFACT_OUTPUT_KEEP=true
  log "credential-free diagnostics preserved at ${ARTIFACT_DIR}"
}

require_tools() {
  local tool
  for tool in docker kind kubectl jq go; do
    command -v "${tool}" >/dev/null 2>&1 || die "required tool is missing: ${tool}"
  done
  docker info >/dev/null 2>&1 || die "Docker daemon is unavailable"
}

build_image() {
  if docker image inspect "${IMAGE}" >/dev/null 2>&1; then
    die "refusing to overwrite pre-existing image tag: ${IMAGE}"
  fi
  log "Building ${IMAGE} for linux/amd64"
  IMAGE_BUILD_ATTEMPTED=true
  if ! docker build --pull --platform linux/amd64 --file "${ROOT_DIR}/utils/cluster-validator/Dockerfile" --tag "${IMAGE}" "${ROOT_DIR}"; then
    IMAGE_BUILT_ID="$(docker image inspect --format '{{.Id}}' "${IMAGE}" 2>/dev/null || true)"
    if [[ -n "${IMAGE_BUILT_ID}" ]]; then
      IMAGE_BUILT=true
    fi
    return 1
  fi
  IMAGE_BUILT_ID="$(docker image inspect --format '{{.Id}}' "${IMAGE}")"
  [[ -n "${IMAGE_BUILT_ID}" ]] || die "built image has no inspectable identity"
  IMAGE_BUILT=true
}

create_cluster() {
  local existing_clusters
  if ! existing_clusters="$(kind get clusters 2>/dev/null)"; then
    die "unable to verify that kind cluster name is unused: ${CLUSTER_NAME}"
  fi
  if grep -Fqx -- "${CLUSTER_NAME}" <<<"${existing_clusters}"; then
    die "refusing to use pre-existing kind cluster: ${CLUSTER_NAME}"
  fi
  log "Creating disposable kind cluster ${CLUSTER_NAME}"
  CLUSTER_ATTEMPTED=true
  if ! kind create cluster --name "${CLUSTER_NAME}" --image "${KIND_NODE_IMAGE}" \
    --kubeconfig "${KUBECONFIG_FILE}" --wait 180s; then
    # The generated run-scoped name is not reused by callers. If kind created
    # node containers before returning an error, capture their identities so
    # the EXIT handler can clean only this invocation's partial cluster.
    CLUSTER_NODE_IDS="$(cluster_node_ids | LC_ALL=C sort || true)"
    if [[ -n "${CLUSTER_NODE_IDS}" ]]; then
      CLUSTER_CREATED=true
    fi
    return 1
  fi
  CLUSTER_CREATED=true
  CLUSTER_NODE_IDS="$(cluster_node_ids | LC_ALL=C sort)"
  [[ -n "${CLUSTER_NODE_IDS}" ]] || die "created kind cluster has no identifiable node containers"
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

wait_for_active_pods_ready() {
  for _ in $(seq 1 60); do
    if kubectl get pods --all-namespaces -o json 2>/dev/null | jq -e '
      all(.items[];
        .status.phase == "Succeeded" or
        (.status.phase == "Running" and
          any(.status.conditions[]?; .type == "Ready" and .status == "True")))
    ' >/dev/null; then
      return 0
    fi
    sleep 1
  done
  return 1
}

run_image_case() {
  local name="$1" mode="$2"
  local pod_file="${WORK_DIR}/${name}.yaml" log_file="${WORK_DIR}/${name}.log"
  wait_for_active_pods_ready || die "active cluster pods did not become Ready before ${name}"
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
  if [[ "${phase}" != Succeeded ]]; then
    collect_pod_diagnostics "${name}"
    printf '%s\n' "--- ${name} report/log ---" >&2
    cat "${log_file}" >&2 || true
    die "${name} did not succeed; report saved at ${log_file}"
  fi
  exit_code="$(kubectl get pod "${name}" -n "${NAMESPACE}" -o jsonpath='{.status.containerStatuses[0].state.terminated.exitCode}')"
  if [[ "${exit_code}" != 0 ]]; then
    collect_pod_diagnostics "${name}"
    printf '%s\n' "--- ${name} report/log ---" >&2
    cat "${log_file}" >&2 || true
    die "${name} returned exit code ${exit_code}; report saved at ${log_file}"
  fi
  assert_report "${log_file}" "${mode}"
  assert_no_leaks "${log_file}"
}

collect_pod_diagnostics() {
  local pod="$1"
  kubectl get pod "${pod}" -n "${NAMESPACE}" -o wide >"${WORK_DIR}/${pod}-status.txt" 2>&1 || true
  kubectl describe pod "${pod}" -n "${NAMESPACE}" >"${WORK_DIR}/${pod}-describe.txt" 2>&1 || true
  kubectl get events -n "${NAMESPACE}" --sort-by=.lastTimestamp >"${WORK_DIR}/events.txt" 2>&1 || true
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
  WORK_DIR_ID="$(directory_identity "${WORK_DIR}")"
  ARTIFACT_STAGE_ID="$(directory_identity "${ARTIFACT_STAGE_DIR}")"
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
