#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

# Real Kubernetes proof for the advanced node-maintenance deployment shape.
# The recovery pod is read-only/no-capability; the repair pod uses only
# NET_ADMIN. Both run host-networked on the exact node they target.
set -Eeuo pipefail

image="${NODE_MAINTENANCE_TEST_IMAGE:?NODE_MAINTENANCE_TEST_IMAGE is required}"
kind_node_image="${NODE_MAINTENANCE_KIND_NODE_IMAGE:-kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5}"
runner_platform="linux/amd64"
run_id="node-maintenance-host-${RANDOM}-${RANDOM}"
namespace="${run_id}"
cluster="${run_id}"
kubeconfig="$(mktemp "${TMPDIR:-/tmp}/node-maintenance-host-kubeconfig.XXXXXX")"
image_archive_dir="$(mktemp -d "${TMPDIR:-/tmp}/node-maintenance-host-image.XXXXXX")"
image_archive="${image_archive_dir}/image.tar"
load_log="${image_archive_dir}/kind-load.log"
KIND_BIN=${KIND_BIN:-kind}
DOCKER_BIN=${DOCKER_BIN:-docker}
export KIND_CLUSTER_NAME="$cluster" KIND_NODE_IMAGE="$kind_node_image" KUBECONFIG_FILE="$kubeconfig" KIND_CLUSTER_CREATED=false KIND_CLUSTER_OWNER_IDS=''
# shellcheck source=../../../hack/kind-ownership.sh
# shellcheck disable=SC1091
script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
# shellcheck disable=SC1091
. "${script_dir}/../../../hack/kind-ownership.sh"
cluster_create_attempted=false

fail() { printf 'node-maintenance host-network proof: %s\n' "$*" >&2; exit 1; }
cleanup() {
	rc=$?
	set +e
	if [[ "${cluster_create_attempted}" == true ]]; then
		if [[ "${rc}" != 0 && "${KIND_CLUSTER_CREATED}" == true ]]; then
			printf 'Failure-state Kind pods:\n'
			KUBECONFIG="${kubeconfig}" kubectl get pods -A -o wide 2>&1 || true
			KUBECONFIG="${kubeconfig}" kubectl describe pods -n "${namespace}" 2>&1 || true
			KUBECONFIG="${kubeconfig}" kubectl get events -A --sort-by=.lastTimestamp 2>&1 || true
		fi
		if [[ "${KIND_CLUSTER_CREATED}" == true ]]; then
			kind_cleanup_owned_cluster || rc=1
		fi
	fi
	rm -f "${kubeconfig}"
	rm -f "${image_archive}"
	rm -f "${load_log}"
	rmdir "${image_archive_dir}" 2>/dev/null || true
	exit "${rc}"
}
trap cleanup EXIT
on_error() {
	rc=$?
	printf 'node-maintenance host-network proof: command failed at line %s (status %s): %s\n' "${BASH_LINENO[0]}" "${rc}" "${BASH_COMMAND}" >&2
	return "${rc}"
}
trap on_error ERR

for command in "${DOCKER_BIN}" "${KIND_BIN}" kubectl jq; do command -v "${command}" >/dev/null 2>&1 || fail "${command} is required"; done
[[ "${image}" != *@sha256:* ]] || fail 'NODE_MAINTENANCE_TEST_IMAGE must be a local tag, not a digest reference'
"${DOCKER_BIN}" image inspect "${image}" >/dev/null 2>&1 || fail "image is unavailable: ${image}"
[[ "$(uname -s)" == Linux ]] || fail "host-network proof requires a Linux runner"
docker_version="$(${DOCKER_BIN} version --format '{{.Server.Version}}' 2>/dev/null)" || fail 'Docker server version is unavailable'
case "${docker_version}" in
	28.*|29.*|[3-9][0-9].*) ;;
	*) fail "Docker >= 28 is required for platform-specific image save (found ${docker_version})" ;;
esac
printf 'Docker server: %s\n' "${docker_version}"
[[ "$(${DOCKER_BIN} image inspect --format '{{.Os}}/{{.Architecture}}' "${image}")" == "${runner_platform}" ]] || fail "image must be built for ${runner_platform}"
clusters="$(${KIND_BIN} get clusters 2>/dev/null)" || fail 'could not list Kind clusters'
grep -Fx -- "${cluster}" <<<"${clusters}" >/dev/null && fail "refusing to reuse cluster ${cluster}"
cluster_create_attempted=true
if ! kind_create_owned_cluster >/dev/null; then
	fail 'could not create disposable Kind cluster'
fi
printf 'Saving exact-platform node-maintenance image archive (%s)\n' "${runner_platform}"
"${DOCKER_BIN}" save --platform "${runner_platform}" --output "${image_archive}" "${image}" || fail 'could not save exact-platform node-maintenance image'
[[ -s "${image_archive}" ]] || fail "Docker produced an empty image archive: ${image_archive}"
printf 'Exact-platform archive size: %s bytes\n' "$(wc -c <"${image_archive}")"
tar -tf "${image_archive}" | sed -n '1,8p' >&2 || fail 'Docker produced an unreadable image archive'
printf 'Loading exact-platform node-maintenance image archive into Kind\n'
set +e
timeout --foreground 5m "${KIND_BIN}" load image-archive "${image_archive}" --name "${cluster}" >"${load_log}" 2>&1
load_status=$?
set -e
printf 'Kind archive load exited with status %s\n' "${load_status}"
if [[ "${load_status}" != 0 ]]; then
	cat "${load_log}" >&2 || true
	"${KIND_BIN}" export logs --name "${cluster}" "${TMPDIR:-/tmp}/node-maintenance-kind-logs-${run_id}" >/dev/null 2>&1 || true
	if [[ "${load_status}" == 124 ]]; then
		fail 'kind image archive load timed out after 5m'
	elif (( load_status >= 128 )); then
		fail "kind image archive load was terminated by signal $((load_status - 128))"
	else
		fail "could not load exact-platform node-maintenance image archive (status ${load_status})"
	fi
fi
printf 'Kind archive load completed\n'
export KUBECONFIG="${kubeconfig}"
if ! kubectl create namespace "${namespace}" >/dev/null; then fail 'could not create proof namespace'; fi
printf 'Proof namespace created: %s\n' "${namespace}"
if ! node="$(kubectl get nodes -o jsonpath='{.items[0].metadata.name}')"; then fail 'could not resolve Kind node'; fi
[[ "${node}" =~ ^[a-z0-9]([-a-z0-9.]*[a-z0-9])?$ ]] || fail "invalid Kind node name: ${node}"
printf 'Resolved Kind node: %s\n' "${node}"
case "${image}" in
  */*)
    case "${image%%/*}" in
      *.*|*:*) containerd_image="${image}" ;;
      *) containerd_image="docker.io/${image}" ;;
    esac
    ;;
  *) containerd_image="docker.io/library/${image}" ;;
esac
containerd_images="$(${DOCKER_BIN} exec "${cluster}-control-plane" ctr -n k8s.io images ls --quiet)" || fail 'could not inspect Kind containerd images'
if ! grep -Fx -- "${containerd_image}" <<<"${containerd_images}" >/dev/null; then
	printf 'Kind containerd images:\n%s\n' "${containerd_images}" >&2
	fail "Kind node does not contain the exact node-maintenance image (${containerd_image})"
fi
printf 'Exact node-maintenance image is present in Kind containerd\n'

assert_security() {
	pod=$1
	expected_caps=$2
	kubectl get pod "${pod}" -n "${namespace}" -o json | jq -e --arg node "${node}" --argjson caps "${expected_caps}" '
		.spec.nodeName == $node and .spec.hostNetwork == true and (.spec.hostPID // false) == false and
		.spec.automountServiceAccountToken == false and (.spec.containers | length) == 1 and
		.spec.containers[0].securityContext.runAsUser == 0 and
		.spec.containers[0].securityContext.runAsGroup == 0 and
		(.spec.containers[0].securityContext.allowPrivilegeEscalation // false) == false and
		(.spec.containers[0].securityContext.privileged // false) == false and
		.spec.containers[0].securityContext.readOnlyRootFilesystem == true and
		.spec.containers[0].securityContext.seccompProfile.type == "RuntimeDefault" and
		.spec.containers[0].securityContext.capabilities.drop == ["ALL"] and
		((.spec.containers[0].securityContext.capabilities.add // []) == $caps) and
		(.spec.volumes | length) == 1 and .spec.volumes[0].name == "evidence" and
		.spec.volumes[0].emptyDir != null and (.spec.containers[0].volumeMounts | length) == 1 and
		.spec.containers[0].volumeMounts[0].name == "evidence" and .spec.containers[0].volumeMounts[0].mountPath == "/evidence"
	' >/dev/null || fail "security or exact-node boundary was not retained for ${pod}"
}

run_pod() {
	pod=$1
	command_name=$2
	confirmation=$3
	approved_action=$4
	caps=$5
	expected_exit=$6
	printf 'Applying proof pod: %s\n' "${pod}"
	approved_request="target_node=${node}&interface=lo&action=${approved_action}&neighbor_address=&bridge=&entry_mac=&vlan=&confirmation=${confirmation}"
	if [[ "${command_name}" == network-repair ]]; then
		helper_args="network-repair --target-node ${node} --interface lo --action ${approved_action} --evidence-dir /evidence --confirm ${confirmation}"
	else
		helper_args="node-recovery --target-node ${node} --interface lo --evidence-dir /evidence --confirm ${confirmation}"
	fi
	kubectl apply -n "${namespace}" -f - >/dev/null <<YAML || fail "could not create ${pod}"
apiVersion: v1
kind: Pod
metadata:
  name: ${pod}
spec:
  nodeName: ${node}
  hostNetwork: true
  dnsPolicy: ClusterFirstWithHostNet
  automountServiceAccountToken: false
  restartPolicy: Never
  containers:
    - name: maintenance
      image: ${image}
      imagePullPolicy: Never
      command: ["/bin/sh", "-c"]
      args:
        - |
          set +e
          /usr/local/bin/node-maintenance ${helper_args}
          helper_status=\$?
          printf '%s\n' "\${helper_status}" > /evidence/helper.exit
          sleep 300
          exit "\${helper_status}"
      env:
        - name: BREAKGLASS_NODE_NAME
          value: "${node}"
        - name: BREAKGLASS_OPERATION_ID
          value: "${run_id}-${pod}"
        - name: BREAKGLASS_RECORDING_ID
          value: "recording-${pod}"
        - name: BREAKGLASS_APPROVAL_ID
          value: "approval-${pod}"
        - name: BREAKGLASS_APPROVED_ACTION
          value: "${approved_action}"
        - name: BREAKGLASS_APPROVED_NETWORK_REQUEST
          value: "${approved_request}"
      securityContext:
        runAsUser: 0
        runAsGroup: 0
        allowPrivilegeEscalation: false
        privileged: false
        readOnlyRootFilesystem: true
        seccompProfile:
          type: RuntimeDefault
        capabilities:
          drop: [ALL]
          add: ${caps}
      volumeMounts:
        - name: evidence
          mountPath: /evidence
  volumes:
    - name: evidence
      emptyDir:
        sizeLimit: 64Mi
YAML
	assert_security "${pod}" "${caps}"
	printf 'Security contract passed: %s\n' "${pod}"
	kubectl wait -n "${namespace}" --for=jsonpath='{.status.phase}'=Running "pod/${pod}" --timeout=120s >/dev/null || { kubectl logs -n "${namespace}" "${pod}" >&2 || true; fail "${pod} did not start"; }
	printf 'Pod reached Running: %s\n' "${pod}"
	for _ in $(seq 1 60); do
		kubectl exec -n "${namespace}" "${pod}" -- test -s /evidence/helper.exit >/dev/null 2>&1 && break
		sleep 1
	done
	kubectl exec -n "${namespace}" "${pod}" -- test -s /evidence/helper.exit >/dev/null || { kubectl logs -n "${namespace}" "${pod}" >&2 || true; fail "${pod} did not complete its helper"; }
	printf 'Helper completed: %s\n' "${pod}"
	logs="$(kubectl logs -n "${namespace}" "${pod}")"
	printf '%s\n' "${logs}" | grep -E '/evidence/[A-Za-z0-9_.-]+' >/dev/null || fail "${pod} did not publish an evidence path"
	# Discover and validate one bundle once; all later assertions use this exact
	# directory so a decoy bundle cannot satisfy a separate glob.
	# shellcheck disable=SC2016 # the expression is evaluated inside the pod
	bundle_dir="$(kubectl exec -n "${namespace}" "${pod}" -- sh -c '
		bundle_dir=
		bundle_count=0
		for candidate in /evidence/*; do
			[ -d "$candidate" ] || continue
			bundle_count=$((bundle_count + 1))
			bundle_dir=$candidate
		done
		[ "$bundle_count" -eq 1 ] && [ -s "$bundle_dir/metadata" ] && [ -s "$bundle_dir/events.jsonl" ] || exit 1
		printf "%s" "$bundle_dir"
	')" || fail "${pod} did not retain exactly one complete evidence bundle"
	actual_status="$(kubectl exec -n "${namespace}" "${pod}" -- cat /evidence/helper.exit)"
	if [[ "${expected_exit}" == 0 ]]; then
		[[ "${actual_status}" == 0 ]] || fail "${pod} returned ${actual_status}, expected exit 0"
	elif [[ "${expected_exit}" != any ]]; then
		fail "unsupported expected exit contract: ${expected_exit}"
	fi
	# The kernel may accept or reject a safe loopback ethtool operation. In
	# either case, the exact approved action and its terminal result must be
	# recorded in the evidence bundle.
	# shellcheck disable=SC2016 # the expression is evaluated inside the pod
	kubectl exec -n "${namespace}" "${pod}" -- grep -Fx -- "action=${approved_action}" "${bundle_dir}/metadata" >/dev/null || fail "${pod} evidence does not record the approved action"
	metadata_content="$(kubectl exec -n "${namespace}" "${pod}" -- cat "${bundle_dir}/metadata")" || fail "${pod} evidence metadata could not be read"
	events_content="$(kubectl exec -n "${namespace}" "${pod}" -- cat "${bundle_dir}/events.jsonl")" || fail "${pod} evidence events could not be read"
	observed_status="${actual_status}"
	if [[ "${command_name}" == network-repair ]]; then
		observed_status="$(awk -F= '$1 == "action_exit_status" { print $2 }' <<<"${metadata_content}")"
		[[ "${observed_status}" =~ ^[0-9]+$ ]] || fail "${pod} evidence does not record a valid action status"
		[[ "${observed_status}" == "${actual_status}" ]] || fail "${pod} evidence action status ${observed_status} disagrees with wrapper status ${actual_status}"
	fi
	terminal_event=failed
	[[ "${observed_status}" == 0 ]] && terminal_event=succeeded
	terminal_count="$(jq -s --arg expected "${terminal_event}" '([.[] | select(.event == "operation-completed")] | length == 1 and .[0].result == $expected)' <<<"${events_content}")" || {
		printf 'Evidence metadata:\n%s\nEvidence events:\n%s\n' "${metadata_content}" "${events_content}" >&2
		fail "${pod} evidence events are not valid JSONL"
	}
	if [[ "${terminal_count}" != true ]]; then
		printf 'Evidence metadata:\n%s\nEvidence events:\n%s\n' "${metadata_content}" "${events_content}" >&2
		fail "${pod} evidence does not contain exactly one terminal status ${terminal_event}"
	fi
	kubectl delete pod -n "${namespace}" "${pod}" --wait=true --timeout=60s >/dev/null || fail "${pod} cleanup failed"
	kubectl get pod -n "${namespace}" "${pod}" >/dev/null 2>&1 && fail "${pod} survived cleanup"
	printf 'Pod cleanup passed: %s\n' "${pod}"
}

# Read-only recovery proves exact target/node placement with no capabilities.
run_pod recovery node-recovery NODE-RECOVERY-PREFLIGHT read-only '[]' 0
# A real allowlisted repair helper runs in host networking with only NET_ADMIN;
# loopback has no auto-negotiation, so its expected failure still must emit
# before/after evidence and never become an unbounded or privileged operation.
run_pod repair network-repair NETWORK-REPAIR restart-autonegotiation '["NET_ADMIN"]' any

printf 'node-maintenance host-network recovery/repair proof passed on %s\n' "${node}"
