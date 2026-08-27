#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail

requirement() {
	printf 'REQUIREMENT: %s\n' "$*" >&2
	exit 1
}

[ "$(uname -s)" = Linux ] || requirement 'selected-pod capture needs a real Linux kernel'
for command in docker kind kubectl; do
	command -v "${command}" >/dev/null 2>&1 || requirement "${command} is required"
done
docker info >/dev/null 2>&1 || requirement 'a reachable Linux Docker daemon is required'

image=${NETWORK_DEBUG_IMAGE:-network-debug:pod-capture-integration}
node_image=${KIND_NODE_IMAGE:-kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5}
docker image inspect "${image}" >/dev/null 2>&1 || requirement "prebuilt image ${image} is required"

run_id="${GITHUB_RUN_ID:-local}-$$"
run_id=$(printf '%s' "${run_id}" | tr -cd 'a-zA-Z0-9-' | tr '[:upper:]' '[:lower:]')
cluster="pod-capture-proof-${run_id}"
namespace="pod-capture-proof-${run_id}"
case "${cluster}" in pod-capture-proof-[a-z0-9-]*) ;; *) requirement 'generated ownership name is unsafe' ;; esac

temp_parent=${RUNNER_TEMP:-/tmp}
work_dir=$(mktemp -d "${temp_parent%/}/network-debug-pod-capture-proof.XXXXXX")
kubeconfig="${work_dir}/kubeconfig"
cluster_create_attempted=false
namespace_created=false

cleanup() {
	status=$?
	set +e
	if [ "${namespace_created}" = true ] && [ -s "${kubeconfig}" ]; then
		KUBECONFIG="${kubeconfig}" kubectl delete namespace "${namespace}" --wait=true --timeout=90s >/dev/null 2>&1
		if KUBECONFIG="${kubeconfig}" kubectl get namespace "${namespace}" >/dev/null 2>&1; then
			printf 'REQUIREMENT: owned proof namespace survived cleanup\n' >&2
			status=1
		fi
	fi
	if [ "${cluster_create_attempted}" = true ]; then
		if ! kind delete cluster --name "${cluster}" >/dev/null 2>&1; then
			status=1
		fi
	fi
	if kind get clusters 2>/dev/null | grep -Fx "${cluster}" >/dev/null; then
		printf 'REQUIREMENT: owned kind cluster survived cleanup\n' >&2
		status=1
	fi
	if docker ps -a --format '{{.Names}}' | grep -E "^${cluster}-(control-plane|worker[0-9]*)$" >/dev/null; then
		printf 'REQUIREMENT: owned kind node container survived cleanup\n' >&2
		status=1
	fi
	case "${work_dir}" in "${temp_parent%/}"/network-debug-pod-capture-proof.*) rm -rf -- "${work_dir}" ;; *) status=1 ;; esac
	exit "${status}"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

if kind get clusters | grep -Fx "${cluster}" >/dev/null; then
	requirement "refusing to reuse existing kind cluster ${cluster}"
fi
cluster_create_attempted=true
kind create cluster --name "${cluster}" --image "${node_image}" --kubeconfig "${kubeconfig}" --wait 120s
kind load docker-image --name "${cluster}" "${image}"

export KUBECONFIG="${kubeconfig}"
kubectl create namespace "${namespace}"
namespace_created=true
kubectl label namespace "${namespace}" pod-security.kubernetes.io/enforce=privileged --overwrite

cat <<EOF | kubectl -n "${namespace}" apply -f -
apiVersion: v1
kind: Pod
metadata:
  name: target
  labels: {proof.telekom.com/role: target}
spec:
  automountServiceAccountToken: false
  containers:
    - name: server
      image: ${image}
      imagePullPolicy: Never
      command: [/bin/sh, -ec]
      args:
        - |
          while true; do
            printf 'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n' | nc -l -p 18080 -q 1
          done
    - name: traffic
      image: ${image}
      imagePullPolicy: Never
      command: [/bin/sh, -ec]
      args:
        - |
          while true; do curl --fail --silent --max-time 2 http://127.0.0.1:18080/ >/dev/null || true; sleep 0.1; done
---
apiVersion: v1
kind: Pod
metadata:
  name: decoy
  labels: {proof.telekom.com/role: decoy}
spec:
  automountServiceAccountToken: false
  containers:
    - name: server
      image: ${image}
      imagePullPolicy: Never
      command: [/bin/sh, -ec]
      args:
        - |
          while true; do
            printf 'HTTP/1.1 204 No Content\r\nContent-Length: 0\r\n\r\n' | nc -l -p 18081 -q 1
          done
    - name: traffic
      image: ${image}
      imagePullPolicy: Never
      command: [/bin/sh, -ec]
      args:
        - |
          while true; do curl --fail --silent --max-time 2 http://127.0.0.1:18081/ >/dev/null || true; sleep 0.1; done
EOF
kubectl -n "${namespace}" wait pod/target pod/decoy --for=condition=Ready --timeout=90s

target_uid=$(kubectl -n "${namespace}" get pod target -o jsonpath='{.metadata.uid}')
case "${target_uid}" in
	????????-????-????-????-????????????) ;;
	*) requirement 'Kubernetes did not return a canonical target Pod UID' ;;
esac

cat <<EOF | kubectl -n "${namespace}" apply -f -
apiVersion: batch/v1
kind: Job
metadata:
  name: capture
  labels: {proof.telekom.com/run: "${run_id}"}
spec:
  backoffLimit: 0
  ttlSecondsAfterFinished: 600
  template:
    metadata:
      labels: {proof.telekom.com/run: "${run_id}"}
    spec:
      restartPolicy: Never
      hostPID: true
      hostNetwork: false
      automountServiceAccountToken: false
      initContainers:
        - name: protect-evidence
          image: ${image}
          imagePullPolicy: Never
          command: [/bin/chmod, "0700", /work]
          securityContext:
            runAsUser: 0
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: [ALL]}
            seccompProfile: {type: RuntimeDefault}
          volumeMounts:
            - {name: evidence, mountPath: /work}
      containers:
        - name: capture
          image: ${image}
          imagePullPolicy: Never
          command: [/usr/local/bin/pod-netns-capture]
          args: [--pod-uid, "${target_uid}", --interface, lo, --duration, "10", --count, "40", --snaplen, "128", --filter, "tcp port 18080 or tcp port 18081", --output, capture.pcap]
          securityContext:
            runAsUser: 0
            runAsNonRoot: false
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities:
              drop: [ALL]
              add: [SYS_ADMIN, SYS_PTRACE, NET_RAW]
            seccompProfile: {type: RuntimeDefault}
          volumeMounts:
            - {name: evidence, mountPath: /work}
        - name: verify
          image: ${image}
          imagePullPolicy: Never
          command: [/bin/sh, -ec]
          args:
            - |
              sleep 15
              test -s /work/capture.pcap
              target_packets=\$(tcpdump -nn -r /work/capture.pcap 'tcp port 18080' 2>/dev/null | wc -l | tr -d ' ')
              decoy_packets=\$(tcpdump -nn -r /work/capture.pcap 'tcp port 18081' 2>/dev/null | wc -l | tr -d ' ')
              test "\${target_packets}" -gt 0
              test "\${decoy_packets}" -eq 0
              printf 'proof_status complete\ntarget_packets %s\ndecoy_packets %s\n' "\${target_packets}" "\${decoy_packets}"
          securityContext:
            runAsUser: 0
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: [ALL]}
            seccompProfile: {type: RuntimeDefault}
          volumeMounts:
            - {name: evidence, mountPath: /work, readOnly: true}
      volumes:
        - name: evidence
          emptyDir: {}
EOF

kubectl -n "${namespace}" get job capture -o json | jq -e '
	.spec.template.spec.hostPID == true and
	.spec.template.spec.hostNetwork == false and
	.spec.template.spec.automountServiceAccountToken == false and
	(.spec.template.spec.volumes | length == 1 and .[0].name == "evidence" and .[0].emptyDir != null and all(.[]; (.hostPath // null) == null)) and
	(.spec.template.spec.containers | length == 2) and
	(.spec.template.spec.initContainers | length == 1) and
	(.spec.template.spec.initContainers[0].securityContext.privileged // false) == false and
	.spec.template.spec.initContainers[0].securityContext.allowPrivilegeEscalation == false and
	.spec.template.spec.initContainers[0].securityContext.capabilities.drop == ["ALL"] and
	(.spec.template.spec.containers[0].securityContext.privileged // false) == false and
	.spec.template.spec.containers[0].securityContext.allowPrivilegeEscalation == false and
	.spec.template.spec.containers[0].securityContext.capabilities.drop == ["ALL"] and
	.spec.template.spec.containers[0].securityContext.capabilities.add == ["SYS_ADMIN", "SYS_PTRACE", "NET_RAW"] and
	(.spec.template.spec.containers[0].volumeMounts | all(.[]; .mountPath == "/work")) and
	(.spec.template.spec.initContainers[0].volumeMounts | all(.[]; .mountPath == "/work")) and
	(.spec.template.spec.containers[1].securityContext.privileged // false) == false and
	.spec.template.spec.containers[1].securityContext.allowPrivilegeEscalation == false and
	(.spec.template.spec.containers[1].securityContext.capabilities.drop == ["ALL"]) and
	(.spec.template.spec.containers[1].volumeMounts | all(.[]; .mountPath == "/work")) and
	all([.spec.template.spec.initContainers[], .spec.template.spec.containers[]][];
		all(.volumeMounts[]?; (.mountPath | IN("/run/containerd/containerd.sock", "/var/run/containerd/containerd.sock", "/var/run/docker.sock") | not)))
' >/dev/null || requirement 'selected-pod capture Job security boundary was not retained by the cluster'

if ! kubectl -n "${namespace}" wait job/capture --for=condition=Complete --timeout=90s; then
	kubectl -n "${namespace}" logs job/capture --all-containers=true >&2 || true
	requirement 'host PID/setns/cgroup/capability selected-pod proof did not complete'
fi
capture_log=$(kubectl -n "${namespace}" logs job/capture -c capture)
verify_log=$(kubectl -n "${namespace}" logs job/capture -c verify)
printf '%s\n' "${capture_log}" | grep -Fx 'capture_status complete' >/dev/null
printf '%s\n' "${capture_log}" | grep -E '^sha256 [0-9a-f]{64}$' >/dev/null
if printf '%s\n' "${capture_log}" | grep -E '(^|[[:space:]])IP6?[[:space:]]|length [0-9]+' >/dev/null; then
	requirement 'capture helper emitted packet payload/header text'
fi
printf '%s\n' "${verify_log}" | grep -Fx 'proof_status complete' >/dev/null
printf '%s\n' "${verify_log}" | grep -Fx 'decoy_packets 0' >/dev/null

kubectl -n "${namespace}" delete job capture --wait=true --timeout=90s
if kubectl -n "${namespace}" get job capture >/dev/null 2>&1; then
	requirement 'capture Job survived exact cleanup'
fi
if kubectl -n "${namespace}" get pods -l "proof.telekom.com/run=${run_id}" -o name | grep -q .; then
	requirement 'capture pod survived exact cleanup'
fi

printf 'selected-pod capture behavior passed\ntarget_uid %s\n' "${target_uid}"
