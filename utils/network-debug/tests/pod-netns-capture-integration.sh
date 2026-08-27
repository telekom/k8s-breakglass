#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail
requirement() { printf 'REQUIREMENT: %s\n' "$*" >&2; exit 1; }
[ "$(uname -s)" = Linux ] || requirement 'selected-pod capture needs a real Linux kernel'
for command in docker kind kubectl jq; do command -v "$command" >/dev/null 2>&1 || requirement "$command is required"; done
docker info >/dev/null 2>&1 || requirement 'a reachable Linux Docker daemon is required'
image=${NETWORK_DEBUG_IMAGE:-network-debug:pod-capture-integration}
node_image=${KIND_NODE_IMAGE:-kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5}
docker image inspect "$image" >/dev/null 2>&1 || requirement "prebuilt image $image is required"
run_id=$(printf '%s' "${GITHUB_RUN_ID:-local}-$$" | tr -cd 'a-zA-Z0-9-' | tr '[:upper:]' '[:lower:]')
cluster="pod-capture-proof-$run_id"; namespace="pod-capture-proof-$run_id"
case "$cluster" in pod-capture-proof-[a-z0-9-]*) ;; *) requirement 'generated ownership name is unsafe' ;; esac
temp_parent=${RUNNER_TEMP:-/tmp}; work_dir=$(mktemp -d "${temp_parent%/}/network-debug-pod-capture-proof.XXXXXX"); kubeconfig=$work_dir/kubeconfig
cluster_create_attempted=false; namespace_created=false
cleanup() {
  status=$?; set +e
  if [ "$namespace_created" = true ] && [ -s "$kubeconfig" ]; then
    KUBECONFIG="$kubeconfig" kubectl delete namespace "$namespace" --wait=true --timeout=90s >/dev/null 2>&1
    KUBECONFIG="$kubeconfig" kubectl get namespace "$namespace" >/dev/null 2>&1 && status=1
  fi
  if [ "$cluster_create_attempted" = true ]; then kind delete cluster --name "$cluster" >/dev/null 2>&1 || status=1; fi
  kind get clusters 2>/dev/null | grep -Fx "$cluster" >/dev/null && status=1
  case "$work_dir" in "${temp_parent%/}"/network-debug-pod-capture-proof.*) rm -rf -- "$work_dir" ;; *) status=1 ;; esac
  exit "$status"
}
trap cleanup EXIT; trap 'exit 130' HUP INT TERM
if kind get clusters | grep -Fx "$cluster" >/dev/null; then requirement "refusing to reuse existing kind cluster $cluster"; fi
cluster_create_attempted=true
kind create cluster --name "$cluster" --image "$node_image" --kubeconfig "$kubeconfig" --wait 120s
kind load docker-image --name "$cluster" "$image"; export KUBECONFIG="$kubeconfig"
kubectl create namespace "$namespace"; namespace_created=true
kubectl label namespace "$namespace" pod-security.kubernetes.io/enforce=privileged --overwrite
cat <<EOF | kubectl -n "$namespace" apply -f -
apiVersion: v1
kind: Pod
metadata: {name: target, labels: {proof.telekom.com/role: target}}
spec:
  automountServiceAccountToken: false
  volumes: [{name: evidence, emptyDir: {}}]
  containers:
    - {name: server, image: $image, imagePullPolicy: Never, command: [/bin/sh, -ec], args: ["while true; do printf 'HTTP/1.1 204 No Content\\r\\nContent-Length: 0\\r\\n\\r\\n' | nc -l -p 18080 -q 1; done"]}
    - {name: traffic, image: $image, imagePullPolicy: Never, command: [/bin/sh, -ec], args: ["while true; do curl --fail --silent --max-time 2 http://127.0.0.1:18080/ >/dev/null || true; sleep 0.1; done"]}
---
apiVersion: v1
kind: Pod
metadata: {name: decoy, labels: {proof.telekom.com/role: decoy}}
spec:
  automountServiceAccountToken: false
  containers:
    - {name: server, image: $image, imagePullPolicy: Never, command: [/bin/sh, -ec], args: ["while true; do printf 'HTTP/1.1 204 No Content\\r\\nContent-Length: 0\\r\\n\\r\\n' | nc -l -p 18081 -q 1; done"]}
    - {name: traffic, image: $image, imagePullPolicy: Never, command: [/bin/sh, -ec], args: ["while true; do curl --fail --silent --max-time 2 http://127.0.0.1:18081/ >/dev/null || true; sleep 0.1; done"]}
EOF
kubectl -n "$namespace" wait pod/target pod/decoy --for=condition=Ready --timeout=90s
target_uid=$(kubectl -n "$namespace" get pod target -o jsonpath='{.metadata.uid}')
case "$target_uid" in ????????-????-????-????-????????????) ;; *) requirement 'Kubernetes did not return a canonical target Pod UID' ;; esac

# shellcheck disable=SC2016 # the script is intentionally interpreted in the target container.
capture_script='set -eu; rm -f /work/capture.pcap /work/capture.log; status=0; timeout 15 tcpdump -p -i lo -s 128 -c 8 -w /work/capture.pcap "tcp port 18080 or tcp port 18081" >/work/capture.log 2>&1 || status=$?; case "$status" in 0|124|130|143) ;; *) cat /work/capture.log >&2; exit 1 ;; esac; test -s /work/capture.pcap; target_packets=$(tcpdump -nn -r /work/capture.pcap "tcp port 18080" 2>/dev/null | wc -l | tr -d " "); decoy_packets=$(tcpdump -nn -r /work/capture.pcap "tcp port 18081" 2>/dev/null | wc -l | tr -d " "); test "$target_packets" -gt 0; test "$decoy_packets" -eq 0; bytes=$(wc -c < /work/capture.pcap | tr -d " "); test "$bytes" -le 40960; printf "proof_status complete\\ntarget_packets %s\\ndecoy_packets %s\\nbytes %s\\n" "$target_packets" "$decoy_packets" "$bytes"'
kubectl -n "$namespace" get pod target -o json |
  jq --arg uid "$target_uid" --arg image "$image" --arg script "$capture_script" 'select(.metadata.uid == $uid) | .spec.ephemeralContainers = ((.spec.ephemeralContainers // []) + [{name:"capture",image:$image,imagePullPolicy:"Never",targetContainerName:"server",command:["/bin/sh","-ec"],args:[$script],securityContext:{runAsUser:0,runAsNonRoot:false,privileged:false,allowPrivilegeEscalation:false,readOnlyRootFilesystem:true,capabilities:{drop:["ALL"],add:["NET_RAW"]},seccompProfile:{type:"RuntimeDefault"}},volumeMounts:[{name:"evidence",mountPath:"/work"}]}])' |
  kubectl replace --raw "/api/v1/namespaces/$namespace/pods/target/ephemeralcontainers" -f - >/dev/null
kubectl -n "$namespace" get pod target -o json | jq -e '
(.spec.hostNetwork // false) == false and (.spec.hostPID // false) == false and
.spec.automountServiceAccountToken == false and .spec.volumes == [{name:"evidence",emptyDir:{}}] and
all(.spec.volumes[]; (.hostPath // null) == null) and (.spec.ephemeralContainers | length == 1) and
.spec.ephemeralContainers[0].name == "capture" and .spec.ephemeralContainers[0].targetContainerName == "server" and
(.spec.ephemeralContainers[0].securityContext.privileged // false) == false and .spec.ephemeralContainers[0].securityContext.allowPrivilegeEscalation == false and
.spec.ephemeralContainers[0].securityContext.readOnlyRootFilesystem == true and .spec.ephemeralContainers[0].securityContext.capabilities.drop == ["ALL"] and
.spec.ephemeralContainers[0].securityContext.capabilities.add == ["NET_RAW"] and
(.spec.ephemeralContainers[0].volumeMounts | length == 1 and .[0].name == "evidence" and .[0].mountPath == "/work") and
all([.spec.containers[],.spec.ephemeralContainers[]][]; all(.volumeMounts[]?; (.mountPath | IN("/run/containerd/containerd.sock","/var/run/containerd/containerd.sock","/var/run/docker.sock") | not)))
' >/dev/null || requirement 'ephemeral selected-pod security boundary was not retained by the API'
capture_status=waiting
for _ in $(seq 1 60); do
  capture_status=$(kubectl -n "$namespace" get pod target -o json | jq -r '.status.ephemeralContainerStatuses[]? | select(.name == "capture") | if .state.terminated then "terminated" elif .state.running then "running" else "waiting" end' | tail -1)
  [ "$capture_status" = terminated ] && break
  sleep 1
done
[ "$capture_status" = terminated ] || requirement 'ephemeral selected-pod capture did not terminate within its bound'
capture_log=$(kubectl -n "$namespace" logs target -c capture)
printf '%s\n' "$capture_log" | grep -Fx 'proof_status complete' >/dev/null || requirement 'ephemeral capture proof did not complete'
printf '%s\n' "$capture_log" | grep -Fx 'decoy_packets 0' >/dev/null || requirement 'ephemeral capture observed decoy traffic'
printf '%s\n' "$capture_log" | grep -E '^target_packets [1-9][0-9]*$' >/dev/null || requirement 'ephemeral capture missed target traffic'
printf '%s\n' "$capture_log" | grep -E '^bytes [1-9][0-9]*$' >/dev/null || requirement 'ephemeral capture produced no bounded evidence'
kubectl -n "$namespace" delete pod target decoy --wait=true --timeout=90s >/dev/null
if kubectl -n "$namespace" get pod target decoy >/dev/null 2>&1; then requirement 'selected-pod target or decoy survived exact cleanup'; fi
printf 'selected-pod ephemeral capture behavior passed\ntarget_uid %s\n' "$target_uid"
