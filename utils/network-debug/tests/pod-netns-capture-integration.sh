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
export KIND_BIN=kind DOCKER_BIN=docker KIND_CLUSTER_NAME="$cluster" KIND_NODE_IMAGE="$node_image" KUBECONFIG_FILE="$kubeconfig"
export KIND_CLUSTER_CREATED=false KIND_CLUSTER_OWNER_IDS=''; namespace_created=false
# shellcheck source=kind-ownership.sh
. "$(dirname -- "$0")/kind-ownership.sh"
cleanup() {
  status=$?; set +e
  if [ "$namespace_created" = true ] && [ -s "$kubeconfig" ]; then
    KUBECONFIG="$kubeconfig" kubectl delete namespace "$namespace" --wait=true --timeout=90s >/dev/null 2>&1
    KUBECONFIG="$kubeconfig" kubectl get namespace "$namespace" >/dev/null 2>&1 && status=1
  fi
  kind_cleanup_owned_cluster >/dev/null 2>&1 || status=1
  case "$work_dir" in "${temp_parent%/}"/network-debug-pod-capture-proof.*) rm -rf -- "$work_dir" ;; *) status=1 ;; esac
  exit "$status"
}
trap cleanup EXIT; trap 'exit 130' HUP INT TERM
if ! kind_create_owned_cluster; then
  requirement "kind cluster creation did not complete with provable ownership"
fi
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

# The ephemeral container invokes the image-owned bounded wrapper. The
# read-only checks below inspect its pcap and summary; tcpdump is never used
# as the capture process itself.
# shellcheck disable=SC2016 # the script is intentionally interpreted in the target container.
capture_script='set -eu
rm -f /work/capture.pcap /work/capture.log /work/overwrite.log
status=0
/usr/local/bin/net-debug capture --interface lo --duration 15 --packets 8 --snaplen 128 --filter "tcp port 18080 or tcp port 18081" --output capture.pcap >/work/capture.log 2>&1 || status=$?
test "$status" -eq 0 || { cat /work/capture.log >&2; exit 1; }
grep -Fx "capture" /work/capture.log >/dev/null
grep -Fx "interface lo" /work/capture.log >/dev/null
grep -Fx "duration 15" /work/capture.log >/dev/null
grep -Fx "packet_limit 8" /work/capture.log >/dev/null
grep -Fx "snaplen 128" /work/capture.log >/dev/null
packet_count=$(sed -n "s/^packet_count //p" /work/capture.log)
case "$packet_count" in ""|*[!0-9]*) exit 1 ;; esac
test "$packet_count" -gt 0
test "$packet_count" -le 8
reported_bytes=$(sed -n "s/^bytes //p" /work/capture.log)
case "$reported_bytes" in ""|*[!0-9]*) exit 1 ;; esac
test "$reported_bytes" -gt 24
test "$reported_bytes" -le $((8 * (128 + 16) + 24))
reported_hash=$(sed -n "s/^sha256 //p" /work/capture.log)
printf "%s\\n" "$reported_hash" | grep -E "^[0-9a-f]{64}$" >/dev/null
actual_hash=$(sha256sum /work/capture.pcap | awk "{print \$1}")
test "$reported_hash" = "$actual_hash"
grep -Fx "file capture.pcap" /work/capture.log >/dev/null
test -s /work/capture.pcap
target_packets=$(tcpdump -nn -r /work/capture.pcap "tcp port 18080" 2>/dev/null | wc -l | tr -d " ")
decoy_packets=$(tcpdump -nn -r /work/capture.pcap "tcp port 18081" 2>/dev/null | wc -l | tr -d " ")
test "$target_packets" -gt 0
test "$decoy_packets" -eq 0
before_hash=$actual_hash
if /usr/local/bin/net-debug capture --interface lo --duration 1 --packets 1 --snaplen 128 --filter "tcp port 18080" --output capture.pcap >/work/overwrite.log 2>&1; then exit 1; fi
test "$before_hash" = "$(sha256sum /work/capture.pcap | awk "{print \$1}")"
test -z "$(find /work -maxdepth 1 -name ".net-debug.*" -print -quit)"
printf "proof_status complete\\ntarget_packets %s\\ndecoy_packets %s\\npacket_count %s\\nbytes %s\\n" "$target_packets" "$decoy_packets" "$packet_count" "$reported_bytes"'
kubectl -n "$namespace" get pod target -o json |
  jq --arg uid "$target_uid" --arg image "$image" --arg script "$capture_script" 'select(.metadata.uid == $uid) | .spec.ephemeralContainers = ((.spec.ephemeralContainers // []) + [{name:"capture",image:$image,imagePullPolicy:"Never",targetContainerName:"server",command:["/bin/sh","-ec"],args:[$script],securityContext:{runAsUser:0,runAsNonRoot:false,privileged:false,allowPrivilegeEscalation:false,readOnlyRootFilesystem:true,capabilities:{drop:["ALL"],add:["NET_RAW"]},seccompProfile:{type:"RuntimeDefault"}},volumeMounts:[{name:"evidence",mountPath:"/work"}]}])' |
  kubectl replace --raw "/api/v1/namespaces/$namespace/pods/target/ephemeralcontainers" -f - >/dev/null
kubectl -n "$namespace" get pod target -o json | jq -e '
(.spec.hostNetwork // false) == false and (.spec.hostPID // false) == false and
.spec.automountServiceAccountToken == false and .spec.volumes == [{name:"evidence",emptyDir:{}}] and
all(.spec.volumes[]; (.hostPath // null) == null) and (.spec.ephemeralContainers | length == 1) and
.spec.ephemeralContainers[0].name == "capture" and .spec.ephemeralContainers[0].targetContainerName == "server" and
.spec.ephemeralContainers[0].command == ["/bin/sh","-ec"] and (.spec.ephemeralContainers[0].args[0] | contains("/usr/local/bin/net-debug capture")) and
(.spec.ephemeralContainers[0].securityContext.privileged // false) == false and .spec.ephemeralContainers[0].securityContext.allowPrivilegeEscalation == false and
.spec.ephemeralContainers[0].securityContext.readOnlyRootFilesystem == true and .spec.ephemeralContainers[0].securityContext.capabilities.drop == ["ALL"] and
.spec.ephemeralContainers[0].securityContext.capabilities.add == ["NET_RAW"] and
(.spec.ephemeralContainers[0].volumeMounts | length == 1 and .[0].name == "evidence" and .[0].mountPath == "/work") and
all([.spec.containers[],.spec.ephemeralContainers[]][]; all(.volumeMounts[]?; (.mountPath | IN("/run/containerd/containerd.sock","/var/run/containerd/containerd.sock","/var/run/docker.sock") | not)))
' >/dev/null || requirement 'ephemeral selected-pod security boundary was not retained by the API'
capture_status=waiting
for _ in $(seq 1 60); do
  capture_status=$(kubectl -n "$namespace" get pod target -o json | jq -r '[.status.ephemeralContainerStatuses[]? | select(.name == "capture") | if .state.terminated != null then "terminated" elif .state.running != null then "running" else "waiting" end] | last // "missing"')
  [ "$capture_status" = terminated ] && break
  sleep 1
done
if [ "$capture_status" != terminated ]; then
  kubectl -n "$namespace" get pod target -o json | jq '.status.ephemeralContainerStatuses // []' >&2 || true
  kubectl -n "$namespace" logs target -c capture --timestamps >&2 || true
  requirement "ephemeral selected-pod capture did not terminate within its bound (state: $capture_status)"
fi
capture_log=$(kubectl -n "$namespace" logs target -c capture) || {
  kubectl -n "$namespace" get pod target -o json | jq '.status.ephemeralContainerStatuses // []' >&2 || true
  requirement 'ephemeral capture logs were unavailable'
}
printf '%s\n' "$capture_log" | grep -Fx 'proof_status complete' >/dev/null || {
  printf '%s\n' "$capture_log" >&2
  requirement 'ephemeral capture proof did not complete'
}
printf '%s\n' "$capture_log" | grep -Fx 'decoy_packets 0' >/dev/null || {
  printf '%s\n' "$capture_log" >&2
  requirement 'ephemeral capture observed decoy traffic'
}
printf '%s\n' "$capture_log" | grep -E '^target_packets [1-9][0-9]*$' >/dev/null || {
  printf '%s\n' "$capture_log" >&2
  requirement 'ephemeral capture missed target traffic'
}
printf '%s\n' "$capture_log" | grep -E '^bytes [1-9][0-9]*$' >/dev/null || {
  printf '%s\n' "$capture_log" >&2
  requirement 'ephemeral capture produced no bounded evidence'
}
kubectl -n "$namespace" delete pod target decoy --wait=true --timeout=90s >/dev/null
if kubectl -n "$namespace" get pod target decoy >/dev/null 2>&1; then requirement 'selected-pod target or decoy survived exact cleanup'; fi
printf 'selected-pod ephemeral capture behavior passed\ntarget_uid %s\n' "$target_uid"
