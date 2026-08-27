#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

IMAGE=${NETWORK_DEBUG_IMAGE:-network-debug:integration}
EXEC_TIMEOUT=${NETWORK_DEBUG_EXEC_TIMEOUT_SECONDS:-20}
DOCKER_TIMEOUT=${NETWORK_DEBUG_DOCKER_TIMEOUT_SECONDS:-30}
PWRU_REQUIRED=${NETWORK_DEBUG_REQUIRE_PWRU:-true}
TRACE_DURATION=10
TRACE_EVENTS=10000
# BPF detach is asynchronous on some kernels; keep graceful shutdown bounded.
PWRU_STOP_TIMEOUT=${NETWORK_DEBUG_PWRU_STOP_TIMEOUT_SECONDS:-15}
# Loading and attaching pwru's kprobes can take substantially longer than
# the trace itself on a busy CI kernel. Keep that startup allowance separate
# from the bounded shutdown windows so the outer wait remains auditable.
PWRU_STARTUP_MARGIN=${NETWORK_DEBUG_PWRU_STARTUP_MARGIN_SECONDS:-30}
# The outer Docker wait must cover the trace duration and both bounded pwru
# startup and shutdown windows. A fixed 20-second wait expired while
# net-debug was still attaching or within its documented stop contract.
PWRU_TIMEOUT=${NETWORK_DEBUG_PWRU_TIMEOUT_SECONDS:-$((TRACE_DURATION + PWRU_STARTUP_MARGIN + PWRU_STOP_TIMEOUT))}
RUN_ID="network-debug-proof-${RANDOM}-${RANDOM}"
NETWORK=${RUN_ID}-network
CONTAINER=${RUN_ID}-tools
PWRU_CONTAINER=${RUN_ID}-pwru
TRACE_TRAFFIC_CONTAINER=${RUN_ID}-trace-traffic
NETWORK_NAMESPACE=${RUN_ID}-network
NETWORK_HOST_POD_NAME=${RUN_ID}-host-network
# Never accept a caller-selected cluster name: the random run ID is the only
# name this invocation can own after its absent-name preflight.
KIND_CLUSTER_NAME=$RUN_ID
KIND_NODE_IMAGE=${KIND_NODE_IMAGE:-kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5}
KIND_BIN=${NETWORK_DEBUG_KIND_BIN:-kind}
# shellcheck disable=SC2034 # consumed by the sourced ownership helper
DOCKER_BIN=${NETWORK_DEBUG_DOCKER_BIN:-docker}
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/network-debug-proof.XXXXXX")
KUBECONFIG_FILE=${WORK_DIR}/kubeconfig
KIND_CLUSTER_CREATED=false
NETWORK_NAMESPACE_CREATED=false
NETWORK_CREATED=false
CONTAINER_CREATED=false
PWRU_CONTAINER_CREATED=false
TRACE_TRAFFIC_CONTAINER_CREATED=false
DOCKER_OWNER_LABEL=com.telekom.network-debug.run
# shellcheck disable=SC2034 # consumed by the sourced pwru lifecycle helper
PWRU_OWNER_LABEL=$DOCKER_OWNER_LABEL
# shellcheck disable=SC2034 # consumed by the sourced pwru lifecycle helper
PWRU_OWNER_VALUE=$RUN_ID
# shellcheck disable=SC2034 # consumed by the sourced pwru lifecycle helper
PWRU_USE_DOCKER_TIMEOUT=true

# shellcheck disable=SC1091
. "$(dirname -- "$0")/kind-ownership.sh"
# shellcheck disable=SC1091
. "$(dirname -- "$0")/pwru-lifecycle.sh"

requirement() {
	printf 'REQUIREMENT: %s\n' "$*" >&2
	exit 2
}

for timeout_value in "$EXEC_TIMEOUT" "$DOCKER_TIMEOUT" "$PWRU_TIMEOUT" "$PWRU_STARTUP_MARGIN" "$PWRU_STOP_TIMEOUT"; do
	case "$timeout_value" in
		''|*[!0-9]*) requirement "timeout settings must be positive integers" ;;
	esac
	[ "$timeout_value" -gt 0 ] || requirement "timeout settings must be positive integers"
done
case "$PWRU_REQUIRED" in
	true|false) ;;
	*) requirement "NETWORK_DEBUG_REQUIRE_PWRU must be true or false" ;;
esac
cleanup() {
	status=$?
	set +e
	cleanup_failed=false
	if [ "$KIND_CLUSTER_CREATED" = true ]; then
		if [ "$NETWORK_NAMESPACE_CREATED" = true ] && command -v kubectl >/dev/null 2>&1; then
			if ! kubectl --kubeconfig "$KUBECONFIG_FILE" delete namespace "$NETWORK_NAMESPACE" --ignore-not-found --wait=true --timeout=60s >/dev/null 2>&1; then
				cleanup_failed=true
			fi
			if kubectl --kubeconfig "$KUBECONFIG_FILE" get namespace "$NETWORK_NAMESPACE" >/dev/null 2>&1; then
				cleanup_failed=true
			fi
		fi
	fi
	if ! kind_cleanup_owned_cluster; then
			cleanup_failed=true
	fi
	for docker_container in "$PWRU_CONTAINER" "$TRACE_TRAFFIC_CONTAINER" "$CONTAINER"; do
		container_owned=false
		if [ "$docker_container" = "$PWRU_CONTAINER" ] && [ "$PWRU_CONTAINER_CREATED" = true ]; then
			container_owned=true
		elif [ "$docker_container" = "$TRACE_TRAFFIC_CONTAINER" ] && [ "$TRACE_TRAFFIC_CONTAINER_CREATED" = true ]; then
			container_owned=true
		elif [ "$docker_container" = "$CONTAINER" ] && [ "$CONTAINER_CREATED" = true ]; then
			container_owned=true
		fi
		if [ "$container_owned" = true ]; then
			if [ "$docker_container" = "$PWRU_CONTAINER" ]; then
				if ! pwru_force_remove "$docker_container"; then
					cleanup_failed=true
				fi
			elif docker_resource_present container "$docker_container"; then
				if ! docker_call rm -f "$docker_container" >/dev/null 2>&1; then
					cleanup_failed=true
				fi
				if docker_resource_present container "$docker_container"; then
					cleanup_failed=true
				else
					resource_status=$?
					[ "$resource_status" -eq 1 ] || cleanup_failed=true
				fi
			else
				resource_status=$?
				[ "$resource_status" -eq 1 ] || cleanup_failed=true
			fi
		fi
	done
	if [ "$NETWORK_CREATED" = true ]; then
		if docker_resource_present network "$NETWORK"; then
			if ! docker_call network rm "$NETWORK" >/dev/null 2>&1; then
				cleanup_failed=true
			fi
			if docker_resource_present network "$NETWORK"; then
				cleanup_failed=true
			else
				resource_status=$?
				[ "$resource_status" -eq 1 ] || cleanup_failed=true
			fi
		else
			resource_status=$?
			[ "$resource_status" -eq 1 ] || cleanup_failed=true
		fi
	fi
	if ! rm -rf "$WORK_DIR"; then
		cleanup_failed=true
	fi
	if [ -e "$WORK_DIR" ]; then
		cleanup_failed=true
	fi
	if [ "$cleanup_failed" = true ]; then
		status=1
	fi
	exit "$status"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

docker_call() {
	timeout --foreground "${DOCKER_TIMEOUT}s" docker "$@"
}

docker_owned_resource() {
	local kind=$1 name=$2 owner
	case "$kind" in
		container) owner=$(docker_call inspect --format "{{index .Config.Labels \"${DOCKER_OWNER_LABEL}\"}}" "$name") || return 2 ;;
		network) owner=$(docker_call network inspect --format "{{index .Labels \"${DOCKER_OWNER_LABEL}\"}}" "$name") || return 2 ;;
		*) return 1 ;;
	esac
	[ "$owner" = "$RUN_ID" ] || return 3
}

docker_resource_listed() {
	local kind=$1 name=$2 listed
	case "$kind" in
		container) listed=$(docker_call container ls --all --filter "name=^/${name}$" --format '{{.Names}}') || return 2 ;;
		network) listed=$(docker_call network ls --filter "name=^${name}$" --format '{{.Name}}') || return 2 ;;
		*) return 2 ;;
	esac
	printf '%s\n' "$listed" | grep -Fx -- "$name" >/dev/null 2>&1
}

docker_resource_present() {
	local kind=$1 name=$2 state
	if docker_owned_resource "$kind" "$name" >/dev/null 2>&1; then
		return 0
	fi
	state=$?
	[ "$state" -eq 3 ] && return 3
	# An inspect failure may mean that the resource is gone, but only a
	# bounded exact-name list query can establish that. If it still appears,
	# refuse deletion because ownership could not be verified.
	if docker_resource_listed "$kind" "$name"; then
		return 3
	fi
	state=$?
	[ "$state" -eq 2 ] && return 2
	return 1
}

command -v docker >/dev/null 2>&1 || requirement "docker is required to run disposable integration containers"
command -v "$KIND_BIN" >/dev/null 2>&1 || requirement "kind is required to run the disposable Kubernetes integration cluster"
command -v kubectl >/dev/null 2>&1 || requirement "kubectl is required to run the disposable Kubernetes integration cluster"
command -v jq >/dev/null 2>&1 || requirement "jq is required to validate structured Kubernetes resources"
command -v timeout >/dev/null 2>&1 || requirement "GNU timeout is required for bounded integration commands"
docker_call image inspect "$IMAGE" >/dev/null 2>&1 || requirement "image $IMAGE is unavailable; build it before running integration proofs"

# Never mutate a caller-selected Kubernetes context. The proof owns the kind
# cluster and its kubeconfig from creation through cleanup, so invoking this
# script locally cannot accidentally create a namespace or PVC in production.
create_status=0
kind_create_owned_cluster || create_status=$?
if [ "$create_status" -ne 0 ]; then
	case "$create_status" in
		2) requirement "refusing to reuse an existing kind cluster named $KIND_CLUSTER_NAME" ;;
		3) requirement "could not inspect existing kind clusters before creating the disposable cluster" ;;
		4) requirement "could not clean up a partial disposable kind cluster" ;;
		*) requirement "could not create the disposable kind cluster" ;;
	esac
fi
export KUBECONFIG="$KUBECONFIG_FILE"
kubectl wait --for=condition=Ready nodes --all --timeout=180s >/dev/null || requirement "disposable kind nodes did not become ready"
"$KIND_BIN" load docker-image "$IMAGE" --name "$KIND_CLUSTER_NAME" || requirement "could not load the network-debug image into kind"

# Keep the Kubernetes fixture in the run-scoped namespace. Creating it before
# the network proof exercises the same image and host-network contract that
# the catalogue deploys, rather than a Docker analogue of a pod namespace.
kubectl create namespace "$NETWORK_NAMESPACE" >/dev/null || requirement "could not create disposable network diagnostics namespace"
NETWORK_NAMESPACE_CREATED=true

# Refuse collisions before claiming ownership. A daemon-reachable absent
# result is the only safe state in which to proceed.
if docker_resource_present network "$NETWORK"; then
	requirement "refusing to reuse an existing network named $NETWORK"
else
	resource_status=$?
	[ "$resource_status" -eq 1 ] || requirement "could not inspect the Docker network before creating it"
fi
NETWORK_CREATED=true
docker_call network create --label "$DOCKER_OWNER_LABEL=$RUN_ID" "$NETWORK" >/dev/null || requirement "Docker could not create an ephemeral network"
if docker_resource_present container "$CONTAINER"; then
	requirement "refusing to reuse an existing fixture container named $CONTAINER"
else
	resource_status=$?
	[ "$resource_status" -eq 1 ] || requirement "could not inspect the fixture container before creating it"
fi
CONTAINER_CREATED=true
docker_call run --detach --name "$CONTAINER" --label "$DOCKER_OWNER_LABEL=$RUN_ID" --network "$NETWORK" \
	--publish 18080:18080 \
	--cap-drop ALL --security-opt no-new-privileges=true \
	--cap-add NET_RAW \
	"$IMAGE" sh -c '
		mkdir -p /work/www
		openssl req -x509 -newkey rsa:2048 -nodes -days 1 \
			-keyout /work/tls.key -out /work/tls.crt \
			-subj /CN=localhost \
			-addext subjectAltName=DNS:localhost,IP:127.0.0.1 \
			>/work/tls-cert.log 2>&1
		openssl s_server -quiet -accept 18443 -cert /work/tls.crt -key /work/tls.key -www \
			>/work/tls-server.log 2>&1 &
		printf "%s\\n" network-debug-fixture > /work/www/index.html
		while :; do
			printf "HTTP/1.1 200 OK\\r\\nContent-Length: 22\\r\\nConnection: close\\r\\n\\r\\nnetwork-debug-fixture\\n" | nc -l -p 18080 -s 0.0.0.0
		done
	' >/dev/null || requirement "could not start the disposable network fixture"

exec_in() {
	timeout --foreground "${EXEC_TIMEOUT}s" docker exec "$CONTAINER" "$@"
}

wait_for_socket() {
	for _ in $(seq 1 40); do
		if exec_in nc -z -w 1 127.0.0.1 18080 >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.25
	done
	return 1
}
wait_for_socket || requirement "the HTTP/socket fixture did not become ready within 10 seconds"

wait_for_tls_socket() {
	for _ in $(seq 1 40); do
		if exec_in nc -z -w 1 127.0.0.1 18443 >/dev/null 2>&1; then
			return 0
		fi
		sleep 0.25
	done
	return 1
}
wait_for_tls_socket || requirement "the local TLS fixture did not become ready within 10 seconds"

printf '%s\n' 'Checking packet capture denial without capabilities' >&2
if timeout --foreground 5 docker run --rm --network "container:$CONTAINER" \
	--cap-drop ALL --security-opt no-new-privileges=true \
	"$IMAGE" tcpdump -i lo -c 1 -w /dev/null >"$WORK_DIR/tcpdump-denied.log" 2>&1; then
	requirement "tcpdump unexpectedly succeeded without NET_RAW; the image security boundary is too broad"
fi
grep -Eiq 'permission|not permitted|operation not permitted' "$WORK_DIR/tcpdump-denied.log" || requirement "tcpdump denial did not report a capability failure"

printf '%s\n' 'Checking real connectivity, DNS, TLS, HTTP, socket, and routing operations' >&2
exec_in curl --fail --silent --show-error --max-time 5 http://127.0.0.1:18080/ | grep -F 'network-debug-fixture' >/dev/null || requirement "curl HTTP fixture check failed"
exec_in sh -c 'printf "GET / HTTP/1.0\\r\\nHost: localhost\\r\\n\\r\\n" | nc -w 3 127.0.0.1 18080' | grep -F '200 OK' >/dev/null || requirement "netcat HTTP fixture check failed"
exec_in ping -n -c 1 -W 1 127.0.0.1 >/dev/null || requirement "ping loopback check failed"
exec_in tracepath -n -m 1 127.0.0.1 >/dev/null || requirement "tracepath loopback check failed"
exec_in traceroute -n -m 1 -w 1 127.0.0.1 >/dev/null || requirement "traceroute loopback check failed"
exec_in mtr -n -r -c 1 -w 127.0.0.1 >/dev/null || requirement "mtr loopback check failed"
exec_in ethtool eth0 >/dev/null || requirement "ethtool interface check failed"
exec_in ip -o address show dev eth0 >/dev/null || requirement "ip address check failed"
exec_in ip route show default | grep -F 'default' >/dev/null || requirement "ip default-route check failed"
exec_in ip rule show | grep -F 'lookup' >/dev/null || requirement "ip policy-rule check failed"
exec_in ss -Hln 'sport = :18080' | grep -F ':18080' >/dev/null || requirement "ss listening-socket check failed"

for resolver_tool in dig host nslookup; do
	case "$resolver_tool" in
		host) resolver_output=$(exec_in host -t A "$CONTAINER") ;;
		*) resolver_output=$(exec_in "$resolver_tool" "$CONTAINER") ;;
	esac
	printf '%s\n' "$resolver_output" | grep -E '([0-9]{1,3}\.){3}[0-9]{1,3}' >/dev/null || requirement "$resolver_tool Docker-DNS check failed"
done
exec_in sh -c "dig +short $CONTAINER" | grep -E '^[0-9]+(\.[0-9]+){3}$' >/dev/null || requirement "dig did not resolve the fixture container"
tls_result=$(exec_in curl --fail --silent --show-error --max-time 10 \
	--cacert /work/tls.crt --output /dev/null \
	--write-out '%{http_code} %{ssl_verify_result}' https://127.0.0.1:18443/) || \
	requirement "curl TLS check against the local fixture failed"
test "$tls_result" = '200 0' || requirement "curl did not verify the local TLS fixture certificate"

report_one=$(exec_in net-debug report)
report_two=$(exec_in net-debug report)
test "$report_one" = "$report_two" || requirement "net-report output is not deterministic"
printf '%s\n' "$report_one" > "$WORK_DIR/net-report.txt"
for section in '[interfaces]' '[routes]' '[rules]' '[dns]' '[tools]'; do
	grep -F "$section" "$WORK_DIR/net-report.txt" >/dev/null || requirement "net-report omitted section $section"
done
if exec_in net-report --unexpected >/dev/null 2>&1; then
	requirement "net-report accepted an unknown option"
fi
tools_output=$(exec_in net-debug tools)
for tool in curl dig host nslookup nc ping tracepath traceroute mtr ip ss tcpdump ethtool pwru; do
	case "$tool" in
		pwru) tool_pattern="^${tool}[[:space:]]+${tool} v[0-9]+" ;;
		*) tool_pattern="^${tool}[[:space:]]+installed$" ;;
	esac
	printf '%s\n' "$tools_output" | grep -E "$tool_pattern" >/dev/null || requirement "$tool is not installed according to net-debug tools"
done
if exec_in kubestr --help >/dev/null 2>&1; then
	requirement "kubestr is present in network-debug; storage tooling belongs to storage-debug"
fi

printf '%s\n' 'Checking generated tcpdump capture' >&2
timeout --foreground 15 docker exec "$CONTAINER" sh -c \
	'tcpdump -i lo -nn -c 2 -w /work/capture.pcap tcp port 18080 >/work/tcpdump.log 2>&1' &
capture_pid=$!
sleep 1
exec_in curl --fail --silent --show-error --max-time 5 http://127.0.0.1:18080/ >/dev/null || requirement "capture traffic generator failed"
if ! wait "$capture_pid"; then
	docker_call exec "$CONTAINER" sh -c 'cat /work/tcpdump.log' >&2 || true
	requirement "tcpdump did not capture generated HTTP packets within 15 seconds"
fi
capture_size=$(exec_in stat -c '%s' /work/capture.pcap)
[ "$capture_size" -gt 24 ] || requirement "tcpdump produced an empty capture"
exec_in tcpdump -nn -r /work/capture.pcap 'tcp port 18080' 2>/dev/null | grep -F '18080' >/dev/null || requirement "captured pcap did not contain the generated HTTP endpoint"

printf '%s\n' 'Checking bounded tcpdump in the host-network context' >&2
kubectl apply -f - >/dev/null <<YAML || requirement "could not create disposable network diagnostics pods"
apiVersion: v1
kind: Pod
metadata:
  name: ${NETWORK_HOST_POD_NAME}
  namespace: ${NETWORK_NAMESPACE}
  labels:
    app.kubernetes.io/name: network-debug-proof
    app.kubernetes.io/instance: ${RUN_ID}
spec:
  hostNetwork: true
  dnsPolicy: ClusterFirstWithHostNet
  automountServiceAccountToken: false
  restartPolicy: Never
  containers:
    - name: debug
      image: ${IMAGE}
      imagePullPolicy: Never
      command: ["/bin/sh", "-c"]
      args:
        - |
          while :; do
            printf 'HTTP/1.1 200 OK\r\nContent-Length: 21\r\nConnection: close\r\n\r\nhost-network-fixture\n' | nc -l -p 18080 -s 127.0.0.1
          done
      securityContext:
        runAsUser: 0
        runAsGroup: 0
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        seccompProfile:
          type: RuntimeDefault
        capabilities:
          drop: [ALL]
          add: [NET_RAW]
      volumeMounts:
        - name: work
          mountPath: /work
  volumes:
    - name: work
      emptyDir: {}
YAML

network_pod=$NETWORK_HOST_POD_NAME
if ! kubectl wait --for=jsonpath='{.status.phase}'=Running \
	--namespace "$NETWORK_NAMESPACE" "pod/$network_pod" --timeout=120s >/dev/null; then
	kubectl describe pod "$network_pod" --namespace "$NETWORK_NAMESPACE" >&2 || true
	requirement "network diagnostics pod $network_pod did not become ready"
fi
host_network=$(kubectl get pod "$NETWORK_HOST_POD_NAME" --namespace "$NETWORK_NAMESPACE" \
	-o jsonpath='{.spec.hostNetwork}')
[ "$host_network" = true ] || requirement "host-network capture pod was not assigned the host network"
kubectl get pod "$NETWORK_HOST_POD_NAME" --namespace "$NETWORK_NAMESPACE" -o json | jq -e '
		.spec.automountServiceAccountToken == false and
		(.spec.containers | length == 1) and
		(.spec.containers[0].securityContext.privileged // false) == false and
		.spec.containers[0].securityContext.allowPrivilegeEscalation == false and
		.spec.containers[0].securityContext.capabilities.drop == ["ALL"] and
		.spec.containers[0].securityContext.capabilities.add == ["NET_RAW"] and
		(.spec.hostPID // false) == false and
		(.spec.volumes | length == 1 and .[0].name == "work" and .[0].emptyDir != null and all(.[]; (.hostPath // null) == null)) and
		(.spec.containers[0].volumeMounts | all(.[]; .mountPath == "/work")) and
		all(.spec.containers[]; all(.volumeMounts[]?; (.mountPath | IN("/run/containerd/containerd.sock", "/var/run/containerd/containerd.sock", "/var/run/docker.sock") | not)))
	' >/dev/null || requirement "host-network capture pod security boundary was not retained by the cluster"

capture_pod_traffic() {
	local pod=$1 expected=$2 capture_log=$3 capture_pid capture_size reported_hash actual_hash packet_count

	for _ in $(seq 1 40); do
		if kubectl exec --namespace "$NETWORK_NAMESPACE" "$pod" -- \
			nc -z -w 1 127.0.0.1 18080 >/dev/null 2>&1; then
			break
		fi
		sleep 0.25
	done
	kubectl exec --namespace "$NETWORK_NAMESPACE" "$pod" -- \
		sh -c "rm -f /work/${expected}.pcap /work/${expected}.log" || \
		requirement "could not prepare $pod capture evidence"
	# Exercise the image-owned bounded wrapper, not a raw tcpdump invocation.
	timeout --foreground 25 kubectl exec --namespace "$NETWORK_NAMESPACE" "$pod" -- \
		sh -c "net-debug capture --interface lo --duration 15 --packets 2 --snaplen 128 --filter 'tcp port 18080' --output ${expected}.pcap >/work/${expected}.log 2>&1" \
		>"$capture_log" 2>&1 &
	capture_pid=$!
	sleep 1
	kubectl exec --namespace "$NETWORK_NAMESPACE" "$pod" -- \
		curl --fail --silent --show-error --max-time 5 http://127.0.0.1:18080/ >/dev/null || \
		requirement "$pod HTTP traffic generator failed"
	if ! wait "$capture_pid"; then
		kubectl exec --namespace "$NETWORK_NAMESPACE" "$pod" -- \
			sh -c "cat /work/${expected}.log" >&2 || true
		requirement "$pod tcpdump did not capture generated HTTP packets"
	fi
	grep -Fx 'capture' <(kubectl exec --namespace "$NETWORK_NAMESPACE" "$pod" -- \
		cat "/work/${expected}.log") >/dev/null || requirement "$pod wrapper summary missing capture marker"
	grep -Fx 'packet_limit 2' <(kubectl exec --namespace "$NETWORK_NAMESPACE" "$pod" -- \
		cat "/work/${expected}.log") >/dev/null || requirement "$pod wrapper summary missing packet bound"
	packet_count=$(kubectl exec --namespace "$NETWORK_NAMESPACE" "$pod" -- \
		sed -n 's/^packet_count //p' "/work/${expected}.log")
	case "$packet_count" in ''|*[!0-9]*) requirement "$pod wrapper summary has an invalid packet count" ;; esac
	if [ "$packet_count" -le 0 ] || [ "$packet_count" -gt 2 ]; then
		requirement "$pod wrapper exceeded its packet bound"
	fi
	reported_hash=$(kubectl exec --namespace "$NETWORK_NAMESPACE" "$pod" -- \
		sed -n 's/^sha256 //p' "/work/${expected}.log")
	printf '%s\n' "$reported_hash" | grep -E '^[0-9a-f]{64}$' >/dev/null || requirement "$pod wrapper summary has an invalid hash"
	actual_hash=$(kubectl exec --namespace "$NETWORK_NAMESPACE" "$pod" -- \
		sha256sum "/work/${expected}.pcap" | awk '{print $1}')
	[ "$reported_hash" = "$actual_hash" ] || requirement "$pod wrapper hash did not match its pcap"
	capture_size=$(kubectl exec --namespace "$NETWORK_NAMESPACE" "$pod" -- \
		stat -c '%s' "/work/${expected}.pcap")
	[ "$capture_size" -gt 24 ] || requirement "$pod tcpdump produced an empty capture"
	[ "$capture_size" -le $((2 * (128 + 16) + 24)) ] || requirement "$pod wrapper exceeded its byte bound"
	kubectl exec --namespace "$NETWORK_NAMESPACE" "$pod" -- \
		tcpdump -nn -r "/work/${expected}.pcap" 'tcp port 18080' 2>/dev/null | \
		grep -F '18080' >/dev/null || requirement "$pod pcap omitted the generated HTTP endpoint"
	before_hash=$actual_hash
	if kubectl exec --namespace "$NETWORK_NAMESPACE" "$pod" -- \
		sh -c "net-debug capture --interface lo --duration 1 --packets 1 --snaplen 128 --filter 'tcp port 18080' --output ${expected}.pcap" >/dev/null 2>&1; then
		requirement "$pod wrapper overwrote an existing capture"
	fi
	actual_hash=$(kubectl exec --namespace "$NETWORK_NAMESPACE" "$pod" -- \
		sha256sum "/work/${expected}.pcap" | awk '{print $1}')
	[ "$before_hash" = "$actual_hash" ] || requirement "$pod wrapper changed an existing capture"
	# shellcheck disable=SC2016 # find is intentionally expanded in the target pod.
	kubectl exec --namespace "$NETWORK_NAMESPACE" "$pod" -- \
		sh -c 'test -z "$(find /work -maxdepth 1 -name ".net-debug.*" -print -quit)' || \
		requirement "$pod wrapper left staging residue"
}

capture_pod_traffic "$NETWORK_HOST_POD_NAME" host-network "$WORK_DIR/host-network-tcpdump.log"

kubectl delete pod "$NETWORK_HOST_POD_NAME" --namespace "$NETWORK_NAMESPACE" --wait=true --timeout=60s >/dev/null || \
	requirement "network diagnostics pod cleanup failed"
if kubectl get pod "$NETWORK_HOST_POD_NAME" --namespace "$NETWORK_NAMESPACE" >/dev/null 2>&1; then
	requirement "network diagnostics pod survived cleanup"
fi

printf '%s\n' 'Checking pwru packet events on an ephemeral capability-bounded namespace' >&2
PWRU_RUN_ARGS=(
	--cap-drop ALL
	--cap-add BPF
	--cap-add PERFMON
	--cap-add NET_ADMIN
	--cap-add SYS_RESOURCE
	--cap-add SYS_PTRACE
	--security-opt seccomp=unconfined
	--security-opt apparmor=unconfined
	--security-opt no-new-privileges=true
	--pid host
)
PWRU_READY=true
for kernel_path in /sys/kernel/btf/vmlinux /sys/kernel/debug /sys/kernel/tracing /sys/kernel/security; do
	if [ ! -e "$kernel_path" ]; then
		PWRU_READY=false
		printf 'REQUIREMENT: pwru requires a compatible Linux runner exposing %s; the dedicated BPF runner job is required\n' "$kernel_path" >&2
	fi
	PWRU_RUN_ARGS+=(--mount "type=bind,src=$kernel_path,dst=$kernel_path,readonly")
done
if [ "$PWRU_READY" = true ]; then
	btf_check=$(docker_call run --rm "${PWRU_RUN_ARGS[@]}" --network host "$IMAGE" sh -c \
		'test -r /sys/kernel/btf/vmlinux && test -d /sys/kernel/debug && test -d /sys/kernel/tracing && test -d /sys/kernel/security && echo ready' 2>&1) || \
		PWRU_READY=false
	if [ "$PWRU_READY" = true ] && [ "$btf_check" != ready ]; then
		PWRU_READY=false
		printf '%s\n' 'REQUIREMENT: pwru kernel prerequisites were not available; the dedicated BPF runner job is required' >&2
	fi
fi
if [ "$PWRU_READY" = true ]; then
	# Keep matching traffic flowing before and during attachment. A single
	# request after a slow kprobe startup is not a behavioral pwru proof: it can
	# finish before the hooks begin listening. This client has no capabilities,
	# is owner-labelled, and is removed by the same failure cleanup as the trace.
	if docker_call inspect "$TRACE_TRAFFIC_CONTAINER" >/dev/null 2>&1; then
		requirement "refusing to reuse an existing trace traffic container named $TRACE_TRAFFIC_CONTAINER"
	fi
	TRACE_TRAFFIC_CONTAINER_CREATED=true
	docker_call run --detach --name "$TRACE_TRAFFIC_CONTAINER" --label "$DOCKER_OWNER_LABEL=$RUN_ID" \
		--network host --cap-drop ALL --security-opt no-new-privileges=true "$IMAGE" sh -ec '
			while :; do
				curl --fail --silent --show-error --max-time 2 http://127.0.0.1:18080/ >/dev/null || true
				sleep 0.1
			done
		' >/dev/null 2>&1 || requirement "could not start owned trace traffic generator"
	docker_call run --rm --network host --cap-drop ALL --security-opt no-new-privileges=true \
		"$IMAGE" curl --fail --silent --show-error --max-time 5 http://127.0.0.1:18080/ >/dev/null || \
		requirement "trace HTTP traffic generator could not reach the fixture"
	# A generated name is expected to be absent. Refuse a collision before
	# claiming ownership so cleanup can never remove another run's container.
	if docker_call inspect "$PWRU_CONTAINER" >/dev/null 2>&1; then
		requirement "refusing to reuse an existing pwru proof container named $PWRU_CONTAINER"
	fi
	docker_call info >/dev/null 2>&1 || requirement "could not inspect pwru container because the Docker daemon is unavailable"
	# Mark ownership before creation. docker can create a container and then
	# return an error (or be interrupted), and EXIT cleanup must still force
	# remove that exact run-scoped name and verify it is gone.
	PWRU_CONTAINER_CREATED=true
	# Exercise the public bounded operation. This is deliberately not a raw
	# pwru command: net-debug performs the host-netns check, event/file bounds,
	# Native event/file bounds, graceful stop, pcap-free summary, and hash publication.
	trace_start_status=0
	docker_call run --detach --name "$PWRU_CONTAINER" --label "$DOCKER_OWNER_LABEL=$RUN_ID" \
		-e NETWORK_DEBUG_PWRU_STOP_TIMEOUT_SECONDS="$PWRU_STOP_TIMEOUT" \
		"${PWRU_RUN_ARGS[@]}" --network host "$IMAGE" trace \
			--duration "$TRACE_DURATION" --events "$TRACE_EVENTS" --filter 'tcp port 18080' --output trace.log \
		>"$WORK_DIR/trace-start.log" 2>&1 || trace_start_status=$?
	[ "$trace_start_status" -eq 0 ] || requirement "could not start public net-debug trace operation"
	# The wrapper's duration is itself bounded. Wait only through a separate
	# bounded Docker wait, then validate its public summary and evidence file.
	trace_wait_status=0
	trace_wait_started=$(date +%s)
	trace_exit=$(timeout --foreground "${PWRU_TIMEOUT}s" docker wait "$PWRU_CONTAINER" 2>/dev/null) || trace_wait_status=$?
	trace_wait_finished=$(date +%s)
	if [ "$trace_wait_status" -ne 0 ]; then
		# Keep the bounded failure actionable and terminate only this owned
		# invocation. The EXIT trap repeats ownership-checked cleanup.
		docker_call logs "$PWRU_CONTAINER" >&2 || true
		docker_call top "$PWRU_CONTAINER" >&2 || true
		if pwru_validate_owner "$PWRU_CONTAINER"; then
			docker_call kill --signal KILL "$PWRU_CONTAINER" >/dev/null 2>&1 || true
		fi
		requirement "public net-debug trace exceeded its bounded wait"
	fi
	trace_wait_elapsed=$((trace_wait_finished - trace_wait_started))
	[ "$trace_wait_elapsed" -le $((TRACE_DURATION + PWRU_STOP_TIMEOUT + 5)) ] || \
		requirement "public net-debug trace exceeded its duration and shutdown contract"
	trace_state=$(docker_call inspect --format '{{.State.Status}}' "$PWRU_CONTAINER" 2>/dev/null) || requirement "could not inspect completed trace container"
	[ "$trace_state" = exited ] || requirement "public net-debug trace container did not exit"
	trace_summary=$(docker_call logs "$PWRU_CONTAINER") || requirement "could not read public trace summary"
	case "$trace_exit" in 0|130|141|143) ;; *)
		printf '%s\n' 'public net-debug trace logs (owned invocation):' >&2
		printf '%s\n' "$trace_summary" >&2
		requirement "public net-debug trace exited unsuccessfully: $trace_exit"
		;;
	esac
	printf '%s\n' "$trace_summary" >"$WORK_DIR/trace-summary.txt"
	grep -Fx 'trace' "$WORK_DIR/trace-summary.txt" >/dev/null || requirement "public trace summary missing operation marker"
	grep -Fx "duration $TRACE_DURATION" "$WORK_DIR/trace-summary.txt" >/dev/null || requirement "public trace summary missing duration bound"
	grep -Fx "event_limit $TRACE_EVENTS" "$WORK_DIR/trace-summary.txt" >/dev/null || requirement "public trace summary missing event bound"
	trace_count=$(sed -n 's/^event_count //p' "$WORK_DIR/trace-summary.txt")
	case "$trace_count" in ''|*[!0-9]*) requirement "public trace summary has an invalid event count" ;; esac
	[ "$trace_count" -le "$TRACE_EVENTS" ] || requirement "public trace exceeded its event bound"
	grep -E '^sha256 [0-9a-f]{64}$' "$WORK_DIR/trace-summary.txt" >/dev/null || requirement "public trace summary missing SHA-256"
	grep -Fx 'file trace.log' "$WORK_DIR/trace-summary.txt" >/dev/null || requirement "public trace summary missing output name"
	docker_call cp "$PWRU_CONTAINER:/work/trace.log" "$WORK_DIR/trace.log" >/dev/null || requirement "public trace did not produce evidence"
	[ -s "$WORK_DIR/trace.log" ] || requirement "public trace evidence is empty"
	trace_bytes=$(wc -c <"$WORK_DIR/trace.log" | tr -d ' ')
	[ "$trace_bytes" -le $((TRACE_EVENTS * 4097)) ] || requirement "public trace evidence exceeds its size bound"
	grep -F -- '->' "$WORK_DIR/trace.log" >/dev/null || requirement "public trace evidence has no packet tuple"
	grep -E -- '127\.0\.0\.1.*->.*127\.0\.0\.1|127\.0\.0\.1.*18080' "$WORK_DIR/trace.log" >/dev/null || requirement "public trace missed generated loopback HTTP traffic"
	pwru_force_remove "$PWRU_CONTAINER" 15 || requirement "public trace container cleanup failed"
	PWRU_CONTAINER_CREATED=false
	if docker_resource_present container "$PWRU_CONTAINER"; then
		requirement "public trace container survived cleanup"
	else
		resource_status=$?
		[ "$resource_status" -eq 1 ] || requirement "could not verify public trace container cleanup"
	fi
fi


if [ "$PWRU_REQUIRED" = true ] && [ "$PWRU_READY" != true ]; then
	requirement "pwru was not exercised; run this integration target on the required Linux BPF runner"
fi

printf 'network-debug integration proofs passed\n'
