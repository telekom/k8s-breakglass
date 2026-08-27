#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

IMAGE=${NETWORK_DEBUG_IMAGE:-network-debug:integration}
EXEC_TIMEOUT=${NETWORK_DEBUG_EXEC_TIMEOUT_SECONDS:-20}
DOCKER_TIMEOUT=${NETWORK_DEBUG_DOCKER_TIMEOUT_SECONDS:-30}
PWRU_TIMEOUT=${NETWORK_DEBUG_PWRU_TIMEOUT_SECONDS:-20}
PWRU_REQUIRED=${NETWORK_DEBUG_REQUIRE_PWRU:-true}
# BPF detach is asynchronous on some kernels; keep graceful shutdown bounded
# while allowing the daemon a short, evidence-backed detach window.
PWRU_STOP_TIMEOUT=${NETWORK_DEBUG_PWRU_STOP_TIMEOUT_SECONDS:-15}
KUBESTR_TIMEOUT=${NETWORK_DEBUG_KUBESTR_TIMEOUT_SECONDS:-60}
KUBESTR_FIXTURE_IMAGE=${NETWORK_DEBUG_KUBESTR_FIXTURE_IMAGE:-network-debug-kubestr-fio:integration}
RUN_ID="network-debug-proof-${RANDOM}-${RANDOM}"
NETWORK=${RUN_ID}-network
CONTAINER=${RUN_ID}-tools
PWRU_CONTAINER=${RUN_ID}-pwru
KUBESTR_NAMESPACE=${RUN_ID}-storage
# Never accept a caller-selected cluster name: the random run ID is the only
# name this invocation can own after its absent-name preflight.
KIND_CLUSTER_NAME=$RUN_ID
KIND_NODE_IMAGE=${KIND_NODE_IMAGE:-kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5}
KIND_BIN=${NETWORK_DEBUG_KIND_BIN:-kind}
# shellcheck disable=SC2034 # consumed by the sourced ownership helper
DOCKER_BIN=${NETWORK_DEBUG_DOCKER_BIN:-docker}
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/network-debug-proof.XXXXXX")
KUBECONFIG_FILE=${WORK_DIR}/kubeconfig
KUBESTR_PV_NAME=${RUN_ID}-pv
KUBESTR_STORAGE_CLASS=${RUN_ID}-storage-class
KIND_CLUSTER_CREATED=false
KUBESTR_NAMESPACE_CREATED=false
NETWORK_CREATED=false
CONTAINER_CREATED=false
PWRU_CONTAINER_CREATED=false
KUBESTR_KUBECONFIG_FILE=${WORK_DIR}/kubestr-kubeconfig
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

for timeout_value in "$EXEC_TIMEOUT" "$DOCKER_TIMEOUT" "$PWRU_TIMEOUT" "$PWRU_STOP_TIMEOUT" "$KUBESTR_TIMEOUT"; do
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
		if [ "$KUBESTR_NAMESPACE_CREATED" = true ] && command -v kubectl >/dev/null 2>&1; then
			if ! kubectl --kubeconfig "$KUBECONFIG_FILE" delete namespace "$KUBESTR_NAMESPACE" --ignore-not-found --wait=true --timeout=60s >/dev/null 2>&1; then
				cleanup_failed=true
			fi
			if kubectl --kubeconfig "$KUBECONFIG_FILE" get namespace "$KUBESTR_NAMESPACE" >/dev/null 2>&1; then
				cleanup_failed=true
			fi
		fi
		if kubectl --kubeconfig "$KUBECONFIG_FILE" get persistentvolume "$KUBESTR_PV_NAME" >/dev/null 2>&1; then
			if ! kubectl --kubeconfig "$KUBECONFIG_FILE" delete persistentvolume "$KUBESTR_PV_NAME" --ignore-not-found >/dev/null 2>&1; then
				cleanup_failed=true
			fi
			if kubectl --kubeconfig "$KUBECONFIG_FILE" get persistentvolume "$KUBESTR_PV_NAME" >/dev/null 2>&1; then
				cleanup_failed=true
			fi
		fi
		if kubectl --kubeconfig "$KUBECONFIG_FILE" get storageclass "$KUBESTR_STORAGE_CLASS" >/dev/null 2>&1; then
			if ! kubectl --kubeconfig "$KUBECONFIG_FILE" delete storageclass "$KUBESTR_STORAGE_CLASS" --ignore-not-found >/dev/null 2>&1; then
				cleanup_failed=true
			fi
			if kubectl --kubeconfig "$KUBECONFIG_FILE" get storageclass "$KUBESTR_STORAGE_CLASS" >/dev/null 2>&1; then
				cleanup_failed=true
			fi
		fi
	fi
	if ! kind_cleanup_owned_cluster; then
			cleanup_failed=true
	fi
	for docker_container in "$PWRU_CONTAINER" "$CONTAINER"; do
		container_owned=false
		if [ "$docker_container" = "$PWRU_CONTAINER" ] && [ "$PWRU_CONTAINER_CREATED" = true ]; then
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

docker_resource_present() {
	local kind=$1 name=$2 state
	if docker_owned_resource "$kind" "$name" >/dev/null 2>&1; then
		return 0
	fi
	state=$?
	[ "$state" -eq 3 ] && return 3
	# An inspect failure may mean that the resource is gone, but only a
	# reachable daemon can establish that. Ownership mismatches fail closed.
	docker_call info >/dev/null 2>&1 || return 2
	if docker_owned_resource "$kind" "$name" >/dev/null 2>&1; then
		return 0
	fi
	state=$?
	[ "$state" -eq 3 ] && return 3
	[ "$state" -eq 2 ] && { docker_call info >/dev/null 2>&1 || return 2; }
	return 1
}

command -v docker >/dev/null 2>&1 || requirement "docker is required to run disposable integration containers"
command -v "$KIND_BIN" >/dev/null 2>&1 || requirement "kind is required to run the disposable Kubernetes integration cluster"
command -v kubectl >/dev/null 2>&1 || requirement "kubectl is required to run the disposable Kubernetes integration cluster"
command -v jq >/dev/null 2>&1 || requirement "jq is required to validate the structured kubestr fio result"
command -v timeout >/dev/null 2>&1 || requirement "GNU timeout is required for bounded integration commands"
docker_call image inspect "$IMAGE" >/dev/null 2>&1 || requirement "image $IMAGE is unavailable; build it before running integration proofs"
docker_call image inspect "$KUBESTR_FIXTURE_IMAGE" >/dev/null 2>&1 || requirement "fixture image $KUBESTR_FIXTURE_IMAGE is unavailable; build it before running integration proofs"

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
"$KIND_BIN" load docker-image "$KUBESTR_FIXTURE_IMAGE" --name "$KIND_CLUSTER_NAME" || requirement "could not load the disposable fio fixture into kind"

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
	--cap-add NET_RAW --cap-add NET_ADMIN \
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
for tool in curl dig host nslookup nc ping tracepath traceroute mtr ip ss tcpdump ethtool kubestr pwru; do
	case "$tool" in
		kubestr|pwru) tool_pattern="^${tool}[[:space:]]+${tool} v[0-9]+" ;;
		*) tool_pattern="^${tool}[[:space:]]+installed$" ;;
	esac
	printf '%s\n' "$tools_output" | grep -E "$tool_pattern" >/dev/null || requirement "$tool is not installed according to net-debug tools"
done

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

printf '%s\n' 'Checking pwru packet events on an ephemeral capability-bounded namespace' >&2
PWRU_RUN_ARGS=(
	--cap-add BPF
	--cap-add PERFMON
	--cap-add NET_ADMIN
	--cap-add SYS_RESOURCE
	--security-opt seccomp=unconfined
	--security-opt apparmor=unconfined
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
	btf_check=$(docker_call run --rm "${PWRU_RUN_ARGS[@]}" --network "container:$CONTAINER" "$IMAGE" sh -c \
		'test -r /sys/kernel/btf/vmlinux && test -d /sys/kernel/debug && test -d /sys/kernel/tracing && test -d /sys/kernel/security && echo ready' 2>&1) || \
		PWRU_READY=false
	if [ "$PWRU_READY" = true ] && [ "$btf_check" != ready ]; then
		PWRU_READY=false
		printf '%s\n' 'REQUIREMENT: pwru kernel prerequisites were not available; the dedicated BPF runner job is required' >&2
	fi
fi
if [ "$PWRU_READY" = true ]; then
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
	docker_call run --detach --name "$PWRU_CONTAINER" --label "$DOCKER_OWNER_LABEL=$RUN_ID" "${PWRU_RUN_ARGS[@]}" --network "container:$CONTAINER" \
		"$IMAGE" pwru --output-tuple --output-file /work/pwru.log --timestamp none \
				host 127.0.0.1 \
		>"$WORK_DIR/pwru-start.log" 2>&1 || requirement "could not start pwru proof container"
	sleep 2
	exec_in curl --fail --silent --show-error --max-time 5 http://127.0.0.1:18080/ >/dev/null || requirement "pwru HTTP traffic generator failed"
	exec_in ping -n -c 1 -W 1 127.0.0.1 >/dev/null || requirement "pwru traffic generator failed"
	# --output-limit-lines only exits after enough events have been observed;
	# sparse traffic can therefore leave pwru running indefinitely. Poll the
	# output file for a real tuple from the generated traffic, then explicitly
	# stop pwru. This gives the proof a bounded observation window independent of
	# pwru's event loop and proves that the graceful signal was honoured.
	pwru_wait_for_event "$PWRU_CONTAINER" "$WORK_DIR/pwru.log" "$PWRU_TIMEOUT" \
		'127\.0\.0\.1.*->.*127\.0\.0\.1|127\.0\.0\.1.*18080' || {
		pwru_state=$(docker_call inspect --format '{{.State.Status}}' "$PWRU_CONTAINER" || true)
		if [ "$pwru_state" = exited ]; then
			requirement "pwru exited before controlled shutdown"
		fi
		requirement "pwru produced no packet tuple for generated traffic within ${PWRU_TIMEOUT}s"
	}
	pwru_stop_gracefully "$PWRU_CONTAINER" "$PWRU_STOP_TIMEOUT" || {
		pwru_exit=$(docker_call inspect --format '{{.State.ExitCode}}' "$PWRU_CONTAINER" || true)
		docker_call logs "$PWRU_CONTAINER" >&2 || true
		requirement "pwru did not cleanly exit after SIGINT (exit ${pwru_exit:-unknown}); the compatible runner needs BTF, BPF, and PERFMON support"
	}
	docker_call cp "$PWRU_CONTAINER:/work/pwru.log" "$WORK_DIR/pwru.log" >/dev/null || requirement "pwru did not produce an event log"
	[ -s "$WORK_DIR/pwru.log" ] || requirement "pwru event log is empty after generated traffic"
	grep -F -- '->' "$WORK_DIR/pwru.log" >/dev/null || requirement "pwru produced no packet tuple after generated traffic"
	grep -E -- '127\.0\.0\.1.*->.*127\.0\.0\.1|127\.0\.0\.1.*18080' "$WORK_DIR/pwru.log" >/dev/null || requirement "pwru did not observe the generated loopback HTTP traffic"
fi

# Use a static, disposable PV so this proof does not depend on a cluster-wide
# storage provisioner. Both objects live only in the kind cluster owned above.
kubectl apply -f - >/dev/null <<YAML || requirement "could not create disposable standard storage"
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: ${KUBESTR_STORAGE_CLASS}
provisioner: kubernetes.io/no-provisioner
volumeBindingMode: Immediate
---
apiVersion: v1
kind: PersistentVolume
metadata:
  name: ${KUBESTR_PV_NAME}
spec:
  capacity:
    storage: 1Gi
  accessModes: [ReadWriteOnce]
  persistentVolumeReclaimPolicy: Delete
  storageClassName: ${KUBESTR_STORAGE_CLASS}
  hostPath:
    path: /var/local/${RUN_ID}
    type: DirectoryOrCreate
YAML
kubectl create namespace "$KUBESTR_NAMESPACE" >/dev/null || requirement "could not create disposable kubestr namespace"
KUBESTR_NAMESPACE_CREATED=true
kubectl config view --raw --minify > "$KUBESTR_KUBECONFIG_FILE"
timeout --foreground "${KUBESTR_TIMEOUT}s" docker run --rm --network host \
	--env KUBECONFIG=/work/kubeconfig \
	--volume "$KUBESTR_KUBECONFIG_FILE:/work/kubeconfig:ro" \
	--volume "$WORK_DIR:/work/results" \
	"$IMAGE" kubestr fio \
		--storageclass "$KUBESTR_STORAGE_CLASS" --size 1Mi --testname default-fio \
		--namespace "$KUBESTR_NAMESPACE" --image "$KUBESTR_FIXTURE_IMAGE" \
		--output json \
		--outfile /work/results/kubestr.out \
	|| requirement "kubestr fio failed; kind needs a functional disposable StorageClass and the loaded fio fixture image"
[ -s "$WORK_DIR/kubestr.out" ] || requirement "kubestr completed without a result file"
if ! jq -e '
  type == "array" and length > 0 and
  any(.[];
    type == "object" and
    (.Raw.result["fio version"] | type == "string" and startswith("fio-")) and
    (.Raw.result.jobs | type == "array" and length == 4) and
    all(.Raw.result.jobs[];
      (.jobname | type == "string" and length > 0) and
      (((.read.iops // .write.iops) | type == "number" and . > 0))
    )
  )
' "$WORK_DIR/kubestr.out" >/dev/null; then
	printf '%s\n' 'kubestr output:' >&2
	cat "$WORK_DIR/kubestr.out" >&2
	requirement "kubestr result did not contain a structured fio result"
fi
kubectl delete namespace "$KUBESTR_NAMESPACE" --wait=true --timeout=60s >/dev/null || requirement "kubestr namespace cleanup failed"
if kubectl get namespace "$KUBESTR_NAMESPACE" >/dev/null 2>&1; then
	requirement "kubestr namespace still exists after cleanup"
fi
KUBESTR_NAMESPACE_CREATED=false
kubectl delete persistentvolume "$KUBESTR_PV_NAME" --ignore-not-found >/dev/null || requirement "disposable storage PV cleanup failed"
if kubectl get persistentvolume "$KUBESTR_PV_NAME" >/dev/null 2>&1; then
	requirement "disposable storage PV still exists after cleanup"
fi
kubectl delete storageclass "$KUBESTR_STORAGE_CLASS" --ignore-not-found >/dev/null || requirement "disposable storage class cleanup failed"

if [ "$PWRU_REQUIRED" = true ] && [ "$PWRU_READY" != true ]; then
	requirement "pwru was not exercised; run this integration target on the required Linux BPF runner"
fi

printf 'network-debug integration proofs passed\n'
