#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

IMAGE=${NETWORK_DEBUG_IMAGE:-network-debug:integration}
EXEC_TIMEOUT=${NETWORK_DEBUG_EXEC_TIMEOUT_SECONDS:-20}
PWRU_TIMEOUT=${NETWORK_DEBUG_PWRU_TIMEOUT_SECONDS:-20}
KUBESTR_TIMEOUT=${NETWORK_DEBUG_KUBESTR_TIMEOUT_SECONDS:-60}
KUBESTR_FIXTURE_IMAGE=${NETWORK_DEBUG_KUBESTR_FIXTURE_IMAGE:-network-debug-kubestr-fio:integration}
RUN_ID="network-debug-proof-${RANDOM}-${RANDOM}"
NETWORK=${RUN_ID}-network
CONTAINER=${RUN_ID}-tools
PWRU_CONTAINER=${RUN_ID}-pwru
KUBESTR_NAMESPACE=${RUN_ID}-storage
KIND_CLUSTER_NAME=${NETWORK_DEBUG_KIND_CLUSTER_NAME:-$RUN_ID}
KIND_NODE_IMAGE=${KIND_NODE_IMAGE:-kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5}
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

requirement() {
	printf 'REQUIREMENT: %s\n' "$*" >&2
	exit 2
}

for timeout_value in "$EXEC_TIMEOUT" "$PWRU_TIMEOUT" "$KUBESTR_TIMEOUT"; do
	case "$timeout_value" in
		''|*[!0-9]*) requirement "timeout settings must be positive integers" ;;
	esac
	[ "$timeout_value" -gt 0 ] || requirement "timeout settings must be positive integers"
done

cleanup() {
	status=$?
	set +e
	cleanup_failed=false
	kind_cluster_present() {
		clusters=$(kind get clusters 2>/dev/null) || return 2
		printf '%s\n' "$clusters" | grep -Fx "$KIND_CLUSTER_NAME" >/dev/null 2>&1
	}
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
		if kind_cluster_present; then
			if ! kind delete cluster --name "$KIND_CLUSTER_NAME" >/dev/null 2>&1; then
				cleanup_failed=true
			fi
		elif [ "$?" -eq 2 ]; then
			cleanup_failed=true
		fi
		if kind_cluster_present; then
			cleanup_failed=true
		elif [ "$?" -eq 2 ]; then
			cleanup_failed=true
		fi
	fi
	for docker_container in "$PWRU_CONTAINER" "$CONTAINER"; do
		container_owned=false
		if [ "$docker_container" = "$PWRU_CONTAINER" ] && [ "$PWRU_CONTAINER_CREATED" = true ]; then
			container_owned=true
		elif [ "$docker_container" = "$CONTAINER" ] && [ "$CONTAINER_CREATED" = true ]; then
			container_owned=true
		fi
		if [ "$container_owned" = true ]; then
			if docker inspect "$docker_container" >/dev/null 2>&1; then
				if ! docker rm -f "$docker_container" >/dev/null 2>&1; then
					cleanup_failed=true
				fi
				if docker inspect "$docker_container" >/dev/null 2>&1; then
					cleanup_failed=true
				fi
			elif ! docker info >/dev/null 2>&1; then
				cleanup_failed=true
			fi
		fi
	done
	if [ "$NETWORK_CREATED" = true ]; then
		if docker network inspect "$NETWORK" >/dev/null 2>&1; then
			if ! docker network rm "$NETWORK" >/dev/null 2>&1; then
				cleanup_failed=true
			fi
			if docker network inspect "$NETWORK" >/dev/null 2>&1; then
				cleanup_failed=true
			fi
		elif ! docker info >/dev/null 2>&1; then
			cleanup_failed=true
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

command -v docker >/dev/null 2>&1 || requirement "docker is required to run disposable integration containers"
command -v kind >/dev/null 2>&1 || requirement "kind is required to run the disposable Kubernetes integration cluster"
command -v kubectl >/dev/null 2>&1 || requirement "kubectl is required to run the disposable Kubernetes integration cluster"
command -v jq >/dev/null 2>&1 || requirement "jq is required to validate the structured kubestr fio result"
command -v timeout >/dev/null 2>&1 || requirement "GNU timeout is required for bounded integration commands"
docker image inspect "$IMAGE" >/dev/null 2>&1 || requirement "image $IMAGE is unavailable; build it before running integration proofs"
docker image inspect "$KUBESTR_FIXTURE_IMAGE" >/dev/null 2>&1 || requirement "fixture image $KUBESTR_FIXTURE_IMAGE is unavailable; build it before running integration proofs"

# Never mutate a caller-selected Kubernetes context. The proof owns the kind
# cluster and its kubeconfig from creation through cleanup, so invoking this
# script locally cannot accidentally create a namespace or PVC in production.
kind_clusters=$(kind get clusters) || requirement "could not inspect existing kind clusters before creating the disposable cluster"
if printf '%s\n' "$kind_clusters" | grep -Fx "$KIND_CLUSTER_NAME" >/dev/null; then
	requirement "refusing to reuse an existing kind cluster named $KIND_CLUSTER_NAME"
fi
kind create cluster --name "$KIND_CLUSTER_NAME" --image "$KIND_NODE_IMAGE" \
	--kubeconfig "$KUBECONFIG_FILE" --wait 120s || requirement "could not create the disposable kind cluster"
KIND_CLUSTER_CREATED=true
export KUBECONFIG="$KUBECONFIG_FILE"
kubectl wait --for=condition=Ready nodes --all --timeout=180s >/dev/null || requirement "disposable kind nodes did not become ready"
kind load docker-image "$KUBESTR_FIXTURE_IMAGE" --name "$KIND_CLUSTER_NAME" || requirement "could not load the disposable fio fixture into kind"

docker network create "$NETWORK" >/dev/null || requirement "Docker could not create an ephemeral network"
NETWORK_CREATED=true
docker run --detach --name "$CONTAINER" --network "$NETWORK" \
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
CONTAINER_CREATED=true

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
	docker exec "$CONTAINER" sh -c 'cat /work/tcpdump.log' >&2 || true
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
	--cap-add NET_RAW
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
	btf_check=$(docker run --rm "${PWRU_RUN_ARGS[@]}" --network "container:$CONTAINER" "$IMAGE" sh -c \
		'test -r /sys/kernel/btf/vmlinux && test -d /sys/kernel/debug && test -d /sys/kernel/tracing && test -d /sys/kernel/security && echo ready' 2>&1) || \
		PWRU_READY=false
	if [ "$PWRU_READY" = true ] && [ "$btf_check" != ready ]; then
		PWRU_READY=false
		printf '%s\n' 'REQUIREMENT: pwru kernel prerequisites were not available; the dedicated BPF runner job is required' >&2
	fi
fi
if [ "$PWRU_READY" = true ]; then
	docker run --detach --name "$PWRU_CONTAINER" "${PWRU_RUN_ARGS[@]}" --network "container:$CONTAINER" \
		"$IMAGE" pwru --output-limit-lines 20 --output-tuple --output-file /work/pwru.log --timestamp none \
			 host 127.0.0.1 \
		>"$WORK_DIR/pwru-start.log" 2>&1 || requirement "could not start pwru proof container"
	PWRU_CONTAINER_CREATED=true
	sleep 2
	exec_in curl --fail --silent --show-error --max-time 5 http://127.0.0.1:18080/ >/dev/null || requirement "pwru HTTP traffic generator failed"
	exec_in ping -n -c 1 -W 1 127.0.0.1 >/dev/null || requirement "pwru traffic generator failed"
	pwru_state=running
	for _ in $(seq 1 "$((PWRU_TIMEOUT * 2))"); do
		pwru_state=$(docker inspect --format '{{.State.Status}}' "$PWRU_CONTAINER")
		if [ "$pwru_state" = exited ]; then
			break
		fi
		sleep 0.5
	done
	[ "$pwru_state" = exited ] || requirement "pwru exceeded its ${PWRU_TIMEOUT}s bounded event window"
	pwru_exit=$(docker inspect --format '{{.State.ExitCode}}' "$PWRU_CONTAINER")
	[ "$pwru_exit" = 0 ] || {
		docker logs "$PWRU_CONTAINER" >&2 || true
		requirement "pwru could not attach/observe events; the compatible runner needs BTF, BPF, and PERFMON support"
	}
	docker cp "$PWRU_CONTAINER:/work/pwru.log" "$WORK_DIR/pwru.log" >/dev/null || requirement "pwru did not produce an event log"
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

[ "$PWRU_READY" = true ] || requirement "pwru was not exercised; run this integration target on the required Linux BPF runner"

printf 'network-debug integration proofs passed\n'
