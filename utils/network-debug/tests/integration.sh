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
WORK_DIR=$(mktemp -d "${TMPDIR:-/tmp}/network-debug-proof.XXXXXX")
KUBESTR_NAMESPACE_CREATED=false

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
	set +e
	if [ "$KUBESTR_NAMESPACE_CREATED" = true ] && command -v kubectl >/dev/null 2>&1; then
		kubectl delete namespace "$KUBESTR_NAMESPACE" --ignore-not-found --wait=true --timeout=60s >/dev/null 2>&1
	fi
	docker rm -f "$PWRU_CONTAINER" "$CONTAINER" >/dev/null 2>&1
	docker network rm "$NETWORK" >/dev/null 2>&1
	rm -rf "$WORK_DIR"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

command -v docker >/dev/null 2>&1 || requirement "docker is required to run disposable integration containers"
command -v timeout >/dev/null 2>&1 || requirement "GNU timeout is required for bounded integration commands"
docker image inspect "$IMAGE" >/dev/null 2>&1 || requirement "image $IMAGE is unavailable; build it before running integration proofs"

docker network create "$NETWORK" >/dev/null || requirement "Docker could not create an ephemeral network"
docker run --detach --name "$CONTAINER" --network "$NETWORK" \
	--cap-add NET_RAW --cap-add NET_ADMIN \
	"$IMAGE" sh -c '
		mkdir -p /work/www
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
exec_in curl --fail --silent --show-error --max-time 10 https://example.com/ >/dev/null || requirement "curl TLS check failed; outbound HTTPS is required"

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
		pwru) tool_pattern="^${tool}[[:space:]]+pwru v[0-9]+" ;;
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
for kernel_path in /sys/kernel/btf/vmlinux /sys/kernel/debug /sys/kernel/tracing /sys/kernel/security; do
	if [ ! -e "$kernel_path" ]; then
		requirement "pwru requires a compatible Linux runner exposing $kernel_path; use the required BPF runner job"
	fi
	PWRU_RUN_ARGS+=(--mount "type=bind,src=$kernel_path,dst=$kernel_path,readonly")
done
btf_check=$(docker run --rm "${PWRU_RUN_ARGS[@]}" --network "container:$CONTAINER" "$IMAGE" sh -c \
	'test -r /sys/kernel/btf/vmlinux && test -d /sys/kernel/debug && test -d /sys/kernel/tracing && test -d /sys/kernel/security && echo ready' 2>&1) || \
	requirement "pwru requires readable BTF, tracing, securityfs, and BPF/PERFMON capability; use the required compatible Linux runner job"
test "$btf_check" = ready || requirement "pwru kernel prerequisites were not available"
docker run --detach --name "$PWRU_CONTAINER" "${PWRU_RUN_ARGS[@]}" --network "container:$CONTAINER" \
	"$IMAGE" pwru --output-limit-lines 20 --output-tuple --output-file /work/pwru.log --timestamp none \
		host 127.0.0.1 \
	>"$WORK_DIR/pwru-start.log" 2>&1 || requirement "could not start pwru proof container"
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

if [ -z "${KUBECONFIG:-}" ] || [ ! -f "$KUBECONFIG" ]; then
	requirement "KUBECONFIG must point to a disposable kind cluster for the kubestr storage proof"
fi
command -v kubectl >/dev/null 2>&1 || requirement "kubectl is required for the disposable kubestr proof"
command -v jq >/dev/null 2>&1 || requirement "jq is required to validate the structured kubestr fio result"
kubectl get storageclass standard >/dev/null 2>&1 || requirement "a default 'standard' StorageClass is required for kubestr fio"
kubectl create namespace "$KUBESTR_NAMESPACE" >/dev/null || requirement "could not create disposable kubestr namespace"
KUBESTR_NAMESPACE_CREATED=true
kubectl config view --raw --minify > "$WORK_DIR/kubeconfig"
timeout --foreground "${KUBESTR_TIMEOUT}s" docker run --rm --network host \
	--env KUBECONFIG=/work/kubeconfig \
	--volume "$WORK_DIR/kubeconfig:/work/kubeconfig:ro" \
	--volume "$WORK_DIR:/work/results" \
	"$IMAGE" kubestr fio \
		--storageclass standard --size 1Mi --testname default-fio \
		--namespace "$KUBESTR_NAMESPACE" --image "$KUBESTR_FIXTURE_IMAGE" \
		--output json \
		--outfile /work/results/kubestr.out \
	|| requirement "kubestr fio failed; kind needs a functional disposable StorageClass and the loaded fio fixture image"
[ -s "$WORK_DIR/kubestr.out" ] || requirement "kubestr completed without a result file"
jq -e 'type == "array" and length > 0 and any(.[]; type == "object" and (.result != null or .fioConfig != null or .storageClass != null))' "$WORK_DIR/kubestr.out" >/dev/null || requirement "kubestr result did not contain a structured fio result"
kubectl delete namespace "$KUBESTR_NAMESPACE" --wait=true --timeout=60s >/dev/null || requirement "kubestr namespace cleanup failed"
if kubectl get namespace "$KUBESTR_NAMESPACE" >/dev/null 2>&1; then
	requirement "kubestr namespace still exists after cleanup"
fi
KUBESTR_NAMESPACE_CREATED=false

printf 'network-debug integration proofs passed\n'
