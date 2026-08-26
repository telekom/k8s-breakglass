#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail

root=$(cd -- "$(dirname "$0")/.." && pwd)
image=${WORKLOAD_DEBUG_IMAGE:-workload-debug:integration-$$}
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/workload-debug.XXXXXX")
dns_pid=
http_pid=
tls_pid=
kind_name="workload-debug-${$}"
kind_created=0
leak_container=

fail() { printf 'integration failure: %s\n' "$*" >&2; exit 1; }
assert_contains() { [[ "$1" == *"$2"* ]] || fail "expected output to contain: $2"; }
assert_not_contains() { [[ "$1" != *"$2"* ]] || fail "output unexpectedly contained: $2"; }

cleanup() {
    status=$?
    if [[ -n "$leak_container" ]]; then
        docker rm -f "$leak_container" >/dev/null 2>&1 || true
    fi
    for pid in "$dns_pid" "$http_pid" "$tls_pid"; do
        if [[ -n "$pid" ]] && kill -0 "$pid" 2>/dev/null; then
            kill "$pid" 2>/dev/null || true
            wait "$pid" 2>/dev/null || true
            if kill -0 "$pid" 2>/dev/null; then
                printf 'integration cleanup failure: fixture process %s remains\n' "$pid" >&2
                status=1
            fi
        fi
    done
    if [[ "$kind_created" -eq 1 ]]; then
        kind delete cluster --name "$kind_name" >/dev/null 2>&1 || true
        if kind get clusters 2>/dev/null | grep -Fx "$kind_name" >/dev/null; then
            printf 'integration cleanup failure: kind cluster %s remains\n' "$kind_name" >&2
            status=1
        fi
    fi
    rm -rf "$fixture_dir"
    [[ ! -e "$fixture_dir" ]] || { printf 'integration cleanup failure: fixture directory remains\n' >&2; status=1; }
    docker image rm "$image" >/dev/null 2>&1 || true
    exit "$status"
}
trap cleanup EXIT

for command in docker kind kubectl openssl python3; do
    command -v "$command" >/dev/null 2>&1 || fail "required command is unavailable: $command"
done
docker info >/dev/null 2>&1 || fail 'Docker daemon is unavailable; run integration-test on a container runner'

read -r dns_port http_port tls_port < <(python3 -c 'import socket; ports=[]; [ports.append((lambda s: (s.bind(("127.0.0.1", 0)), s.getsockname()[1], s.close())[1])(socket.socket())) for _ in range(3)]; print(*ports)')
dns_name=workload.fixture.test
base_url="http://127.0.0.1:$http_port"

printf '%s\n' 'Building workload-debug integration image'
docker build --pull=false --tag "$image" "$root" >/dev/null

python3 "$root/tests/fixtures.py" dns --port "$dns_port" --name "$dns_name" --address 203.0.113.7 >"$fixture_dir/dns.log" 2>&1 &
dns_pid=$!
python3 "$root/tests/fixtures.py" http --port "$http_port" >"$fixture_dir/http.log" 2>&1 &
http_pid=$!

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=workload-debug fixture CA' \
    -keyout "$fixture_dir/ca.key" -out "$fixture_dir/ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj '/CN=localhost' \
    -keyout "$fixture_dir/server.key" -out "$fixture_dir/server.csr" >/dev/null 2>&1
printf '%s\n' 'subjectAltName=DNS:localhost,IP:127.0.0.1' >"$fixture_dir/server.ext"
openssl x509 -req -days 1 -in "$fixture_dir/server.csr" -CA "$fixture_dir/ca.crt" \
    -CAkey "$fixture_dir/ca.key" -CAcreateserial -out "$fixture_dir/server.crt" \
    -extfile "$fixture_dir/server.ext" >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj '/CN=wrong fixture CA' \
    -keyout "$fixture_dir/wrong-ca.key" -out "$fixture_dir/wrong-ca.crt" >/dev/null 2>&1
openssl s_server -accept "$tls_port" -cert "$fixture_dir/server.crt" -key "$fixture_dir/server.key" \
    -www -quiet >"$fixture_dir/tls.log" 2>&1 &
tls_pid=$!

for port in "$http_port" "$tls_port"; do
    for _ in {1..50}; do
        if python3 -c 'import socket,sys; s=socket.socket(); s.settimeout(.1); ok=s.connect_ex(("127.0.0.1", int(sys.argv[1]))) == 0; s.close(); raise SystemExit(0 if ok else 1)' "$port"; then break; fi
        sleep .1
    done
    python3 -c 'import socket,sys; s=socket.socket(); s.settimeout(.2); rc=s.connect_ex(("127.0.0.1", int(sys.argv[1]))); s.close(); raise SystemExit(rc != 0)' "$port" || fail "fixture did not start on port $port"
done
sleep .2

run_image() {
    docker run --rm --network host --read-only --cap-drop=ALL --security-opt=no-new-privileges:true \
        --user 65532:65532 --volume "$fixture_dir:/fixtures:ro" -e WORKLOAD_DEBUG_MOTD=0 \
        "$image" "$@"
}

# The awk expressions are intentionally evaluated inside the container.
# shellcheck disable=SC2016
policy=$(run_image sh -c 'id; awk "/CapEff/{print \$2}" /proc/self/status; awk "/NoNewPrivs/{print \$2}" /proc/self/status; ! touch /must-not-exist')
assert_contains "$policy" 'uid=65532'
assert_contains "$policy" '0000000000000000'
assert_contains "$policy" '1'

dns_output=$(run_image workload-debug dns --server "127.0.0.1#$dns_port" "$dns_name")
assert_contains "$dns_output" '203.0.113.7'

tls_output=$(run_image workload-debug tls --ca /fixtures/ca.crt "localhost:$tls_port")
assert_contains "$tls_output" 'TLS endpoint: localhost:'
assert_contains "$tls_output" 'Verification: OK'
if run_image workload-debug tls --ca /fixtures/wrong-ca.crt "localhost:$tls_port" >/dev/null 2>&1; then
    fail 'TLS accepted a certificate signed by an untrusted CA'
fi
if run_image workload-debug tls --timeout 1 "localhost:1" >/dev/null 2>&1; then
    fail 'TLS accepted an unavailable endpoint'
fi

get_output=$(run_image workload-debug http "$base_url/get")
assert_contains "$get_output" 'fixture-get'
head_output=$(run_image workload-debug http --method HEAD "$base_url/head")
assert_contains "$head_output" 'X-Fixture: head'
assert_not_contains "$head_output" 'fixture-head'
options_output=$(run_image workload-debug http --method OPTIONS "$base_url/options")
assert_contains "$options_output" 'Allow: GET, HEAD, OPTIONS'
redirect_output=$(run_image workload-debug http "$base_url/redirect")
assert_contains "$redirect_output" 'Location: /get'
assert_not_contains "$redirect_output" 'fixture-get'
if WORKLOAD_DEBUG_MAX_BYTES=64 run_image workload-debug http "$base_url/large" >/dev/null 2>&1; then
    fail 'HTTP accepted a response larger than the configured bound'
fi
set +e
WORKLOAD_DEBUG_TIMEOUT=1 timeout 5 docker run --rm --network host --read-only --cap-drop=ALL \
    --security-opt=no-new-privileges:true --user 65532:65532 --volume "$fixture_dir:/fixtures:ro" \
    -e WORKLOAD_DEBUG_MOTD=0 "$image" workload-debug http "$base_url/slow" >/dev/null 2>&1
timeout_status=$?
set -e
[[ "$timeout_status" -ne 0 && "$timeout_status" -ne 124 ]] || fail 'HTTP timeout was not enforced by the helper'
if run_image workload-debug http --method POST "$base_url/get" >/dev/null 2>&1; then
    fail 'HTTP accepted a mutating method'
fi

report_one=$(run_image workload-debug report --json --dns "$dns_name" \
    --dns-server "127.0.0.1#$dns_port" --tls "localhost:$tls_port" --tls-ca /fixtures/ca.crt \
    --http "$base_url/get")
report_two=$(run_image workload-debug report --json --dns "$dns_name" \
    --dns-server "127.0.0.1#$dns_port" --tls "localhost:$tls_port" --tls-ca /fixtures/ca.crt \
    --http "$base_url/get")
[[ "$report_one" == "$report_two" ]] || fail 'JSON diagnostic report is not deterministic'
assert_contains "$report_one" '"checks_failed":0'
assert_contains "$report_one" '"schema_version":1'
printf '%s' "$report_one" | jq -e '.checks | length == 3 and all(.success == true)' >/dev/null

kind create cluster --name "$kind_name" --wait 120s >/dev/null
kind_created=1
kubectl config use-context "kind-$kind_name" >/dev/null
namespace="workload-debug-fixture"
kubectl create namespace "$namespace" >/dev/null
kubectl create serviceaccount workload-debug -n "$namespace" >/dev/null
kubectl create role workload-debug-reader --verb=get --resource=configmaps -n "$namespace" >/dev/null
kubectl create rolebinding workload-debug-reader --role=workload-debug-reader \
    --serviceaccount="$namespace:workload-debug" -n "$namespace" >/dev/null
kubectl create configmap fixture --from-literal=result=kind-service-account -n "$namespace" >/dev/null
kubectl create token workload-debug -n "$namespace" --duration=10m >"$fixture_dir/token"
chmod 0444 "$fixture_dir/token"
kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.certificate-authority-data}' \
    | base64 --decode >"$fixture_dir/kube-ca.crt"
server=$(kubectl config view --raw --minify -o jsonpath='{.clusters[0].cluster.server}')
kube_output=$(run_image workload-debug kube-api --server "$server" --ca /fixtures/kube-ca.crt \
    --token /fixtures/token "/api/v1/namespaces/$namespace/configmaps/fixture")
assert_contains "$kube_output" 'kind-service-account'
assert_not_contains "$kube_output" "$(<"$fixture_dir/token")"

leak_container="workload-debug-token-check-$$"
docker run --detach --name "$leak_container" --network host --read-only --cap-drop=ALL \
    --security-opt=no-new-privileges:true --user 65532:65532 --volume "$fixture_dir:/fixtures:ro" \
    -e WORKLOAD_DEBUG_MOTD=0 "$image" workload-debug kube-api --server "$base_url/slow" \
    --token /fixtures/token >/dev/null
sleep 1
process_args=$(docker top "$leak_container" -eo args)
assert_not_contains "$process_args" "$(<"$fixture_dir/token")"
docker wait "$leak_container" >/dev/null || true
if docker logs "$leak_container" 2>&1 | grep -F "$(<"$fixture_dir/token")"; then
    fail 'Kubernetes token appeared in helper logs'
fi
docker rm "$leak_container" >/dev/null
leak_container=

printf '%s\n' 'workload-debug integration proof passed (restricted image, fixtures, kind token, deterministic report)'
