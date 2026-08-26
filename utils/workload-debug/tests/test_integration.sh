#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail

root=$(cd -- "$(dirname "$0")/.." && pwd)
image=${WORKLOAD_DEBUG_IMAGE:-workload-debug:integration-$$}
fixture_image=workload-debug-fixture:integration-$$
fixture_dir=$(mktemp -d "${TMPDIR:-/tmp}/workload-debug.XXXXXX")
kind_name=workload-debug-$$
kubeconfig="$fixture_dir/kubeconfig"
namespace=workload-debug-fixture
runner=workload-debug-runner
dns_fixture_name=fixture.workload-debug.test
kind_node_image=${KIND_NODE_IMAGE:-kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5}
image_built=0
fixture_image_built=0
kind_created=0

fail() { echo "integration-test: $*" >&2; exit 1; }
assert_contains() { [[ "$1" == *"$2"* ]] || fail "expected '$2' in output"; }
assert_not_contains() { [[ "$1" != *"$2"* ]] || fail "unexpected secret in output"; }
run_target() { kubectl --kubeconfig "$kubeconfig" -n "$namespace" exec "$runner" -- /bin/sh -c "$*"; }

cleanup() {
  status=$?
  if (( kind_created )); then
    kind delete cluster --name "$kind_name" --kubeconfig "$kubeconfig" >/dev/null 2>&1 || true
    if kind get clusters 2>/dev/null | grep -Fxq "$kind_name"; then
      echo "integration-test: kind cluster still exists after cleanup" >&2
      status=1
    fi
  fi
  if (( image_built )); then
    docker image rm "$image" >/dev/null 2>&1 || true
  fi
  if (( fixture_image_built )); then
    docker image rm "$fixture_image" >/dev/null 2>&1 || true
  fi
  rm -rf -- "$fixture_dir"
  [[ ! -e "$fixture_dir" ]] || status=1
  exit "$status"
}
trap cleanup EXIT

for command in docker kind kubectl go openssl jq; do
  command -v "$command" >/dev/null 2>&1 || fail "required tool '$command' is unavailable; install it (integration proof does not skip)"
done
docker info >/dev/null 2>&1 || fail "Docker daemon is unavailable"

if [[ -z "${WORKLOAD_DEBUG_IMAGE:-}" ]]; then
  docker build --pull=false --tag "$image" "$root"
  image_built=1
else
  docker image inspect "$image" >/dev/null 2>&1 || fail "WORKLOAD_DEBUG_IMAGE '$image' is not available"
fi

GOOS=linux CGO_ENABLED=0 go build -trimpath -o "$fixture_dir/fixture-server" "$root/tests/fixture-server.go"
cat >"$fixture_dir/Dockerfile" <<'EOF'
FROM scratch
COPY fixture-server /fixture-server
USER 65532:65532
ENTRYPOINT ["/fixture-server"]
EOF
docker build --pull=false --tag "$fixture_image" "$fixture_dir"
fixture_image_built=1

kind_created=1
kind create cluster --name "$kind_name" --image "$kind_node_image" --kubeconfig "$kubeconfig" --wait 120s
export KUBECONFIG="$kubeconfig"
kind load docker-image "$image" --name "$kind_name"
kind load docker-image "$fixture_image" --name "$kind_name"

kubectl create namespace "$namespace"
kubectl -n "$namespace" create serviceaccount workload-debug
kubectl -n "$namespace" create role workload-debug --verb=get --resource=configmaps
kubectl -n "$namespace" create rolebinding workload-debug --role=workload-debug --serviceaccount="$namespace:workload-debug"
kubectl -n "$namespace" create configmap fixture-config --from-literal=value=fixture-config-value

openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=workload-debug-fixture" \
  -keyout "$fixture_dir/ca.key" -out "$fixture_dir/ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj "/CN=tls-fixture" \
  -keyout "$fixture_dir/server.key" -out "$fixture_dir/server.csr" >/dev/null 2>&1
openssl x509 -req -days 1 -in "$fixture_dir/server.csr" -CA "$fixture_dir/ca.crt" -CAkey "$fixture_dir/ca.key" \
  -CAcreateserial -out "$fixture_dir/server.crt" -extfile <(printf 'subjectAltName=DNS:tls-fixture.%s.svc.cluster.local\n' "$namespace") >/dev/null 2>&1
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj "/CN=wrong-ca" \
  -keyout "$fixture_dir/wrong.key" -out "$fixture_dir/wrong.crt" >/dev/null 2>&1
kubectl -n "$namespace" create secret generic tls-fixture --from-file=server.crt="$fixture_dir/server.crt" --from-file=server.key="$fixture_dir/server.key"
kubectl -n "$namespace" create configmap fixture-ca --from-file=ca.crt="$fixture_dir/ca.crt" --from-file=wrong.crt="$fixture_dir/wrong.crt"

cat >"$fixture_dir/fixtures.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: http-fixture
  labels: {app: http-fixture}
spec:
  containers:
  - name: fixture
    image: $fixture_image
    args: ["--mode=http", "--listen=:8080"]
    securityContext: {runAsUser: 65532, runAsGroup: 65532, runAsNonRoot: true, readOnlyRootFilesystem: true, allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}}
---
apiVersion: v1
kind: Service
metadata:
  name: http-fixture
spec:
  selector: {app: http-fixture}
  ports: [{name: http, port: 8080, targetPort: 8080}]
---
apiVersion: v1
kind: Pod
metadata:
  name: tls-fixture
  labels: {app: tls-fixture}
spec:
  containers:
  - name: fixture
    image: $fixture_image
    args: ["--mode=tls", "--listen=:8443", "--cert=/tls/server.crt", "--key=/tls/server.key"]
    volumeMounts: [{name: tls, mountPath: /tls, readOnly: true}]
    securityContext: {runAsUser: 65532, runAsGroup: 65532, runAsNonRoot: true, readOnlyRootFilesystem: true, allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}}
  volumes: [{name: tls, secret: {secretName: tls-fixture}}]
---
apiVersion: v1
kind: Service
metadata:
  name: tls-fixture
spec:
  selector: {app: tls-fixture}
  ports: [{name: https, port: 8443, targetPort: 8443}]
---
apiVersion: v1
kind: Pod
metadata:
  name: dns-fixture
  labels: {app: dns-fixture}
spec:
  containers:
  - name: fixture
    image: $fixture_image
    args: ["--mode=dns", "--listen=:5353", "--name=$dns_fixture_name", "--address=203.0.113.7"]
    securityContext: {runAsUser: 65532, runAsGroup: 65532, runAsNonRoot: true, readOnlyRootFilesystem: true, allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}}
---
apiVersion: v1
kind: Service
metadata:
  name: dns-fixture
spec:
  selector: {app: dns-fixture}
  ports: [{name: dns, port: 5353, targetPort: 5353, protocol: UDP}]
---
apiVersion: v1
kind: Pod
metadata:
  name: $runner
spec:
  serviceAccountName: workload-debug
  automountServiceAccountToken: true
  containers:
  - name: workload-debug
    image: $image
    command: ["/bin/sh", "-c", "exec sleep 600"]
    securityContext: {runAsUser: 65532, runAsGroup: 65532, runAsNonRoot: true, readOnlyRootFilesystem: true, allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}}
    volumeMounts: [{name: ca, mountPath: /fixture-ca, readOnly: true}]
  volumes: [{name: ca, configMap: {name: fixture-ca}}]
EOF
kubectl apply -f "$fixture_dir/fixtures.yaml"
kubectl -n "$namespace" wait --for=condition=Ready pod/http-fixture pod/tls-fixture pod/dns-fixture pod/$runner --timeout=120s

security=$(kubectl -n "$namespace" get pod "$runner" -o json | jq -c '.spec.containers[0].securityContext')
[[ "$(jq -r '.runAsUser' <<<"$security")" == 65532 ]] || fail "runner is not UID 65532"
[[ "$(jq -r '.readOnlyRootFilesystem' <<<"$security")" == true ]] || fail "runner is writable"
[[ "$(jq -r '.allowPrivilegeEscalation' <<<"$security")" == false ]] || fail "privilege escalation is enabled"
[[ "$(jq -c '.capabilities' <<<"$security")" == '{"drop":["ALL"]}' ]] || fail "runner capabilities are not dropped"
if run_target "touch /runtime-write" >/dev/null 2>&1; then fail "read-only runner allowed a filesystem write"; fi

http_url="http://http-fixture.$namespace.svc.cluster.local:8080"
tls_url="https://tls-fixture.$namespace.svc.cluster.local:8443"
dns_server="dns-fixture.$namespace.svc.cluster.local#5353"
assert_contains "$(run_target "debug-dns --server '$dns_server' '$dns_fixture_name'")" "203.0.113.7"
run_target "debug-tls --ca /fixture-ca/ca.crt '$tls_url'" >/dev/null
if run_target "debug-tls --ca /fixture-ca/wrong.crt '$tls_url'" >/dev/null 2>&1; then fail "wrong TLS CA was accepted"; fi
if run_target "debug-tls --timeout 1 'https://tls-fixture.$namespace.svc.cluster.local:1'" >/dev/null 2>&1; then fail "unavailable TLS endpoint was accepted"; fi

assert_contains "$(run_target "debug-http --method GET '$http_url/get'")" "fixture-get"
run_target "debug-http --method HEAD '$http_url/head'" >/dev/null
run_target "debug-http --method OPTIONS '$http_url/get'" >/dev/null
redirect=$(run_target "debug-http --method GET '$http_url/redirect'")
assert_contains "$redirect" "HTTP/1.1 302"
if run_target "WORKLOAD_DEBUG_MAX_BYTES=64 debug-http --method GET '$http_url/large'" >/dev/null 2>&1; then fail "large response exceeded max-bytes"; fi
if run_target "debug-http --method GET --timeout 1 '$http_url/slow'" >/dev/null 2>&1; then fail "slow response exceeded timeout"; fi
if run_target "debug-http --method POST '$http_url/get'" >/dev/null 2>&1; then fail "unsupported method was accepted"; fi
if run_target "debug-http --method GET '$http_url/missing'" >/dev/null 2>&1; then fail "404 response was accepted"; fi

kube_path="/api/v1/namespaces/$namespace/configmaps/fixture-config"
kube_output=$(run_target "debug-kube-api '$kube_path'")
assert_contains "$kube_output" "fixture-config-value"

report_a=$(run_target "debug-report --json --dns '$dns_fixture_name' --dns-server '$dns_server' --tls '$tls_url' --tls-ca /fixture-ca/ca.crt --http '$http_url/get' --kube '$kube_path'")
report_b=$(run_target "debug-report --json --dns '$dns_fixture_name' --dns-server '$dns_server' --tls '$tls_url' --tls-ca /fixture-ca/ca.crt --http '$http_url/get' --kube '$kube_path'")
[[ "$report_a" == "$report_b" ]] || fail "readiness report is not deterministic"
[[ "$(jq -r '.status' <<<"$report_a")" == ready ]] || fail "successful report is not ready"
[[ "$(jq -r '.checks_failed' <<<"$report_a")" == 0 ]] || fail "successful report has failures"
[[ "$(jq '.checks | length' <<<"$report_a")" == 4 ]] || fail "report check count changed"
[[ "$(jq '[.checks[].success] | all' <<<"$report_a")" == true ]] || fail "report has unsuccessful check"
failed_report=$(run_target "debug-report --json --http '$http_url/missing'")
[[ "$(jq -r '.status' <<<"$failed_report")" == not-ready ]] || fail "failed report is not not-ready"
[[ "$(jq -r '.checks_failed' <<<"$failed_report")" == 1 ]] || fail "failed report count is wrong"

token=$(kubectl -n "$namespace" exec "$runner" -- /bin/sh -c 'cat /var/run/secrets/kubernetes.io/serviceaccount/token')
secret_probe=$(kubectl -n "$namespace" exec "$runner" -- /bin/sh -c "debug-kube-api --server '$http_url/slow' --timeout 5 >/dev/null 2>&1 & p=\$!; observed=0; for _ in 1 2 3 4 5 6 7 8 9 10; do if kill -0 \$p 2>/dev/null; then observed=1; tr '\\000' ' ' < /proc/\$p/cmdline; fi; sleep .2; done; wait \$p; [ \$observed -eq 1 ] || { echo 'could not observe helper process' >&2; exit 1; }")
assert_not_contains "$secret_probe" "$token"
logs=$(kubectl -n "$namespace" logs "$runner")
assert_not_contains "$logs" "$token"
echo "workload-debug integration proof passed"
