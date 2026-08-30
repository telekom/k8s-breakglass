#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail

root=$(cd -- "$(dirname "$0")/.." && pwd)
# shellcheck disable=SC1091
source "$root/tests/kind-lifecycle.sh"
image=${WORKLOAD_DEBUG_IMAGE:-ghcr.io/telekom/k8s-breakglass/utils/workload-debug:integration-$$}
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
auth_secret_created=0

fail() { echo "integration-test: $*" >&2; exit 1; }
assert_contains() { [[ "$1" == *"$2"* ]] || fail "expected '$2' in output"; }
assert_not_contains() { [[ "$1" != *"$2"* ]] || fail "unexpected secret in output"; }
run_target() { kubectl --kubeconfig "$kubeconfig" -n "$namespace" exec "$runner" -- /bin/sh -c "$*"; }

http_url="http://http-fixture.$namespace.svc.cluster.local:8080"
tls_endpoint="tls-fixture.$namespace.svc.cluster.local:8443"
dns_server="dns-fixture.$namespace.svc.cluster.local#5353"

diagnose() {
  echo 'integration-test: fixture diagnostics' >&2
  kubectl --kubeconfig "$kubeconfig" -n "$namespace" get pods -o wide >&2 || true
  kubectl --kubeconfig "$kubeconfig" -n "$namespace" get services,endpoints,endpointslices.discovery.k8s.io -o wide >&2 || true
  kubectl --kubeconfig "$kubeconfig" -n "$namespace" describe pods >&2 || true
  kubectl --kubeconfig "$kubeconfig" -n "$namespace" logs "$runner" >&2 || true
  kubectl --kubeconfig "$kubeconfig" -n "$namespace" exec "$runner" -- /bin/sh -c \
    "for url in '$http_url/get' 'https://$tls_endpoint'; do echo \"probe: \$url\"; curl --silent --show-error --max-time 3 --insecure \"\$url\" || true; done" >&2 || true
}

cleanup() {
  status=$?
  if (( KIND_LIFECYCLE_OWNED )); then
    if (( status != 0 )); then diagnose; fi
    if (( auth_secret_created )); then
      kubectl --kubeconfig "$kubeconfig" -n "$namespace" delete secret "${auth_secret_name}" \
        --ignore-not-found >/dev/null 2>&1 || status=1
    fi
    kind_lifecycle_cleanup "$kind_name" "$kubeconfig" || status=1
  fi
  if (( image_built )); then
    docker image rm "$image" >/dev/null 2>&1 || status=1
    if docker image inspect "$image" >/dev/null 2>&1; then
      echo "integration-test: built image tag still exists after cleanup: $image" >&2
      status=1
    fi
    if [ -n "${image_id:-}" ] && docker image inspect "$image_id" >/dev/null 2>&1; then
      echo "integration-test: built image ID still exists after cleanup: $image_id" >&2
      status=1
    fi
  fi
  if (( fixture_image_built )); then
    docker image rm "$fixture_image" >/dev/null 2>&1 || status=1
    if docker image inspect "$fixture_image" >/dev/null 2>&1; then
      echo "integration-test: fixture image tag still exists after cleanup: $fixture_image" >&2
      status=1
    fi
    if [ -n "${fixture_image_id:-}" ] && docker image inspect "$fixture_image_id" >/dev/null 2>&1; then
      echo "integration-test: fixture image ID still exists after cleanup: $fixture_image_id" >&2
      status=1
    fi
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
  if docker image inspect "$image" >/dev/null 2>&1; then
    fail "generated workload-debug image tag already exists: $image"
  fi
  image_built=1
  docker build --pull=false --tag "$image" "$root"
  image_id=$(docker image inspect --format '{{.Id}}' "$image") || fail "unable to record built image ID"
else
  docker image inspect "$image" >/dev/null 2>&1 || fail "WORKLOAD_DEBUG_IMAGE '$image' is not available"
fi

docker run --rm --network none --read-only --cap-drop ALL \
  --security-opt no-new-privileges --entrypoint /bin/sh "$image" -c '
    test -r /usr/share/breakglass/runbooks/upstream/workload-debug/README.md
    test -r /usr/share/breakglass/runbooks/upstream/workload-debug/RUNBOOK.md
    test -d /usr/share/breakglass/runbooks/internal
    test ! -e /usr/share/breakglass/runbooks/internal/INDEX.md
    workload-debug --help >/dev/null
  ' || fail "standalone image did not expose generic runbooks and helper behavior"

GOOS=linux CGO_ENABLED=0 go build -trimpath -o "$fixture_dir/fixture-server" "$root/tests/fixture-server.go"

# The fixture must reject an arbitrary token-file path rather than following
# an environment-controlled path outside its fixed Secret mount.
if EXPECTED_AUTH_TOKEN_FILE="$fixture_dir/../outside-token" \
  "$fixture_dir/fixture-server" --mode=http --listen=127.0.0.1:0 >/dev/null 2>&1; then
  fail "HTTP fixture accepted a token-file traversal path"
fi

cat >"$fixture_dir/Dockerfile" <<'EOF'
FROM scratch
COPY fixture-server /fixture-server
USER 65532:65532
ENTRYPOINT ["/fixture-server"]
EOF
if docker image inspect "$fixture_image" >/dev/null 2>&1; then
  fail "generated fixture image tag already exists: $fixture_image"
fi
fixture_image_built=1
docker build --pull=false --tag "$fixture_image" "$fixture_dir"
fixture_image_id=$(docker image inspect --format '{{.Id}}' "$fixture_image") || fail "unable to record fixture image ID"

kind_lifecycle_create "$kind_name" "$kind_node_image" "$kubeconfig" || \
  fail "unable to create disposable kind cluster '$kind_name'"
export KUBECONFIG="$kubeconfig"
kind load docker-image "$image" --name "$kind_name"
kind load docker-image "$fixture_image" --name "$kind_name"

kubectl create namespace "$namespace"
kubectl -n "$namespace" create serviceaccount workload-debug
kubectl -n "$namespace" create role workload-debug --verb=get --resource=configmaps
kubectl -n "$namespace" create rolebinding workload-debug --role=workload-debug --serviceaccount="$namespace:workload-debug"
kubectl -n "$namespace" create configmap fixture-config --from-literal=value=fixture-config-value
cat >"$fixture_dir/bundle.yaml" <<'EOF'
schema: breakglass.runbook/v1
intent: workload-diagnostics
version: 0.1.0
EOF
kubectl -n "$namespace" create configmap internal-runbook \
	--from-literal=INDEX.md='internal runbook fixture' \
	--from-file=bundle.yaml="$fixture_dir/bundle.yaml"

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

cat >"$fixture_dir/runner.yaml" <<EOF
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
    securityContext: {runAsUser: 65532, runAsGroup: 65532, runAsNonRoot: true, readOnlyRootFilesystem: true, allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}, seccompProfile: {type: RuntimeDefault}}
    volumeMounts:
    - {name: ca, mountPath: /fixture-ca, readOnly: true}
    - {name: ephemeral, mountPath: /workload-debug-tmp}
    - {name: internal-runbooks, mountPath: /usr/share/breakglass/runbooks/internal, readOnly: true}
  volumes:
  - {name: ca, configMap: {name: fixture-ca}}
  - name: ephemeral
    emptyDir: {medium: Memory, sizeLimit: 1Mi}
  - name: internal-runbooks
    configMap: {name: internal-runbook, defaultMode: 0444}
EOF
# Create the runner first so the HTTP fixture is pinned to this invocation's
# exact projected token, rather than independently projecting another token.
kubectl -n "$namespace" apply -f "$fixture_dir/runner.yaml"
kubectl -n "$namespace" wait --for=condition=Ready pod/$runner --timeout=120s

runner_token_file="$fixture_dir/runner-token"
(umask 077; kubectl -n "$namespace" exec "$runner" -- /bin/sh -c \
  'cat /var/run/secrets/kubernetes.io/serviceaccount/token' >"$runner_token_file")
chmod 600 "$runner_token_file"
[[ -s "$runner_token_file" ]] || fail "runner service-account token is empty"
auth_secret_name=http-fixture-auth
kubectl -n "$namespace" create secret generic "$auth_secret_name" --from-file=token="$runner_token_file"
auth_secret_created=1

cat >"$fixture_dir/fixtures.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: http-fixture
  labels: {app: http-fixture}
spec:
  automountServiceAccountToken: false
  containers:
  - name: fixture
    image: $fixture_image
    args: ["--mode=http", "--listen=:8080"]
    env:
    - name: EXPECTED_AUTH_TOKEN_FILE
      value: /var/run/secrets/workload-debug/token
    volumeMounts:
    - name: auth-token
      mountPath: /var/run/secrets/workload-debug
      readOnly: true
    securityContext: {runAsUser: 65532, runAsGroup: 65532, runAsNonRoot: true, readOnlyRootFilesystem: true, allowPrivilegeEscalation: false, capabilities: {drop: [ALL]}}
  securityContext:
    fsGroup: 65532
    fsGroupChangePolicy: OnRootMismatch
  volumes:
  - name: auth-token
    secret:
      secretName: $auth_secret_name
      defaultMode: 0440
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
EOF
# All namespaced fixtures, including the runner's ConfigMap volume, belong to
# the same namespace as the service account created above.
kubectl -n "$namespace" apply -f "$fixture_dir/fixtures.yaml"
kubectl -n "$namespace" wait --for=condition=Ready pod/http-fixture pod/tls-fixture pod/dns-fixture --timeout=120s

security=$(kubectl -n "$namespace" get pod "$runner" -o json | jq -c '.spec.containers[0].securityContext')
[[ "$(jq -r '.runAsUser' <<<"$security")" == 65532 ]] || fail "runner is not UID 65532"
[[ "$(jq -r '.readOnlyRootFilesystem' <<<"$security")" == true ]] || fail "runner is writable"
[[ "$(jq -r '.allowPrivilegeEscalation' <<<"$security")" == false ]] || fail "privilege escalation is enabled"
[[ "$(jq -c '.capabilities' <<<"$security")" == '{"drop":["ALL"]}' ]] || fail "runner capabilities are not dropped"
[[ "$(jq -r '.seccompProfile.type' <<<"$security")" == RuntimeDefault ]] || fail "runner does not use RuntimeDefault seccomp"
if run_target "touch /runtime-write" >/dev/null 2>&1; then fail "read-only runner allowed a filesystem write"; fi
internal_notice=$(run_target "WORKLOAD_DEBUG_MOTD=0 /usr/local/bin/workload-debug-entrypoint /bin/true")
assert_contains "$internal_notice" '/usr/share/breakglass/runbooks/internal/INDEX.md'
bundle_metadata=$(run_target "cat /usr/share/breakglass/runbooks/internal/bundle.yaml")
assert_contains "$bundle_metadata" 'schema: breakglass.runbook/v1'
if run_target "printf modified >>/usr/share/breakglass/runbooks/internal/bundle.yaml" >/dev/null 2>&1; then
  fail "mounted internal runbook bundle was writable"
fi

http_security=$(kubectl -n "$namespace" get pod http-fixture -o json)
[[ "$(jq -r '.spec.automountServiceAccountToken' <<<"$http_security")" == false ]] || fail "HTTP fixture has a service-account token"
[[ "$(jq -r '.spec.securityContext.fsGroup' <<<"$http_security")" == 65532 ]] || fail "HTTP fixture Secret group is not restricted"
[[ "$(jq -r '.spec.securityContext.fsGroupChangePolicy' <<<"$http_security")" == OnRootMismatch ]] || fail "HTTP fixture Secret group policy is not bounded"
[[ "$(jq -r '.spec.containers[0].securityContext.runAsUser' <<<"$http_security")" == 65532 ]] || fail "HTTP fixture is not UID 65532"
[[ "$(jq -r '.spec.containers[0].securityContext.readOnlyRootFilesystem' <<<"$http_security")" == true ]] || fail "HTTP fixture is writable"
[[ "$(jq -r '.spec.containers[0].volumeMounts[] | select(.name == "auth-token") | .readOnly' <<<"$http_security")" == true ]] || fail "HTTP fixture Secret mount is writable"
[[ "$(jq -r '.spec.volumes[] | select(.name == "auth-token") | .secret.defaultMode' <<<"$http_security")" == 288 ]] || fail "HTTP fixture Secret mode is not 0440"

dns_ready=0
dns_output=
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
  if dns_output=$(run_target "debug-dns --server '$dns_server' '$dns_fixture_name'" 2>/dev/null); then
    dns_ready=1
    break
  fi
  sleep 1
done
[[ "$dns_ready" -eq 1 ]] || fail "DNS fixture did not become reachable from the runner"
assert_contains "$dns_output" "203.0.113.7"
run_target "debug-tls --ca /fixture-ca/ca.crt '$tls_endpoint'" >/dev/null
if run_target "debug-tls --ca /fixture-ca/wrong.crt '$tls_endpoint'" >/dev/null 2>&1; then fail "wrong TLS CA was accepted"; fi
if run_target "debug-tls --timeout 1 'tls-fixture.$namespace.svc.cluster.local:1'" >/dev/null 2>&1; then fail "unavailable TLS endpoint was accepted"; fi

http_ready=0
for _ in 1 2 3 4 5 6 7 8 9 10 11 12 13 14 15 16 17 18 19 20 21 22 23 24 25 26 27 28 29 30; do
  if run_target "curl --silent --show-error --fail --max-time 2 '$http_url/get'" >/dev/null 2>&1; then
    http_ready=1
    break
  fi
  sleep 1
done
[[ "$http_ready" -eq 1 ]] || fail "HTTP fixture did not become reachable from the runner"
http_output=
http_attempt=0
while [ "$http_attempt" -lt 5 ]; do
  if http_output=$(run_target "debug-http --method GET --timeout 3 '$http_url/get'"); then break; fi
  http_attempt=$((http_attempt + 1))
  sleep 1
done
[[ "$http_attempt" -lt 5 ]] || fail "HTTP helper could not read the reachable fixture"
assert_contains "$http_output" "fixture-get"
run_target "debug-http --method HEAD '$http_url/head'" >/dev/null
run_target "debug-http --method OPTIONS '$http_url/get'" >/dev/null
redirect=$(run_target "debug-http --method GET '$http_url/redirect'")
assert_contains "$redirect" "HTTP/1.1 302"
if run_target "WORKLOAD_DEBUG_MAX_BYTES=64 debug-http --method GET '$http_url/large'" >/dev/null 2>&1; then fail "large response exceeded max-bytes"; fi
if run_target "WORKLOAD_DEBUG_MAX_BYTES=64 debug-http --method GET '$http_url/chunked'" >/dev/null 2>&1; then fail "chunked response exceeded max-bytes"; fi
oversized_headers_output="$fixture_dir/oversized-headers.out"
if run_target "WORKLOAD_DEBUG_MAX_BYTES=64 debug-http --method GET '$http_url/oversized-headers'" >"$oversized_headers_output" 2>/dev/null; then
  fail "oversized response headers were accepted"
fi
[[ ! -s "$oversized_headers_output" ]] || fail "oversized response headers were emitted"
if run_target "debug-http --method GET --timeout 1 '$http_url/slow'" >/dev/null 2>&1; then fail "slow response exceeded timeout"; fi
if run_target "debug-http --method POST '$http_url/get'" >/dev/null 2>&1; then fail "unsupported method was accepted"; fi
if run_target "debug-http --method GET '$http_url/missing'" >/dev/null 2>&1; then fail "404 response was accepted"; fi
if run_target "debug-http --method GET '$http_url/unknown'" >/dev/null 2>&1; then fail "unknown fixture path was accepted"; fi

kube_path="/api/v1/namespaces/$namespace/configmaps/fixture-config"
token=$(<"$runner_token_file")
kube_output=$(run_target "debug-kube-api '$kube_path'")
assert_contains "$kube_output" "fixture-config-value"
if run_target "debug-kube-api '/api/v1/namespaces/$namespace/secrets/$auth_secret_name'" >/dev/null 2>&1; then
  fail "runner service account can read the HTTP fixture Secret"
fi

# An explicitly overridden server must not receive the projected in-cluster
# token. The authenticated fixture returns 401 when no Authorization header is
# sent, which proves the request reached it without implicit credentials.
kube_no_auth_output=
if kube_no_auth_output=$(run_target "debug-kube-api --server '$http_url' /auth"); then
  fail "debug-kube-api sent an implicit token to an overridden server"
fi
assert_contains "$kube_no_auth_output" "authorization-required"

# The fixture validates the exact projected service-account token, rather than
# merely checking that some Authorization header exists. The successful body
# proves that debug-kube-api supplied the real bearer credential.
kube_auth_output=$(run_target "debug-kube-api --server '$http_url' --token /var/run/secrets/kubernetes.io/serviceaccount/token /auth")
assert_contains "$kube_auth_output" "authenticated"
assert_not_contains "$kube_auth_output" "$token"

# The token-authenticated branch must use the same bounded streaming path as
# unauthenticated requests. The fixture requires an Authorization header and
# deliberately sends an unknown-length chunked response, so a direct curl
# invocation would both authenticate successfully and exceed the limit.
kube_chunked_output="$fixture_dir/kube-chunked.out"
kube_chunked_error="$fixture_dir/kube-chunked.err"
if kubectl --kubeconfig "$kubeconfig" -n "$namespace" exec "$runner" -- /bin/sh -c \
  "WORKLOAD_DEBUG_MAX_BYTES=64 debug-kube-api --server '$http_url' --token /var/run/secrets/kubernetes.io/serviceaccount/token /auth-chunked" \
  >"$kube_chunked_output" 2>"$kube_chunked_error"; then
  fail "token-authenticated chunked response exceeded max-bytes"
fi
chunked_output_bytes=$(wc -c <"$kube_chunked_output")
if [[ "$chunked_output_bytes" -le 64 || "$chunked_output_bytes" -ge 1024 ]]; then
  fail "token-authenticated chunked output was not bounded: $chunked_output_bytes bytes"
fi
assert_contains "$(cat "$kube_chunked_output")" "HTTP/1.1 200 OK"

kube_oversized_output="$fixture_dir/kube-oversized-headers.out"
if kubectl --kubeconfig "$kubeconfig" -n "$namespace" exec "$runner" -- /bin/sh -c \
  "WORKLOAD_DEBUG_MAX_BYTES=64 debug-kube-api --server '$http_url' --token /var/run/secrets/kubernetes.io/serviceaccount/token /auth-oversized-headers" \
  >"$kube_oversized_output" 2>/dev/null; then
  fail "token-authenticated oversized response headers were accepted"
fi
[[ ! -s "$kube_oversized_output" ]] || fail "token-authenticated oversized response headers were emitted"

report_a=$(run_target "debug-report --json --dns '$dns_fixture_name' --dns-server '$dns_server' --tls '$tls_endpoint' --tls-ca /fixture-ca/ca.crt --http '$http_url/get' --kube '$kube_path'")
report_b=$(run_target "debug-report --json --dns '$dns_fixture_name' --dns-server '$dns_server' --tls '$tls_endpoint' --tls-ca /fixture-ca/ca.crt --http '$http_url/get' --kube '$kube_path'")
[[ "$report_a" == "$report_b" ]] || fail "readiness report is not deterministic"
[[ "$(jq -r '.status' <<<"$report_a")" == ready ]] || fail "successful report is not ready"
[[ "$(jq -r '.checks_failed' <<<"$report_a")" == 0 ]] || fail "successful report has failures"
[[ "$(jq '.checks | length' <<<"$report_a")" == 4 ]] || fail "report check count changed"
[[ "$(jq '[.checks[].success] | all' <<<"$report_a")" == true ]] || fail "report has unsuccessful check"
failed_report=$(run_target "debug-report --json --http '$http_url/missing'")
[[ "$(jq -r '.status' <<<"$failed_report")" == not-ready ]] || fail "failed report is not not-ready"
[[ "$(jq -r '.checks_failed' <<<"$failed_report")" == 1 ]] || fail "failed report count is wrong"

secret_probe=$(kubectl -n "$namespace" exec "$runner" -- /bin/sh -c "TMPDIR=/workload-debug-tmp WORKLOAD_DEBUG_TIMEOUT=5 debug-kube-api --server '$http_url' --token /var/run/secrets/kubernetes.io/serviceaccount/token /auth-chunked >/dev/null 2>/workload-debug-tmp/auth-stderr & p=\$!; observed=0; for _ in 1 2 3 4 5 6 7 8 9 10; do if kill -0 \$p 2>/dev/null; then observed=1; tr '\\000' ' ' < /proc/\$p/cmdline; fi; sleep .2; done; wait \$p || { echo 'authenticated helper failed' >&2; exit 1; }; grep -F 'response' /workload-debug-tmp/auth-stderr >/dev/null && { echo 'authenticated helper emitted an unexpected error' >&2; exit 1; } || true; rm -f /workload-debug-tmp/auth-stderr; [ \$observed -eq 1 ] || { echo 'could not observe helper process' >&2; exit 1; }; echo helper-executed")
assert_contains "$secret_probe" 'helper-executed'
token=$(kubectl -n "$namespace" exec "$runner" -- /bin/sh -c 'cat /var/run/secrets/kubernetes.io/serviceaccount/token')
secret_probe=$(kubectl -n "$namespace" exec "$runner" -- /bin/sh -c "WORKLOAD_DEBUG_TIMEOUT=5 debug-kube-api --server '$http_url/slow' >/dev/null 2>&1 & p=\$!; observed=0; for _ in 1 2 3 4 5 6 7 8 9 10; do if kill -0 \$p 2>/dev/null; then observed=1; tr '\\000' ' ' < /proc/\$p/cmdline; fi; sleep .2; done; wait \$p; [ \$observed -eq 1 ] || { echo 'could not observe helper process' >&2; exit 1; }")
assert_not_contains "$secret_probe" "$token"
logs=$(kubectl -n "$namespace" logs "$runner")
assert_not_contains "$logs" "$token"
echo "workload-debug integration proof passed"
