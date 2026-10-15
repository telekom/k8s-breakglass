#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

cd "$(dirname "$0")/.."
for tool in docker kind kubectl go curl; do
	command -v "$tool" >/dev/null || { printf 'Required tool missing: %s\n' "$tool" >&2; exit 1; }
done
docker info >/dev/null
proof_dir=".hotfix-controller-proof-$$"
cluster="hotfix-proof-$$"
registry="hotfix-registry-$$"
node="$cluster-control-plane"
export KIND_BIN=kind DOCKER_BIN=docker KIND_CLUSTER_NAME="$cluster"
KIND_CLUSTER_CREATED=false
# shellcheck source=kind-ownership.sh
# shellcheck disable=SC1091
. hack/kind-ownership.sh
# shellcheck source=docker-resource-ownership.sh
# shellcheck disable=SC1091
. hack/docker-resource-ownership.sh
# shellcheck source=docker-image-ownership.sh
# shellcheck disable=SC1091
. hack/docker-image-ownership.sh
[[ ! -e "$proof_dir" ]] || { echo "Proof directory collision" >&2; exit 1; }
if kind get clusters | grep -Fx "$cluster" >/dev/null; then
	echo "Proof cluster collision" >&2
	exit 1
fi
if docker container inspect "$registry" >/dev/null 2>&1; then
	echo "Proof registry collision" >&2
	exit 1
fi
mkdir "$proof_dir"
registry_id=""
image=""
image_id=""
scheduler_ref=""
scheduler_image_id=""
scheduler_preexisting=""
scheduler_tag=""
cleanup() {
	status=$?
	trap - EXIT
	if [[ "$status" -ne 0 && "$KIND_CLUSTER_CREATED" == true ]]; then
		docker stats --no-stream "$KIND_CLUSTER_OWNER_IDS" || true
		kubectl --kubeconfig "$proof_dir/kubeconfig" --request-timeout=10s get pods,jobs,leases,nodes --all-namespaces -o wide || true
		docker exec "$KIND_CLUSTER_OWNER_IDS" crictl logs "$(docker exec "$KIND_CLUSTER_OWNER_IDS" crictl ps --name kube-apiserver -q | head -1)" 2>&1 | tail -100 || true
		docker exec "$KIND_CLUSTER_OWNER_IDS" crictl logs "$(docker exec "$KIND_CLUSTER_OWNER_IDS" crictl ps --name kube-scheduler -q | head -1)" 2>&1 | tail -100 || true
	fi
	if [[ "$KIND_CLUSTER_CREATED" == true ]]; then
		for _attempt in 1 2 3; do
			if kind_cleanup_owned_cluster; then
				break
			fi
			sleep 1
		done
		[[ "$KIND_CLUSTER_CREATED" == false ]] || status=1
	fi
	if [[ -z "$registry_id" && -f "$proof_dir/registry.cid" ]]; then
		registry_id=$(cat "$proof_dir/registry.cid")
	fi
	if [[ -n "$registry_id" ]]; then
		if [[ "$registry_id" =~ ^[0-9a-f]{64}$ ]]; then
			docker_remove_resource_with_volumes docker container "$registry_id" >/dev/null || status=1
		else
			status=1
		fi
	fi
	if [[ -z "$image_id" && -f "$proof_dir/image.id" ]]; then
		image_id=$(cat "$proof_dir/image.id")
	fi
	if [[ -n "$image_id" && -n "$image" ]]; then
		docker_remove_image_if_id docker "$image" "$image_id" || status=1
	fi
	# Remove only what this proof created on the host.
	if [[ -n "$scheduler_tag" ]]; then
		docker image rm "$scheduler_tag" >/dev/null 2>&1 || true
	fi
	if [[ -n "$scheduler_image_id" && -z "$scheduler_preexisting" ]]; then
		docker_remove_image_if_id docker "$scheduler_ref" "$scheduler_image_id" || status=1
	fi
	rm -rf -- "$proof_dir"
	exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir "$proof_dir/go-work"
GOTMPDIR="$PWD/$proof_dir/go-work" go test -c ./pkg/breakglass/debug -o "$proof_dir/hotfix.test"

registry_id=$(docker run --detach --cidfile "$proof_dir/registry.cid" --name "$registry" --publish 127.0.0.1::5000 registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e)
port=$(docker port "$registry_id" 5000/tcp | sed 's/^127\.0\.0\.1://')
[[ "$port" =~ ^[0-9]+$ ]] || { echo "Invalid proof registry port" >&2; exit 1; }
curl --fail --silent --show-error --retry 10 --retry-delay 1 --retry-connrefused "http://127.0.0.1:$port/v2/" >/dev/null
image="localhost:$port/node-maintenance:hotfix-proof"
# Pass a build proxy only when the host uses one; host networking lets the
# build reach it (the default build network may not route to a host proxy).
proxy_args=()
for variable in http_proxy https_proxy no_proxy HTTP_PROXY HTTPS_PROXY NO_PROXY; do
	[[ -z "${!variable:-}" ]] || proxy_args+=(--build-arg "$variable=${!variable}")
done
docker build --quiet --network host ${proxy_args[@]+"${proxy_args[@]}"} --iidfile "$proof_dir/image.id" --tag "$image" --file utils/node-maintenance/Dockerfile utils/node-maintenance
image_id=$(docker image inspect "$image" --format '{{.Id}}')
docker push "$image"
digest=$(docker image inspect "$image" --format '{{index .RepoDigests 0}}' | sed 's/.*@//')
[[ "$digest" =~ ^sha256:[a-f0-9]{64}$ ]] || { echo "Missing immutable helper digest" >&2; exit 1; }
cat > "$proof_dir/kind.yaml" <<EOF
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
containerdConfigPatches:
  - |-
    [plugins."io.containerd.cri.v1.images".registry]
      config_path = "/etc/containerd/certs.d"
nodes:
  - role: control-plane
EOF
# The node reaches the proof registry directly; never through a host proxy.
env -u HTTP_PROXY -u HTTPS_PROXY -u http_proxy -u https_proxy \
	kind create cluster --name "$cluster" --config "$proof_dir/kind.yaml" \
	--kubeconfig "$proof_dir/kubeconfig" --wait 120s \
	--image "${KIND_NODE_IMAGE:-kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5}"
kind_capture_owned_cluster_identity
KIND_CLUSTER_CREATED=true
node_id="$KIND_CLUSTER_OWNER_IDS"
[[ "$node_id" =~ ^[0-9a-f]{64}$ ]] || { echo "Expected exactly one owned Kind node" >&2; exit 1; }
# Push through the published port before the registry joins the kind network:
# afterwards the loopback port forward refuses connections on some hosts.
# The node's /tmp is a tmpfs that docker cp cannot read, so export to /root.
# Serve the node's own kube-scheduler image from the proof registry by digest,
# so the static-pod-image payload swaps to a pinned reference of the same image.
scheduler_ref=$(docker exec "$node_id" sed -n 's/^ *image: *//p' /etc/kubernetes/manifests/kube-scheduler.yaml)
[[ "$scheduler_ref" =~ ^registry\.k8s\.io/kube-scheduler: ]] || { echo "Unexpected kube-scheduler image: $scheduler_ref" >&2; exit 1; }
docker exec "$node_id" ctr -n k8s.io images export /root/hotfix-scheduler.tar "$scheduler_ref"
docker cp "$node_id:/root/hotfix-scheduler.tar" "$proof_dir/scheduler.tar"
docker exec "$node_id" rm -f /root/hotfix-scheduler.tar
scheduler_preexisting=$(docker image inspect --format '{{.Id}}' "$scheduler_ref" 2>/dev/null || true)
docker load --quiet --input "$proof_dir/scheduler.tar" >/dev/null
scheduler_image_id=$(docker image inspect --format '{{.Id}}' "$scheduler_ref")
scheduler_tag="127.0.0.1:$port/kube-scheduler:hotfix-proof"
docker tag "$scheduler_ref" "$scheduler_tag"
docker push --quiet "$scheduler_tag" >/dev/null
scheduler_digest=$(docker image inspect "$scheduler_tag" --format '{{range .RepoDigests}}{{println .}}{{end}}' \
	| grep -F "127.0.0.1:$port/kube-scheduler@" | sed 's/.*@//')
[[ "$scheduler_digest" =~ ^sha256:[a-f0-9]{64}$ ]] || { echo "Missing kube-scheduler digest" >&2; exit 1; }
docker network connect kind "$registry_id"
docker exec "$node_id" mkdir -p "/etc/containerd/certs.d/$registry:5000"
printf 'server = "http://%s:5000"\n[host."http://%s:5000"]\n  capabilities = ["pull", "resolve"]\n' "$registry" "$registry" \
	| docker exec --interactive "$node_id" sh -c "cat > '/etc/containerd/certs.d/$registry:5000/hosts.toml'"
kubectl --kubeconfig "$proof_dir/kubeconfig" apply \
	-f config/crd/bases/breakglass.t-caas.telekom.com_clusterconfigs.yaml \
	-f config/crd/bases/breakglass.t-caas.telekom.com_debugsessions.yaml \
	-f config/crd/bases/breakglass.t-caas.telekom.com_debugsessiontemplates.yaml \
	-f config/crd/bases/breakglass.t-caas.telekom.com_debugsessionclusterbindings.yaml \
	-f config/crd/bases/breakglass.t-caas.telekom.com_debugpodtemplates.yaml \
	-f config/crd/bases/breakglass.t-caas.telekom.com_hotfixrecords.yaml
# kubectl wait --for=condition fails instead of waiting while a fresh object
# has no status.conditions yet, so retry it within the same 60s bound.
established=false
for _attempt in {1..12}; do
	if kubectl --kubeconfig "$proof_dir/kubeconfig" wait --for=condition=Established --timeout=5s \
		crd/clusterconfigs.breakglass.t-caas.telekom.com \
		crd/debugpodtemplates.breakglass.t-caas.telekom.com \
		crd/debugsessionclusterbindings.breakglass.t-caas.telekom.com \
		crd/debugsessions.breakglass.t-caas.telekom.com \
		crd/debugsessiontemplates.breakglass.t-caas.telekom.com \
		crd/hotfixrecords.breakglass.t-caas.telekom.com; then
		established=true
		break
	fi
	sleep 1
done
[[ "$established" == true ]] || { echo "Proof CRDs did not become Established" >&2; exit 1; }
kubectl --kubeconfig "$proof_dir/kubeconfig" rollout status --timeout=120s \
	--namespace kube-system deployment/coredns
ready=false
for _attempt in {1..12}; do
	if kubectl --kubeconfig "$proof_dir/kubeconfig" --request-timeout=10s get --raw='/readyz'; then
		ready=true
		break
	fi
	sleep 1
done
[[ "$ready" == true ]] || { echo "Proof API server did not become ready" >&2; exit 1; }
kubectl --kubeconfig "$proof_dir/kubeconfig" create namespace breakglass-node-maintenance
kubectl --kubeconfig "$proof_dir/kubeconfig" label namespace breakglass-node-maintenance \
	pod-security.kubernetes.io/enforce=privileged

# Disposable node file for the node-file payload.
docker exec "$node_id" sh -eu -c '
	mkdir -p /etc/hotfix-proof
	printf "mode = old\nkeep = yes\n" > /etc/hotfix-proof/app.conf
'

HOTFIX_KIND_KUBECONFIG="$PWD/$proof_dir/kubeconfig" \
HOTFIX_KIND_NODE="$node" \
HOTFIX_KIND_CONTAINER_ID="$node_id" \
HOTFIX_KIND_IMAGE="$registry:5000/node-maintenance@$digest" \
HOTFIX_KIND_SCHEDULER_IMAGE="$registry:5000/kube-scheduler@$scheduler_digest" \
	"$proof_dir/hotfix.test" -test.run '^TestHotfixKind$' -test.count=1 -test.timeout=20m -test.v
