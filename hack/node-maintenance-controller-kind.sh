#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail

cd "$(dirname "$0")/.."
for tool in docker kind kubectl go curl; do
	command -v "$tool" >/dev/null || { printf 'Required tool missing: %s\n' "$tool" >&2; exit 1; }
done
docker info >/dev/null
proof_dir=".node-maintenance-controller-proof-$$"
cluster="node-maintenance-proof-$$"
registry="node-maintenance-registry-$$"
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
cleanup() {
	status=$?
	trap - EXIT
	if [[ "$status" -ne 0 && "$KIND_CLUSTER_CREATED" == true ]]; then
		docker stats --no-stream "$KIND_CLUSTER_OWNER_IDS" || true
		kubectl --kubeconfig "$proof_dir/kubeconfig" --request-timeout=10s get pods,jobs,leases,nodes --all-namespaces -o wide || true
		docker exec "$KIND_CLUSTER_OWNER_IDS" crictl logs "$(docker exec "$KIND_CLUSTER_OWNER_IDS" crictl ps --name kube-apiserver -q | head -1)" 2>&1 | tail -100 || true
		docker exec "$KIND_CLUSTER_OWNER_IDS" crictl logs "$(docker exec "$KIND_CLUSTER_OWNER_IDS" crictl ps --name etcd -q | head -1)" 2>&1 | tail -100 || true
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
	rm -rf -- "$proof_dir"
	exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir "$proof_dir/go-work"
GOTMPDIR="$PWD/$proof_dir/go-work" go test -c ./pkg/breakglass/debug -o "$proof_dir/maintenance.test"

registry_id=$(docker run --detach --cidfile "$proof_dir/registry.cid" --name "$registry" --publish 127.0.0.1::5000 registry:3.0.0@sha256:6c5666b861f3505b116bb9aa9b25175e71210414bd010d92035ff64018f9457e)
port=$(docker port "$registry_id" 5000/tcp | sed 's/^127\.0\.0\.1://')
[[ "$port" =~ ^[0-9]+$ ]] || { echo "Invalid proof registry port" >&2; exit 1; }
curl --fail --silent --show-error --retry 10 --retry-delay 1 --retry-connrefused "http://127.0.0.1:$port/v2/" >/dev/null
image="localhost:$port/node-maintenance:controller-proof"
docker buildx build --load --quiet --iidfile "$proof_dir/image.id" --tag "$image" --file utils/node-maintenance/Dockerfile utils/node-maintenance
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
if [[ "${NODE_MAINTENANCE_KIND_ACTION:-}" == module ]]; then
	# The module lane loads a real module of the runner kernel from its module tree.
	printf '    extraMounts:\n      - hostPath: /lib/modules\n        containerPath: /lib/modules\n        readOnly: true\n' >> "$proof_dir/kind.yaml"
fi
kind create cluster --name "$cluster" --config "$proof_dir/kind.yaml" \
	--kubeconfig "$proof_dir/kubeconfig" --wait 120s \
	--image "${KIND_NODE_IMAGE:-kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5}"
kind_capture_owned_cluster_identity
KIND_CLUSTER_CREATED=true
node_id="$KIND_CLUSTER_OWNER_IDS"
[[ "$node_id" =~ ^[0-9a-f]{64}$ ]] || { echo "Expected exactly one owned Kind node" >&2; exit 1; }
docker network connect kind "$registry_id"
docker exec "$node_id" mkdir -p "/etc/containerd/certs.d/$registry:5000"
printf 'server = "http://%s:5000"\n[host."http://%s:5000"]\n  capabilities = ["pull", "resolve"]\n' "$registry" "$registry" \
	| docker exec --interactive "$node_id" sh -c "cat > '/etc/containerd/certs.d/$registry:5000/hosts.toml'"
kubectl --kubeconfig "$proof_dir/kubeconfig" apply \
	-f config/crd/bases/breakglass.t-caas.telekom.com_clusterconfigs.yaml \
	-f config/crd/bases/breakglass.t-caas.telekom.com_debugsessions.yaml \
	-f config/crd/bases/breakglass.t-caas.telekom.com_debugsessiontemplates.yaml \
	-f config/crd/bases/breakglass.t-caas.telekom.com_debugsessionclusterbindings.yaml \
	-f config/crd/bases/breakglass.t-caas.telekom.com_debugpodtemplates.yaml
# kubectl wait --for=condition fails instead of waiting while a fresh object
# has no status.conditions yet, so retry it within the same 60s bound.
established=false
for _attempt in {1..12}; do
	if kubectl --kubeconfig "$proof_dir/kubeconfig" wait --for=condition=Established --timeout=5s \
		crd/clusterconfigs.breakglass.t-caas.telekom.com \
		crd/debugpodtemplates.breakglass.t-caas.telekom.com \
		crd/debugsessionclusterbindings.breakglass.t-caas.telekom.com \
		crd/debugsessions.breakglass.t-caas.telekom.com \
		crd/debugsessiontemplates.breakglass.t-caas.telekom.com; then
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

# This is disposable Kind-node kernel state, never an arbitrary caller command.
docker exec "$node_id" sh -eu -c '
	for link in bg1551n bg1551v bg1551vrf bg1551a bg1551ap bg1551b bg1551bp bg1551br; do
		if ip link show "$link" >/dev/null 2>&1; then
			echo "Fixture link collision: $link" >&2
			exit 1
		fi
	done
	ip link add bg1551n type dummy
	ip address add 192.0.2.1/24 dev bg1551n
	ip link set bg1551n up
	ip neigh replace 192.0.2.2 lladdr 02:00:00:00:00:03 nud permanent dev bg1551n
	ip neigh replace 192.0.2.9 lladdr 02:00:00:00:00:09 nud permanent dev bg1551n
	ip link add bg1551vrf type vrf table 1551
	ip link set bg1551vrf up
	ip link add bg1551v type dummy
	ip link set bg1551v master bg1551vrf
	ip address add 198.51.100.1/24 dev bg1551v
	ip link set bg1551v up
	ip neigh replace 198.51.100.2 lladdr 02:00:00:00:00:03 nud permanent dev bg1551v
	ip neigh replace 198.51.100.9 lladdr 02:00:00:00:00:09 nud permanent dev bg1551v
	ip link add bg1551br type bridge vlan_filtering 1
	# Each port gets an unbridged peer: bridging both ends of one veth pair
	# forms a layer-2 loop whose broadcast storm starves the Kind control plane.
	ip link add bg1551a type veth peer name bg1551ap
	ip link add bg1551b type veth peer name bg1551bp
	ip link set bg1551a master bg1551br
	ip link set bg1551b master bg1551br
	ip link set bg1551br up
	for link in bg1551a bg1551ap bg1551b bg1551bp; do
		ip link set "$link" up
	done
	bridge vlan add dev bg1551a vid 100
	bridge vlan add dev bg1551b vid 100
	bridge vlan add dev bg1551b vid 101
	bridge fdb replace 02:00:00:00:00:02 dev bg1551b master static vlan 100
	bridge fdb replace 02:00:00:00:00:09 dev bg1551b master static vlan 101
'
# A disposable recovery bundle that is only hashed and never loaded: Kind
# nodes are control planes, so the kexec lane proves validation and refusal.
recovery_dir=/var/lib/bg1551-recovery
kexec_sha256=$(docker exec "$node_id" sh -eu -c "
	[ ! -e $recovery_dir ] || { echo 'Fixture recovery bundle collision' >&2; exit 1; }
	mkdir -m 0755 $recovery_dir
	printf 'disposable kernel\\n' > $recovery_dir/kernel
	printf 'disposable initrd\\n' > $recovery_dir/initrd
	printf 'console=ttyS0\\n' > $recovery_dir/cmdline
	for file in kernel initrd cmdline; do sha256sum $recovery_dir/\$file | cut -d' ' -f1; done | paste -sd,
")
[[ "$kexec_sha256" =~ ^[a-f0-9]{64},[a-f0-9]{64},[a-f0-9]{64}$ ]] || { echo "Invalid recovery bundle digests" >&2; exit 1; }
kind_module=""
if [[ "${NODE_MAINTENANCE_KIND_ACTION:-}" == module ]]; then
	# Pick a module that exists for the running kernel and is not loaded yet.
	kind_module=$(docker exec --interactive "$node_id" /bin/sh -s <<'PICK'
release=$(uname -r)
for m in ip6_gre gre vxlan ipip sit bonding dummy; do
	[ -d "/sys/module/$m" ] && continue
	grep -Eq "/$m\.ko(\.(xz|zst|gz))?:" "/lib/modules/$release/modules.dep" 2>/dev/null && { echo "$m"; exit 0; }
done
PICK
)
	[[ "$kind_module" =~ ^[a-z0-9_]+$ ]] || {
		echo "No unloaded test module is available for this kernel: $(docker exec "$node_id" uname -r) $(docker exec "$node_id" ls /lib/modules 2>&1 | tr '\n' ' ')" >&2
		exit 1
	}
fi
NODE_MAINTENANCE_KIND_MODULE="$kind_module" \
NODE_MAINTENANCE_KIND_KEXEC_SHA256="$kexec_sha256" \
NODE_MAINTENANCE_KIND_KUBECONFIG="$PWD/$proof_dir/kubeconfig" \
NODE_MAINTENANCE_KIND_NODE="$node" \
NODE_MAINTENANCE_KIND_CONTAINER_ID="$node_id" \
NODE_MAINTENANCE_KIND_IMAGE="$registry:5000/node-maintenance@$digest" \
	"$proof_dir/maintenance.test" -test.run '^TestNodeMaintenanceKind$' -test.count=1 -test.timeout=15m -test.v
