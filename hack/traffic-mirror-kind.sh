#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
# Disposable Kind proof for session-scoped traffic mirroring (TestTrafficMirrorKind).
set -euo pipefail

cd "$(dirname "$0")/.."
for tool in docker kind kubectl go; do
	command -v "$tool" >/dev/null || { printf 'Required tool missing: %s\n' "$tool" >&2; exit 1; }
done
docker info >/dev/null
proof_dir=".traffic-mirror-proof-$$"
cluster="traffic-mirror-proof-$$"
if kind get clusters | grep -Fx "$cluster" >/dev/null; then
	echo "Proof cluster collision" >&2
	exit 1
fi
[[ ! -e "$proof_dir" ]] || { echo "Proof directory collision" >&2; exit 1; }
mkdir "$proof_dir"
created=false
cleanup() {
	status=$?
	trap - EXIT
	if [[ "$created" == true ]]; then
		if [[ "$status" -ne 0 ]]; then
			kubectl --kubeconfig "$proof_dir/kubeconfig" --request-timeout=10s get pods --all-namespaces -o wide || true
			kubectl --kubeconfig "$proof_dir/kubeconfig" --request-timeout=10s describe pods -n breakglass-node-maintenance || true
		fi
		kind delete cluster --name "$cluster" --kubeconfig "$proof_dir/kubeconfig" >/dev/null 2>&1 || status=1
		if kind get clusters | grep -Fx "$cluster" >/dev/null; then
			echo "Proof cluster was not removed" >&2
			status=1
		fi
	fi
	rm -rf "$proof_dir"
	exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir "$proof_dir/go-work"
GOTMPDIR="$PWD/$proof_dir/go-work" go test -c ./pkg/breakglass/debug -o "$proof_dir/mirror.test"
created=true
kind_node_image="${KIND_NODE_IMAGE:-kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5}"
kind create cluster --name "$cluster" --kubeconfig "$proof_dir/kubeconfig" --wait 120s --image "$kind_node_image"
node_id=$(docker ps --no-trunc --quiet --filter "name=^${cluster}-control-plane$")
[[ "$node_id" =~ ^[0-9a-f]{64}$ ]] || { echo "Expected exactly one Kind node container" >&2; exit 1; }
kubectl --kubeconfig "$proof_dir/kubeconfig" apply --server-side \
	-f config/crd/bases/breakglass.t-caas.telekom.com_clusterconfigs.yaml \
	-f config/crd/bases/breakglass.t-caas.telekom.com_debugsessions.yaml \
	-f config/crd/bases/breakglass.t-caas.telekom.com_debugsessiontemplates.yaml \
	-f config/crd/bases/breakglass.t-caas.telekom.com_debugsessionclusterbindings.yaml \
	-f config/crd/bases/breakglass.t-caas.telekom.com_debugpodtemplates.yaml
kubectl --kubeconfig "$proof_dir/kubeconfig" wait --for=condition=Established --timeout=60s \
	crd/clusterconfigs.breakglass.t-caas.telekom.com \
	crd/debugsessions.breakglass.t-caas.telekom.com \
	crd/debugsessiontemplates.breakglass.t-caas.telekom.com
# The operator-provisioned fixed executor namespace admits the hostPID mirror Pod.
kubectl --kubeconfig "$proof_dir/kubeconfig" create namespace breakglass-node-maintenance
kubectl --kubeconfig "$proof_dir/kubeconfig" label namespace breakglass-node-maintenance \
	pod-security.kubernetes.io/enforce=privileged
# The network-debug utility's pinned netshoot base provides ip, tc, nsenter and tcpdump.
image="${TRAFFIC_MIRROR_IMAGE:-ghcr.io/nicolaka/netshoot:v0.16@sha256:b09d9b21381f47a79b3cbcb30da25266dc17186ea00ae65e99fdc51396f48e70}"
TRAFFIC_MIRROR_KIND_KUBECONFIG="$PWD/$proof_dir/kubeconfig" \
TRAFFIC_MIRROR_KIND_CONTAINER_ID="$node_id" \
TRAFFIC_MIRROR_KIND_IMAGE="$image" \
	"$proof_dir/mirror.test" -test.run '^TestTrafficMirrorKind$' -test.count=1 -test.timeout=20m -test.v
