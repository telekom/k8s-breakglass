#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
# Disposable Kind proof for typed admission recipes (TestAdmissionRecipeKind).
set -euo pipefail

cd "$(dirname "$0")/.."
for tool in docker kind kubectl go; do
	command -v "$tool" >/dev/null || { printf 'Required tool missing: %s\n' "$tool" >&2; exit 1; }
done
proof_dir=".admission-recipe-proof-$$"
cluster="admission-recipe-proof-$$"
if kind get clusters | grep -Fx "$cluster" >/dev/null; then
	echo "Proof cluster collision" >&2
	exit 1
fi
mkdir "$proof_dir"
created=false
cleanup() {
	status=$?
	trap - EXIT
	if [[ "$created" == true ]]; then
		kind delete cluster --name "$cluster" --kubeconfig "$proof_dir/kubeconfig" >/dev/null 2>&1 || status=1
	fi
	rm -rf "$proof_dir"
	exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

mkdir "$proof_dir/go-work"
GOTMPDIR="$PWD/$proof_dir/go-work" go test -c ./pkg/breakglass/debug -o "$proof_dir/recipe.test"
created=true
kind create cluster --name "$cluster" --kubeconfig "$proof_dir/kubeconfig" --wait 120s \
	--image "${KIND_NODE_IMAGE:-kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5}"
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
ADMISSION_RECIPE_KIND_KUBECONFIG="$PWD/$proof_dir/kubeconfig" \
	"$proof_dir/recipe.test" -test.run '^TestAdmissionRecipeKind$' -test.count=1 -test.timeout=10m -test.v
