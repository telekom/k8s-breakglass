#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -eu

root=$(cd -- "$(dirname -- "$0")/.." && pwd)
cluster=dac-collision
image=diagnostic-artifact-collector:kind-test
sentinel_image=$image
KIND_NODE_IMAGE=${KIND_NODE_IMAGE:-kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5}
DOCKER_BIN=${DOCKER_BIN:-docker}
KIND_BIN=${KIND_BIN:-kind}
KUBECTL_BIN=${KUBECTL_BIN:-kubectl}
sentinel_kubeconfig=$(mktemp "${TMPDIR:-/tmp}/diagnostic-artifact-collector-collision-kubeconfig.XXXXXX")
export KIND_CLUSTER_NAME="$cluster" KUBECONFIG_FILE="$sentinel_kubeconfig" KIND_CLUSTER_CREATED=false KIND_CLUSTER_OWNER_IDS=''
# shellcheck source=../../../../hack/kind-ownership.sh
# shellcheck disable=SC1091
script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
# shellcheck disable=SC1091
. "${script_dir}/../../../../hack/kind-ownership.sh"
# shellcheck disable=SC1091
. "${script_dir}/../../../../hack/docker-image-ownership.sh"
image_owned=false
image_owned_id=
cleanup() {
	kind_cleanup_owned_cluster >/dev/null 2>&1 || true
	if [ "$image_owned" = true ]; then
		docker_remove_image_if_id "$DOCKER_BIN" "$sentinel_image" "$image_owned_id" || true
	fi
	rm -f "$sentinel_kubeconfig"
}
trap cleanup EXIT HUP INT TERM

command -v "$DOCKER_BIN" >/dev/null 2>&1 || { echo 'Docker is required for collision proof' >&2; exit 1; }
command -v "$KIND_BIN" >/dev/null 2>&1 || { echo 'Kind is required for collision proof' >&2; exit 1; }

alpine_image='alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b'
if "$DOCKER_BIN" image inspect "$sentinel_image" >/dev/null 2>&1; then
	:
else
	"$DOCKER_BIN" pull "$alpine_image" >/dev/null
	"$DOCKER_BIN" tag "$alpine_image" "$sentinel_image"
	image_owned=true
fi
sentinel_id=$("$DOCKER_BIN" image inspect --format '{{.Id}}' "$sentinel_image")
image_owned_id=$sentinel_id
if ! existing_clusters=$("$KIND_BIN" get clusters 2>/dev/null); then
	echo 'could not list Kind clusters before creating the collision sentinel' >&2
	exit 1
fi
if printf '%s\n' "$existing_clusters" | grep -Fx "$cluster" >/dev/null 2>&1; then
	:
else
	if ! kind_create_owned_cluster >/dev/null; then
		echo 'could not create collision sentinel Kind cluster' >&2
		exit 1
	fi
fi

# The reference test must detect both pre-existing resources and choose owned
# names. Its cleanup must leave these sentinels untouched.
DOCKER_BIN="$DOCKER_BIN" KIND_BIN="$KIND_BIN" KUBECTL_BIN="$KUBECTL_BIN" \
	KIND_CLUSTER_NAME="$cluster" KIND_IMAGE_NAME="$image" "$root/tests/kind-emptydir.sh"
"$KIND_BIN" get clusters | grep -Fx "$cluster" >/dev/null
[ "$("$DOCKER_BIN" image inspect --format '{{.Id}}' "$sentinel_image")" = "$sentinel_id" ]

echo 'Kind collision preservation behavior passed'
