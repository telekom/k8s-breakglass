#!/bin/sh
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
cluster_owned=false
cluster_create_attempted=false
image_owned=false
partial_cluster_is_owned() {
	[ "$cluster_create_attempted" = true ] || return 1
	[ -s "$sentinel_kubeconfig" ] || return 1
	if ! awk -v expected="kind-${cluster}" '
		($1 == "name:" && $2 == expected) || ($1 == "-" && $2 == "name:" && $3 == expected) { found_name = 1 }
		$1 == "current-context:" && $2 == expected { found_context = 1 }
		END { exit !(found_name && found_context) }
	' "$sentinel_kubeconfig"; then
		return 1
	fi
	"$KUBECTL_BIN" --kubeconfig "$sentinel_kubeconfig" get --raw=/version >/dev/null 2>&1
}
cleanup() {
	if [ "$cluster_owned" = true ] || partial_cluster_is_owned; then
		"$KIND_BIN" delete cluster --name "$cluster" --kubeconfig "$sentinel_kubeconfig" >/dev/null 2>&1 || true
	fi
	if [ "$image_owned" = true ]; then
		"$DOCKER_BIN" image rm "$sentinel_image" >/dev/null 2>&1 || true
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
if ! existing_clusters=$("$KIND_BIN" get clusters 2>/dev/null); then
	echo 'could not list Kind clusters before creating the collision sentinel' >&2
	exit 1
fi
if printf '%s\n' "$existing_clusters" | grep -Fx "$cluster" >/dev/null 2>&1; then
	:
else
	cluster_create_attempted=true
	if "$KIND_BIN" create cluster --name "$cluster" --image "$KIND_NODE_IMAGE" --kubeconfig "$sentinel_kubeconfig" --wait 90s >/dev/null; then
		cluster_owned=true
	else
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
