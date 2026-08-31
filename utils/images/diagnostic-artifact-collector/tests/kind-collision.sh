#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -eu

root=$(cd -- "$(dirname -- "$0")/.." && pwd)
cluster=dac-collision
image=diagnostic-artifact-collector:kind-test
sentinel_image=$image
KIND_NODE_IMAGE=${KIND_NODE_IMAGE:-kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5}
cleanup() {
	kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
	docker image rm "$sentinel_image" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

command -v docker >/dev/null 2>&1 || { echo 'Docker is required for collision proof' >&2; exit 1; }
command -v kind >/dev/null 2>&1 || { echo 'Kind is required for collision proof' >&2; exit 1; }

alpine_image='alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b'
docker pull "$alpine_image" >/dev/null
docker tag "$alpine_image" "$sentinel_image"
sentinel_id=$(docker image inspect --format '{{.Id}}' "$sentinel_image")
kind create cluster --name "$cluster" --image "$KIND_NODE_IMAGE" --wait 90s >/dev/null

# The reference test must detect both pre-existing resources and choose owned
# names. Its cleanup must leave these sentinels untouched.
KIND_CLUSTER_NAME="$cluster" KIND_IMAGE_NAME="$image" "$root/tests/kind-emptydir.sh"
kind get clusters | grep -Fx "$cluster" >/dev/null
[ "$(docker image inspect --format '{{.Id}}' "$sentinel_image")" = "$sentinel_id" ]

echo 'Kind collision preservation behavior passed'
