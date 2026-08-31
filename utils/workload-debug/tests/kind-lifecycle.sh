#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

# Compatibility wrapper for the workload integration proof. Ownership is
# established by the shared helper from exact Docker node IDs after a
# successful create; cluster names and Kind's partial state are never enough.

script_dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)
KIND_BIN=${KIND_BIN:-kind}
DOCKER_BIN=${DOCKER_BIN:-docker}
KIND_CLUSTER_CREATED=${KIND_CLUSTER_CREATED:-false}
KIND_CLUSTER_OWNER_IDS=${KIND_CLUSTER_OWNER_IDS:-}
# shellcheck disable=SC1091
. "${script_dir}/../../../hack/kind-ownership.sh"

KIND_LIFECYCLE_OWNED=0

kind_lifecycle_create() {
    [ "$#" -eq 3 ] || return 2
    local cluster_name=$1 node_image=$2 kubeconfig=$3 status=0
    export KIND_CLUSTER_NAME="$cluster_name" KIND_NODE_IMAGE="$node_image" \
        KUBECONFIG_FILE="$kubeconfig" KIND_CLUSTER_CREATED=false KIND_CLUSTER_OWNER_IDS=
    if kind_create_owned_cluster; then
        KIND_LIFECYCLE_OWNED=1
        return 0
    else
        status=$?
    fi
    KIND_LIFECYCLE_OWNED=0
    case "$status" in
        2) return 3 ;;
        3) return 2 ;;
        *) return "$status" ;;
    esac
}

kind_lifecycle_cleanup() {
    [ "$#" -eq 2 ] || return 2
    local cluster_name=$1 kubeconfig=$2 status=0
    export KIND_CLUSTER_NAME="$cluster_name" KUBECONFIG_FILE="$kubeconfig"
    if [ "$KIND_LIFECYCLE_OWNED" -eq 1 ]; then
        kind_cleanup_owned_cluster || status=$?
    else
        return 0
    fi
    KIND_LIFECYCLE_OWNED=0
    return "$status"
}
