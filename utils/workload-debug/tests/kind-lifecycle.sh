#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

# Small, testable ownership boundary for the disposable Kind cluster used by
# the integration proof. A name is checked before create. If create fails
# after Kind has registered the previously absent name, the partial cluster
# is owned by this invocation and may be cleaned up. A pre-existing name is
# never marked as owned.

KIND_LIFECYCLE_OWNED=0

kind_lifecycle_cluster_exists() {
    local cluster_name=$1
    local clusters

    clusters=$(kind get clusters) || return 2
    grep -Fxq -- "$cluster_name" <<<"$clusters"
}

kind_lifecycle_create() {
    [ "$#" -eq 3 ] || return 2
    local cluster_name=$1
    local node_image=$2
    local kubeconfig=$3
    local create_status=0
    local kubeconfig_preexisting=0

    KIND_LIFECYCLE_OWNED=0
    [ -e "$kubeconfig" ] && kubeconfig_preexisting=1
    if kind_lifecycle_cluster_exists "$cluster_name"; then
        return 3
    elif [ "$?" -eq 2 ]; then
        return 2
    fi

    if kind create cluster --name "$cluster_name" --image "$node_image" \
        --kubeconfig "$kubeconfig" --wait 120s; then
        KIND_LIFECYCLE_OWNED=1
        return 0
    else
        create_status=$?
    fi

    # The preflight established that this name was absent. If Kind left a
    # cluster behind after a timeout or partial bootstrap, it belongs to this
    # invocation and must be cleaned up by the EXIT trap. A collision detected
    # during preflight never reaches this branch and remains caller-owned.
    if kind_lifecycle_cluster_exists "$cluster_name" && [ "$kubeconfig_preexisting" -eq 0 ]; then
        KIND_LIFECYCLE_OWNED=1
    fi
    return "$create_status"
}

kind_lifecycle_cleanup() {
    [ "$#" -eq 2 ] || return 2
    local cluster_name=$1
    local kubeconfig=$2
    local remaining
    local status=0

    if (( ! KIND_LIFECYCLE_OWNED )); then
        return 0
    fi
    if [ -e "$kubeconfig" ]; then
        kind delete cluster --name "$cluster_name" --kubeconfig "$kubeconfig" >/dev/null 2>&1 || status=1
    else
        kind delete cluster --name "$cluster_name" >/dev/null 2>&1 || status=1
    fi
    if ! remaining=$(kind get clusters 2>/dev/null); then
        status=1
        remaining=
    fi
    if grep -Fxq -- "$cluster_name" <<<"$remaining"; then
        status=1
    fi
    KIND_LIFECYCLE_OWNED=0
    return "$status"
}
