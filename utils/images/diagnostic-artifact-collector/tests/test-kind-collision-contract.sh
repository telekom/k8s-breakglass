#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

script="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)/tests/kind-collision.sh"
grep -F "alpine:3.24@sha256:28bd5fe8b56d1bd048e5babf5b10710ebe0bae67db86916198a6eec434943f8b" "${script}" >/dev/null
if grep -E 'docker (pull|tag) alpine:3\.24([[:space:]]|$)' "${script}" >/dev/null; then
	printf '%s\n' 'collision proof uses an unpinned Alpine reference' >&2
	exit 1
fi
grep -F 'cluster_owned=false' "${script}" >/dev/null
grep -F 'image_owned=false' "${script}" >/dev/null
grep -F 'partial_cluster_is_owned' "${script}" >/dev/null
grep -F 'if ! awk -v expected=' "${script}" >/dev/null
grep -F "if [ \"\$cluster_owned\" = true ] || partial_cluster_is_owned" "${script}" >/dev/null
grep -F "if [ \"\$image_owned\" = true ]; then" "${script}" >/dev/null
if grep -E "delete cluster --name \\\"\$cluster\\\"( |\$)" "${script}" | grep -v -- '--kubeconfig' >/dev/null; then
	printf '%s\n' 'collision proof can delete a cluster without ownership kubeconfig' >&2
	exit 1
fi

fixture="$(mktemp -d)"
trap 'rm -rf "${fixture}"' EXIT HUP INT TERM
mkdir -p "${fixture}/bin"
cat >"${fixture}/bin/docker" <<'EOF'
#!/bin/bash
case "${1:-} ${2:-}" in
  "image inspect")
    if [[ "${FAKE_IMAGE_PRESENT:-0}" == 1 || -e "${FAKE_IMAGE_STATE:?}" ]]; then
      printf '%s\n' 'sha256:sentinel'
      exit 0
    fi
    exit 1
    ;;
  pull*) exit 0 ;;
  tag*) touch "${FAKE_IMAGE_STATE:?}"; exit 0 ;;
  "image rm"*) touch "${FAKE_IMAGE_REMOVED:?}"; exit 0 ;;
  *) exit 0 ;;
esac
EOF
cat >"${fixture}/bin/kind" <<'EOF'
#!/bin/bash
case "${1:-}" in
  get)
    [[ "${FAKE_KIND_GET_FAIL:-0}" != 1 ]] || exit 1
    printf '%s\n' "${FAKE_EXISTING_CLUSTERS:-}"
    ;;
  create)
    touch "${FAKE_CLUSTER_CREATE_ATTEMPTED:?}"
    if [[ "${FAKE_CLUSTER_CREATE_FAIL:-0}" == 1 ]]; then
      if [[ "${FAKE_WRONG_KUBECONFIG:-0}" == 1 ]]; then
        while [[ $# -gt 0 ]]; do
          if [[ "${1:-}" == --kubeconfig ]]; then
            printf 'clusters:\n- name: kind-foreign-cluster\ncurrent-context: kind-foreign-cluster\n' >"${2:?}"
            break
          fi
          shift
        done
      elif [[ "${FAKE_PARTIAL_KUBECONFIG:-0}" == 1 ]]; then
        while [[ $# -gt 0 ]]; do
          if [[ "${1:-}" == --kubeconfig ]]; then
            printf 'clusters:\n- name: kind-dac-collision\ncurrent-context: kind-dac-collision\n' >"${2:?}"
            break
          fi
          shift
        done
      fi
      exit 1
    fi
    ;;
  delete) touch "${FAKE_CLUSTER_DELETED:?}" ;;
  *) exit 0 ;;
esac
EOF
cat >"${fixture}/bin/kubectl" <<'EOF'
#!/bin/bash
exit 0
EOF
chmod +x "${fixture}/bin/docker" "${fixture}/bin/kind" "${fixture}/bin/kubectl"

run_collision_failure() {
	local name=$1 image_present=$2 get_fail=$3 create_fail=$4 partial=$5 wrong=${6:-0}
	local image_state="${fixture}/${name}.image" image_removed="${fixture}/${name}.image-removed"
	local create_attempted="${fixture}/${name}.create" cluster_deleted="${fixture}/${name}.deleted"
	FAKE_IMAGE_PRESENT="$image_present" FAKE_IMAGE_STATE="$image_state" \
	FAKE_IMAGE_REMOVED="$image_removed" FAKE_KIND_GET_FAIL="$get_fail" \
	FAKE_CLUSTER_CREATE_FAIL="$create_fail" FAKE_PARTIAL_KUBECONFIG="$partial" \
	FAKE_WRONG_KUBECONFIG="$wrong" \
	FAKE_CLUSTER_CREATE_ATTEMPTED="$create_attempted" FAKE_CLUSTER_DELETED="$cluster_deleted" \
	DOCKER_BIN="${fixture}/bin/docker" KIND_BIN="${fixture}/bin/kind" KUBECTL_BIN="${fixture}/bin/kubectl" \
	  bash -c 'set +e; "$1" >/dev/null 2>&1; status=$?; set -e; test "$status" -ne 0' bash "${script}"
}

run_collision_failure preexisting 1 1 0 0
[[ ! -e "${fixture}/preexisting.image-removed" && ! -e "${fixture}/preexisting.deleted" ]] || {
	printf '%s\n' 'pre-existing image/cluster failure path attempted cleanup' >&2
	exit 1
}

run_collision_failure image-owned 0 1 0 0
[[ -e "${fixture}/image-owned.image-removed" && ! -e "${fixture}/image-owned.deleted" ]] || {
	printf '%s\n' 'owned image failure path did not clean only the owned image' >&2
	exit 1
}

run_collision_failure partial-cluster 0 0 1 1
[[ -e "${fixture}/partial-cluster.image-removed" && \
	-e "${fixture}/partial-cluster.create" && -e "${fixture}/partial-cluster.deleted" ]] || {
	printf '%s\n' 'verified partial create did not clean its owned resources' >&2
	exit 1
}

run_collision_failure wrong-kubeconfig 0 0 1 1 1
[[ -e "${fixture}/wrong-kubeconfig.image-removed" && \
	-e "${fixture}/wrong-kubeconfig.create" && ! -e "${fixture}/wrong-kubeconfig.deleted" ]] || {
	printf '%s\n' 'wrong-name Kind kubeconfig authorized collision cleanup' >&2
	exit 1
}

printf '%s\n' 'Kind collision image reference contract passed'
