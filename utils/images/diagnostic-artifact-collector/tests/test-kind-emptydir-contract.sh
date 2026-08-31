#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"
trap 'rm -rf "${tmp}"' EXIT
mkdir -p "${tmp}/bin"

cat >"${tmp}/bin/docker" <<'EOF'
#!/usr/bin/env bash
case "${1:-} ${2:-}" in
  "image inspect") exit 1 ;;
  build) exit 0 ;;
  "image rm") exit 0 ;;
  *) exit 0 ;;
esac
EOF
cat >"${tmp}/bin/kind" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  get)
    if [[ "${KIND_GET_FAIL:-}" == 1 ]]; then exit 1; fi
    printf '%s\n' "${KIND_EXISTING_CLUSTERS:-}"
    exit 0
    ;;
  create)
    touch "${KIND_CREATE_MARKER:?}"
    if [[ "${KIND_WRONG_KUBECONFIG:-}" == 1 ]]; then
      while [[ $# -gt 0 ]]; do
        if [[ "${1:-}" == --kubeconfig ]]; then
          printf 'clusters:\n- name: kind-foreign-cluster\ncurrent-context: kind-foreign-cluster\n' >"${2:?}"
          break
        fi
        shift
      done
    elif [[ "${KIND_PARTIAL_KUBECONFIG:-}" == 1 ]]; then
      while [[ $# -gt 0 ]]; do
        if [[ "${1:-}" == --kubeconfig ]]; then
          printf 'clusters:\n- name: kind-diagnostic-artifact-collector\ncurrent-context: kind-diagnostic-artifact-collector\n' >"${2:?}"
          break
        fi
        shift
      done
    fi
    exit 1
    ;;
  delete) touch "${KIND_DELETE_MARKER:?}"; exit 0 ;;
  *) exit 0 ;;
esac
EOF
cat >"${tmp}/bin/kubectl" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "${tmp}/bin/docker" "${tmp}/bin/kind" "${tmp}/bin/kubectl"

create_marker="${tmp}/created"
delete_marker="${tmp}/deleted"
if PATH="${tmp}/bin:${PATH}" KIND_CREATE_MARKER="${create_marker}" KIND_DELETE_MARKER="${delete_marker}" \
  KIND_GET_FAIL=1 \
  KIND_IMAGE_NAME=diagnostic-artifact-collector:test \
  "${root}/tests/kind-emptydir.sh" >/dev/null 2>&1; then
  echo 'Kind list failure unexpectedly succeeded' >&2
  exit 1
fi
[[ ! -e "${create_marker}" && ! -e "${delete_marker}" ]] || {
  echo 'Kind list failure attempted create or delete' >&2
  exit 1
}

rm -f "${create_marker}" "${delete_marker}"
if PATH="${tmp}/bin:${PATH}" KIND_CREATE_MARKER="${create_marker}" KIND_DELETE_MARKER="${delete_marker}" \
  KIND_EXISTING_CLUSTERS='' \
  KIND_IMAGE_NAME=diagnostic-artifact-collector:test \
  "${root}/tests/kind-emptydir.sh" >/dev/null 2>&1; then
  echo 'partial Kind create unexpectedly succeeded' >&2
  exit 1
fi
[[ -e "${create_marker}" && ! -e "${delete_marker}" ]] || {
  echo 'unverified failed Kind create attempted unsafe cleanup' >&2
  exit 1
}

rm -f "${create_marker}" "${delete_marker}"
if PATH="${tmp}/bin:${PATH}" KIND_CREATE_MARKER="${create_marker}" KIND_DELETE_MARKER="${delete_marker}" \
  KIND_PARTIAL_KUBECONFIG=1 \
  KIND_EXISTING_CLUSTERS='' \
  KIND_IMAGE_NAME=diagnostic-artifact-collector:test \
  "${root}/tests/kind-emptydir.sh" >/dev/null 2>&1; then
  echo 'verified partial Kind create unexpectedly succeeded' >&2
  exit 1
fi
[[ -e "${create_marker}" && -e "${delete_marker}" ]] || {
  echo 'verified partial Kind create did not clean its owned cluster' >&2
  exit 1
}

rm -f "${create_marker}" "${delete_marker}"
if PATH="${tmp}/bin:${PATH}" KIND_CREATE_MARKER="${create_marker}" KIND_DELETE_MARKER="${delete_marker}" \
  KIND_WRONG_KUBECONFIG=1 \
  KIND_EXISTING_CLUSTERS='' \
  KIND_IMAGE_NAME=diagnostic-artifact-collector:test \
  "${root}/tests/kind-emptydir.sh" >/dev/null 2>&1; then
  echo 'wrong-name Kind create unexpectedly succeeded' >&2
  exit 1
fi
[[ -e "${create_marker}" && ! -e "${delete_marker}" ]] || {
  echo 'wrong-name Kind kubeconfig authorized cleanup' >&2
  exit 1
}

if PATH="${tmp}/bin:${PATH}" KIND_IMAGE_NAME=registry.example/collector@sha256:$(printf '%064d' 1) \
  "${root}/tests/kind-emptydir.sh" >/dev/null 2>&1; then
  echo 'digest-form Kind image unexpectedly accepted' >&2
  exit 1
fi
echo 'Kind emptyDir lifecycle and image-reference contract passed'
