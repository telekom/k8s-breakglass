#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

script="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)/tests/kind-host-network.sh"
save_command="\"\${DOCKER_BIN}\" save --platform \"\${runner_platform}\" --output \"\${image_archive}\" \"\${image}\""
load_command="\"\${KIND_BIN}\" load image-archive \"\${image_archive}\" --name \"\${cluster}\""
assert_contains() {
	local needle=$1
	if ! grep -F "${needle}" "${script}" >/dev/null; then
		printf 'missing node-maintenance image-load contract assertion: %s\n' "${needle}" >&2
		exit 1
	fi
}

assert_contains "${save_command}"
assert_contains "${load_command}"
assert_contains "timeout --foreground 5m \"\${KIND_BIN}\" load image-archive"
assert_contains 'Kind archive load exited with status'
assert_contains 'Exact-platform archive size:'
assert_contains "tar -tf \"\${image_archive}\""
assert_contains 'Kind archive load completed'
assert_contains 'Exact node-maintenance image is present in Kind containerd'
assert_contains "containerd_image=\"docker.io/library/\${image}\""
assert_contains 'cluster_create_attempted=true'
assert_contains "if [[ \"\${cluster_create_attempted}\" == true ]]"
assert_contains 'KIND_CLUSTER_CREATED=false'
assert_contains 'kind_create_owned_cluster'
assert_contains 'kind_cleanup_owned_cluster'
if grep -F 'partial_cluster_is_owned' "${script}" >/dev/null; then
	printf '%s\n' 'node-maintenance proof trusts unproven partial cluster ownership' >&2
	exit 1
fi
assert_contains 'KIND_CLUSTER_OWNER_IDS='
assert_contains 'Kind containerd images:'
assert_contains 'volumeMounts | length) == 1'
assert_contains 'expected_exit'
assert_contains 'jq -s --arg expected'
assert_contains 'terminal_count'
assert_contains "length == 1 and .[0].result == \$expected"
assert_contains 'terminal_event=succeeded'
assert_contains 'terminal_event=failed'
if grep -F "helper_status=\${action_status}" "${script}" >/dev/null; then
	exit 1
fi
assert_contains 'helper_status=\$?'
assert_contains 'exactly one complete evidence bundle'
assert_contains "bundle_count=\$((bundle_count + 1))"
assert_contains 'bundle_dir}/metadata'
assert_contains "rm -f \"\${load_log}\""
if grep -F 'kind load docker-image' "${script}" >/dev/null; then
	exit 1
fi

# Exercise failed Kind creation, including a same-name takeover. The fake
# kubectl deliberately succeeds even for a foreign kubeconfig; cleanup must
# refuse deletion whenever create did not return success.
fixture="$(mktemp -d)"
trap 'rm -rf "${fixture}"' EXIT HUP INT TERM
mkdir -p "${fixture}/bin"
cat >"${fixture}/bin/docker" <<'EOF'
#!/usr/bin/env bash
case "${1:-} ${2:-}" in
  "image inspect")
    if [[ "$*" == *"--format"* ]]; then printf '%s\n' 'linux/amd64'; fi
    exit 0
    ;;
  "version") printf '%s\n' '28.0.0'; exit 0 ;;
  *) exit 0 ;;
esac
EOF
cat >"${fixture}/bin/kind" <<'EOF'
#!/usr/bin/env bash
case "${1:-}" in
  get) exit 0 ;;
  create)
    cluster_name=
    kubeconfig=
    while [[ $# -gt 0 ]]; do
      case "${1:-}" in
        --name) cluster_name="${2:?}"; shift 2 ;;
        --kubeconfig) kubeconfig="${2:?}"; shift 2 ;;
        *) shift ;;
      esac
    done
    case "${KIND_KUBECONFIG_MODE:?}" in
      wrong-name) name=kind-foreign-cluster; context=kind-foreign-cluster ;;
      wrong-context) name="kind-${cluster_name}"; context=kind-foreign-cluster ;;
      same-name-takeover) name="kind-${cluster_name}"; context="kind-${cluster_name}" ;;
      *) exit 2 ;;
    esac
    printf 'clusters:\n- name: %s\ncurrent-context: %s\n' "${name}" "${context}" >"${kubeconfig}"
    exit 1
    ;;
  delete) touch "${KIND_DELETE_MARKER:?}"; exit 0 ;;
  export) exit 0 ;;
  *) exit 0 ;;
esac
EOF
cat >"${fixture}/bin/kubectl" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat >"${fixture}/bin/jq" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
cat >"${fixture}/bin/uname" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' Linux
EOF
chmod +x "${fixture}/bin/docker" "${fixture}/bin/kind" "${fixture}/bin/kubectl" "${fixture}/bin/jq" "${fixture}/bin/uname"

for mode in wrong-name wrong-context same-name-takeover; do
	delete_marker="${fixture}/${mode}.deleted"
	if PATH="${fixture}/bin:${PATH}" \
		NODE_MAINTENANCE_TEST_IMAGE=node-maintenance:test \
		NODE_MAINTENANCE_KIND_NODE_IMAGE=kindest/node:test \
		KIND_KUBECONFIG_MODE="${mode}" KIND_DELETE_MARKER="${delete_marker}" \
		"${script}" >"${fixture}/${mode}.log" 2>&1; then
		printf 'foreign %s kubeconfig unexpectedly succeeded\n' "${mode}" >&2
		exit 1
	fi
	[[ ! -e "${delete_marker}" ]] || {
		printf 'foreign %s kubeconfig authorized Kind deletion\n' "${mode}" >&2
		exit 1
	}
done
printf '%s\n' 'node-maintenance exact-platform archive load contract passed'
