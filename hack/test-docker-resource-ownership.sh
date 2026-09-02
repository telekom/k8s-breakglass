#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail

root=$(cd -- "$(dirname -- "$0")/.." && pwd)
fixture=$(mktemp -d "${TMPDIR:-/tmp}/docker-resource-ownership.XXXXXX")
trap 'rm -rf -- "$fixture"' EXIT HUP INT TERM
cat >"$fixture/docker" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
case "${1:-} ${2:-}" in
"inspect")
  [ "${3:-}" = --format ] && [ "${4:-}" = '{{.Id}}' ] && printf '%s\n' "${CONTAINER_ID:?}" || exit 1
  [ "${3:-}" = "$CONTAINER_ID" ]
  ;;
"network inspect") printf '%s\n' "${NETWORK_ID:?}" ;;
"rm -f") touch "${CONTAINER_REMOVED:?}" ;;
"network rm") touch "${NETWORK_REMOVED:?}" ;;
"rm -fv")
  [ "${3:-}" = owner-original ] || exit 1
  touch "${OWNER_REMOVED:?}"
  ;;
*) exit 2 ;;
esac
EOF
chmod +x "$fixture/docker"
source "$root/hack/docker-resource-ownership.sh"
CONTAINER_ID=container-original CONTAINER_REMOVED="$fixture/container" \
  docker_remove_resource_id "$fixture/docker" container container-original
[ -e "$fixture/container" ]
NETWORK_ID=network-original NETWORK_REMOVED="$fixture/network" \
  docker_remove_resource_id "$fixture/docker" network network-original
[ -e "$fixture/network" ]
OWNER_REMOVED="$fixture/owner" docker_remove_resource_with_volumes "$fixture/docker" container owner-original
[ -e "$fixture/owner" ]
echo 'Docker immutable resource ownership behavior passed'
