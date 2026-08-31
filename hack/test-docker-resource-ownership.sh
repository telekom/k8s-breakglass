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
"volume inspect") printf '%s\n' "${VOLUME_OWNER:-foreign}" ;;
"volume rm") touch "${VOLUME_REMOVED:?}" ;;
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
if VOLUME_OWNER=replacement VOLUME_REMOVED="$fixture/volume" \
  docker_remove_volume_if_owned "$fixture/docker" proof-volume owner run-original; then
  echo 'replacement volume passed ownership check' >&2
  exit 1
fi
[ ! -e "$fixture/volume" ]
echo 'Docker immutable resource ownership behavior passed'
