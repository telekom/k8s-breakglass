#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail

root=$(cd -- "$(dirname -- "$0")/.." && pwd)
fixture=$(mktemp -d "${TMPDIR:-/tmp}/docker-image-ownership.XXXXXX")
trap 'rm -rf -- "$fixture"' EXIT HUP INT TERM
cat >"$fixture/docker" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
case "${1:-} ${2:-}" in
"image inspect") printf '%s\n' "${FAKE_IMAGE_ID:?}" ;;
"image rm") touch "${REMOVED:?}" ;;
*) exit 2 ;;
esac
EOF
chmod +x "$fixture/docker"
source "$root/hack/docker-image-ownership.sh"
REMOVED="$fixture/removed" FAKE_IMAGE_ID=id-original \
  docker_remove_image_if_id "$fixture/docker" collector:proof id-original
[ -e "$fixture/removed" ] || { echo 'matching image ID was not removed' >&2; exit 1; }
rm -f "$fixture/removed"
if REMOVED="$fixture/removed" FAKE_IMAGE_ID=id-replacement \
  docker_remove_image_if_id "$fixture/docker" collector:proof id-original; then
  echo 'replacement image tag was removed' >&2
  exit 1
fi
[ ! -e "$fixture/removed" ] || { echo 'replacement image was deleted' >&2; exit 1; }
printf '%s\n' 'Docker immutable image ownership behavior passed'
