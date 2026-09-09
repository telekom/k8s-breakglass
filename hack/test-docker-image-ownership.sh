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
"image rm")
	[ "${3:-}" = id-original ] || exit 1
	printf '%s\n' "${3}" >"${REMOVED_ID:?}"
	if [ "${RACE_REPLACEMENT:-false}" = true ]; then
		touch "${REPLACEMENT_SURVIVED:?}"
	fi
	;;
*) exit 2 ;;
esac
EOF
chmod +x "$fixture/docker"
source "$root/hack/docker-image-ownership.sh"
REMOVED_ID="$fixture/removed-id" FAKE_IMAGE_ID=id-original \
  docker_remove_image_if_id "$fixture/docker" collector:proof id-original
[ "$(cat "$fixture/removed-id")" = id-original ] || { echo 'matching image ID was not removed' >&2; exit 1; }
rm -f "$fixture/removed-id"
if REMOVED_ID="$fixture/removed-id" FAKE_IMAGE_ID=id-replacement \
  docker_remove_image_if_id "$fixture/docker" collector:proof id-original; then
  echo 'replacement image tag was removed' >&2
  exit 1
fi
 [ ! -e "$fixture/removed-id" ] || { echo 'replacement image was deleted' >&2; exit 1; }
RACE_REPLACEMENT=true REMOVED_ID="$fixture/removed-id" REPLACEMENT_SURVIVED="$fixture/replacement-survived" FAKE_IMAGE_ID=id-original \
  docker_remove_image_if_id "$fixture/docker" collector:proof id-original
[ -e "$fixture/replacement-survived" ] || { echo 'replacement image tag was not preserved' >&2; exit 1; }
printf '%s\n' 'Docker immutable image ownership behavior passed'
