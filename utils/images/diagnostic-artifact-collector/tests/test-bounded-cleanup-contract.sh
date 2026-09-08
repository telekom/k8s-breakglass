#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail

root=$(cd -- "$(dirname -- "$0")/.." && pwd)
# shellcheck disable=SC1091
source "$root/../../..//hack/docker-resource-ownership.sh"
# shellcheck disable=SC1091
source "$root/tests/bounded-container-cleanup.sh"

fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT
printf '%s\n' owned >"$fixture/owned"
printf '%s\n' foreign >"$fixture/foreign"
cat >"$fixture/docker" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
[ "${1:-}" = rm ] && [ "${2:-}" = -f ]
name=${3:?}
case "$name" in
owned) rm -f "$FAKE_DOCKER_STATE/owned" ;;
foreign) printf '%s\n' 'foreign deletion attempted' >>"$FAKE_DOCKER_STATE/errors"; exit 1 ;;
*) printf '%s\n' "unexpected deletion: $name" >>"$FAKE_DOCKER_STATE/errors"; exit 1 ;;
esac
EOF
chmod +x "$fixture/docker"
FAKE_DOCKER_STATE=$fixture cleanup_bounded_container_name "$fixture/docker" owned
[ ! -e "$fixture/owned" ]
[ -e "$fixture/foreign" ]
[ ! -e "$fixture/errors" ]
printf '%s\n' 'bounded container capture-failure cleanup contract passed'
