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
printf '%s\n' name-taken >"$fixture/name"
cat >"$fixture/docker" <<'EOF'
#!/usr/bin/env bash
set -Eeuo pipefail
[ "${1:-}" = rm ] && [ "${2:-}" = -f ]
id=${3:?}
case "$id" in
aaaaaaaa) rm -f "$FAKE_DOCKER_STATE/owned" ;;
bbbbbbbb) printf '%s\n' 'foreign deletion attempted' >>"$FAKE_DOCKER_STATE/errors"; exit 1 ;;
*) printf '%s\n' "unexpected deletion: $id" >>"$FAKE_DOCKER_STATE/errors"; exit 1 ;;
esac
EOF
chmod +x "$fixture/docker"
printf '%s\n' aaaaaaaa >"$fixture/cidfile"
captured_id=$(docker_capture_resource_id_from_cidfile "$fixture/cidfile")
[ "$captured_id" = aaaaaaaa ]
# The generated name is taken over after ID capture; cleanup must still use the
# registered original ID and must never delete the replacement by name.
printf '%s\n' bbbbbbbb >"$fixture/name"
FAKE_DOCKER_STATE=$fixture docker_remove_resource_id "$fixture/docker" container "$captured_id"
[ ! -e "$fixture/owned" ]
[ -e "$fixture/foreign" ]
[ -e "$fixture/name" ]
[ ! -e "$fixture/errors" ]
printf '%s\n' 'bounded container immutable-ID cleanup race contract passed'
