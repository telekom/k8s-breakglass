#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0
set -eu

root=$(cd -- "$(dirname -- "$0")/../../.." && pwd)
# shellcheck disable=SC1091
. "$root/hack/docker-resource-ownership.sh"

fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT INT TERM
printf '%s\n' owned >"$fixture/owned"
printf '%s\n' foreign >"$fixture/foreign"
printf '%s\n' name-taken >"$fixture/name"
cat >"$fixture/docker" <<'EOF'
#!/bin/sh
set -eu
case "${1:-}" in
run)
	printf '%s\n' aaaaaaaa
	;;
rm)
	[ "${2:-}" = -f ]
	case "${3:-}" in
	aaaaaaaa) rm -f "$FAKE_DOCKER_STATE/owned" ;;
	bbbbbbbb) printf '%s\n' 'foreign deletion attempted' >>"$FAKE_DOCKER_STATE/errors"; exit 1 ;;
	*) printf '%s\n' "unexpected deletion: ${3:-}" >>"$FAKE_DOCKER_STATE/errors"; exit 1 ;;
	esac
	;;
*) exit 2 ;;
esac
EOF
chmod +x "$fixture/docker"
captured_id=$(docker_run_detached_with_id "$fixture/docker" generated-name --network none)
[ "$captured_id" = aaaaaaaa ]
# The generated name is taken over after ID capture; immutable-ID cleanup must
# never remove the replacement by name.
printf '%s\n' bbbbbbbb >"$fixture/name"
FAKE_DOCKER_STATE=$fixture docker_remove_resource_id "$fixture/docker" container "$captured_id"
[ ! -e "$fixture/owned" ]
[ -e "$fixture/foreign" ]
[ -e "$fixture/name" ]
[ ! -e "$fixture/errors" ]
printf '%s\n' 'node immutable container ID race contract passed'
