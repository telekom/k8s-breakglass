#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -eu

root=$(cd -- "$(dirname -- "$0")/.." && pwd)

fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT HUP INT TERM

cat >"$fixture/ip" <<'EOF'
#!/bin/sh
case "$*" in
  '-o address show') printf '%s\n' '1: lo    inet 127.0.0.1/8 scope host lo' ;;
  '-o route show') printf '%s\n' 'default via 192.0.2.1 dev eth0' ;;
  '-o rule show') printf '%s\n' '0: from all lookup local' ;;
  *) exit 2 ;;
esac
EOF
cat >"$fixture/kubestr" <<'EOF'
#!/bin/sh
[ "${1:-}" = version ] || exit 2
printf '%s\n' 'Version: v0.4.49'
EOF
cat >"$fixture/pwru" <<'EOF'
#!/bin/sh
[ "${1:-}" = --version ] || exit 2
printf '%s\n' 'pwru version v1.0.12'
EOF
chmod +x "$fixture/ip" "$fixture/kubestr" "$fixture/pwru"

if sh "$root/scripts/net-report" --not-an-option >/dev/null 2>&1; then
	printf '%s\n' 'net-report accepted an unknown option' >&2
	exit 1
fi

wrapped=$(sh "$root/scripts/net-debug" printf '%s' 'wrapper-executed')
test "$wrapped" = 'wrapper-executed'
if PATH=/usr/bin:/bin sh "$root/scripts/net-debug" does-not-exist >/dev/null 2>&1; then
	printf '%s\n' 'net-debug accepted an unknown command' >&2
	exit 1
fi

version=$(NETWORK_DEBUG_VERSION=0.1.0 sh "$root/scripts/net-report" --version)
test "$version" = 'net-report 0.1.0'
intent=$(NETWORK_DEBUG_INTENT=network-diagnostics sh "$root/scripts/net-report" | sed -n '2p')
test "$intent" = 'intent network-diagnostics'

# Exercise the report against deterministic command fixtures. These assertions
# validate the public runtime output, not implementation files.
first=$(PATH="$fixture:/usr/bin:/bin" NETWORK_DEBUG_VERSION=test sh "$root/scripts/net-report")
second=$(PATH="$fixture:/usr/bin:/bin" NETWORK_DEBUG_VERSION=test sh "$root/scripts/net-report")
test "$first" = "$second"
printf '%s\n' "$first" | grep -F '1: lo    inet 127.0.0.1/8 scope host lo' >/dev/null
printf '%s\n' "$first" | grep -F 'default via 192.0.2.1 dev eth0' >/dev/null
printf '%s\n' "$first" | grep -F '0: from all lookup local' >/dev/null
printf '%s\n' "$first" | grep -E '^kubestr[[:space:]]+kubestr v0\.4\.49$' >/dev/null
printf '%s\n' "$first" | grep -E '^pwru[[:space:]]+pwru v1\.0\.12$' >/dev/null
echo 'network-debug image checks passed'
