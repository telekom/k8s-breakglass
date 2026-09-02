#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -eu

root=$(cd -- "$(dirname "$0")/.." && pwd)
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT HUP INT TERM
cat >"$fixture/curl" <<'EOF'
#!/bin/sh
set -eu
echo "$*" >"${WORKLOAD_DEBUG_CURL_LOG:?}"
EOF
cat >"$fixture/openssl" <<'EOF'
#!/bin/sh
set -eu
echo "$*" >"${WORKLOAD_DEBUG_OPENSSL_LOG:?}"
EOF
chmod +x "$fixture/curl" "$fixture/openssl"
PATH="$fixture:$root/scripts:$PATH" WORKLOAD_DEBUG_CURL_LOG="$fixture/curl.log" \
    WORKLOAD_DEBUG_MAX_BYTES=1048576 debug-http https://example.test >/dev/null
grep -F -- '--dump-header' "$fixture/curl.log" >/dev/null
PATH="$fixture:$root/scripts:$PATH" WORKLOAD_DEBUG_OPENSSL_LOG="$fixture/openssl.log" \
    debug-tls '[2001:db8::1]:443' >/dev/null
grep -F -- '-connect [2001:db8::1]:443' "$fixture/openssl.log" >/dev/null
echo 'command safety tests passed'
