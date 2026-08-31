#!/bin/sh
set -eu

root=$(cd -- "$(dirname "$0")/.." && pwd)
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT HUP INT TERM
cat >"$fixture/limit-response" <<'EOF'
#!/bin/sh
set -eu
echo "$1" >"${WORKLOAD_DEBUG_LIMIT_LOG:?}"
shift
exec "$@"
EOF
cat >"$fixture/curl" <<'EOF'
#!/bin/sh
echo curl-called
EOF
cat >"$fixture/openssl" <<'EOF'
#!/bin/sh
set -eu
echo "$*" >"${WORKLOAD_DEBUG_OPENSSL_LOG:?}"
EOF
chmod +x "$fixture/limit-response" "$fixture/curl" "$fixture/openssl"
PATH="$fixture:$root/scripts:$PATH" WORKLOAD_DEBUG_LIMIT_LOG="$fixture/limit.log" \
    debug-http https://example.test >/dev/null
grep -Fx 1048576 "$fixture/limit.log" >/dev/null
PATH="$fixture:$root/scripts:$PATH" WORKLOAD_DEBUG_OPENSSL_LOG="$fixture/openssl.log" \
    debug-tls '[2001:db8::1]:443' >/dev/null
grep -F -- '-connect [2001:db8::1]:443' "$fixture/openssl.log" >/dev/null
echo 'command safety tests passed'
