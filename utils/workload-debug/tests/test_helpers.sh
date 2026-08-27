#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -eu

root=$(cd -- "$(dirname "$0")/.." && pwd)
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT HUP INT TERM
cat >"$fixture/nslookup" <<'EOF'
#!/bin/sh
if [ "$#" -ne 1 ] || { [ "$1" != localhost ] && [ "$1" != large ]; }; then
  exit 2
fi
if [ "$1" = large ]; then
  i=0
  while [ "$i" -lt 1024 ]; do printf x; i=$((i + 1)); done
  exit 0
fi
printf '%s\n' 'Name: localhost' 'Address: 127.0.0.1'
EOF
chmod +x "$fixture/nslookup"
no_nslookup="$fixture/no-nslookup"
mkdir -p "$no_nslookup"
cat >"$no_nslookup/getent" <<'EOF'
#!/bin/sh
[ "$1" = hosts ] || exit 2
printf '%s\n' '127.0.0.1 localhost'
EOF
chmod +x "$no_nslookup/getent"
cat >"$fixture/openssl" <<'EOF'
#!/bin/sh
printf '%s\n' 'fake TLS client'
EOF
chmod +x "$fixture/openssl"

PATH="$root/scripts:$fixture:$PATH"
export PATH

assert_contains() {
    haystack=$1
    needle=$2
    printf '%s' "$haystack" | grep -F -- "$needle" >/dev/null || {
        printf 'expected %s to contain %s\n' "$haystack" "$needle" >&2
        exit 1
    }
}

assert_not_contains() {
    haystack=$1
    needle=$2
    if printf '%s' "$haystack" | grep -F -- "$needle" >/dev/null; then
        printf 'did not expect %s to contain %s\n' "$haystack" "$needle" >&2
        exit 1
    fi
}

wrapped=$(workload-debug report)
assert_contains "$wrapped" 'workload-debug report'
assert_contains "$wrapped" 'checks_failed: 0'

dns_result=$(debug-dns localhost)
assert_contains "$dns_result" '127.0.0.1'
debug-report --json | jq -e '.schema_version == 1 and .status == "ready" and .checks == [] and .checks_failed == 0' >/dev/null

if debug-http ftp://invalid.example >/dev/null 2>&1; then
    printf '%s\n' 'debug-http accepted an unsupported URL scheme' >&2
    exit 1
fi
if debug-http --method DELETE https://invalid.example >/dev/null 2>&1; then
    printf '%s\n' 'debug-http accepted a mutating method' >&2
    exit 1
fi
if debug-http --timeout 0 https://invalid.example >/dev/null 2>&1; then
    printf '%s\n' 'debug-http accepted an unbounded timeout' >&2
    exit 1
fi
if debug-http --timeout 301 https://invalid.example >/dev/null 2>&1; then
    printf '%s\n' 'debug-http accepted an excessive timeout' >&2
    exit 1
fi
if WORKLOAD_DEBUG_MAX_BYTES=0 debug-http https://invalid.example >/dev/null 2>&1; then
    printf '%s\n' 'debug-http accepted an unbounded response size' >&2
    exit 1
fi

# Curl can reject a malformed URL before opening the header FIFO. The bounded
# response helper must return promptly rather than leaving its reader blocked.
malformed_status=0
timeout 5 debug-http 'http://[::1' >"$fixture/malformed-output" 2>"$fixture/malformed-error" || malformed_status=$?
[ "$malformed_status" -ne 124 ] || {
  printf '%s\n' 'debug-http hung after curl rejected a malformed URL' >&2
  exit 1
}

# DNS/TLS diagnostic output is finite even when a peer emits an unusually
# large response. The command returns failure after emitting the configured
# bound, rather than buffering unbounded output.
dns_large_status=0
if WORKLOAD_DEBUG_MAX_OUTPUT_BYTES=64 debug-dns large >"$fixture/dns-large-output" 2>"$fixture/dns-large-error"; then
  printf '%s\n' 'debug-dns accepted output over its configured bound' >&2
  exit 1
else
  dns_large_status=$?
fi
[ "$dns_large_status" -ne 0 ] || exit 1
[ "$(wc -c <"$fixture/dns-large-output")" -eq 64 ] || {
  printf '%s\n' 'debug-dns did not emit exactly its configured output bound' >&2
  exit 1
}

# Exercise the actual streaming limiter with an unknown-length response. The
# fake curl emits 1 KiB without Content-Length, so --max-filesize alone would
# not stop it; the helper must return a failure after exactly 64 body bytes.
cat >"$fixture/curl" <<'EOF'
#!/bin/sh
set -eu
header=
output=-
auth_header=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --dump-header) header=$2; shift 2 ;;
        --output) output=$2; shift 2 ;;
        --header) auth_header=$2; shift 2 ;;
        *) shift ;;
    esac
done
if [ "${OVERSIZED_HEADERS:-0}" = 1 ]; then
    header_body=
    i=0
    while [ "$i" -lt 1024 ]; do header_body=${header_body}x; i=$((i + 1)); done
    printf 'HTTP/1.1 200 OK\r\nX-Fixture-Large: %s\r\n\r\n' "$header_body" >"$header"
else
    printf 'HTTP/1.1 200 OK\r\n\r\n' >"$header"
fi
if [ -n "${EXPECTED_AUTH_HEADER:-}" ]; then
    case "$auth_header" in
        @*) grep -Fx -- "$EXPECTED_AUTH_HEADER" "${auth_header#@}" >/dev/null || exit 3 ;;
        *) exit 3 ;;
    esac
fi
body=
i=0
while [ "$i" -lt 1024 ]; do body=${body}x; i=$((i + 1)); done
if [ "$output" = - ]; then printf '%s' "$body"; else printf '%s' "$body" >"$output"; fi
EOF
chmod +x "$fixture/curl"
limited_output=$fixture/limited-output
limited_error=$fixture/limited-error
if WORKLOAD_DEBUG_MAX_BYTES=64 debug-http http://fixture/chunked >"$limited_output" 2>"$limited_error"; then
    printf '%s\n' 'debug-http accepted an unknown-length response over the configured limit' >&2
    exit 1
fi
header_bytes=$(printf 'HTTP/1.1 200 OK\r\n\r\n' | wc -c)
output_bytes=$(wc -c <"$limited_output")
[ "$output_bytes" -eq $((header_bytes + 64)) ] || {
    printf 'streaming limiter emitted %s bytes, expected %s\n' "$output_bytes" "$((header_bytes + 64))" >&2
    exit 1
}
grep -F 'response body exceeds 64 bytes' "$limited_error" >/dev/null

# Header bytes are bounded independently of the body. An oversized header is
# rejected before any response bytes are emitted and temporary state is
# removed.
oversized_output=$fixture/oversized-output
oversized_error=$fixture/oversized-error
if OVERSIZED_HEADERS=1 TMPDIR="$fixture" WORKLOAD_DEBUG_MAX_BYTES=64 \
    debug-http http://fixture/oversized >"$oversized_output" 2>"$oversized_error"; then
    printf '%s\n' 'debug-http accepted oversized response headers' >&2
    exit 1
fi
[ "$(wc -c <"$oversized_output")" -eq 0 ] || {
    printf '%s\n' 'oversized response headers were emitted' >&2
    exit 1
}
grep -F 'response headers exceed 64 bytes' "$oversized_error" >/dev/null
for leftover in "$fixture"/workload-debug-response.*; do
    [ -e "$leftover" ] || continue
    printf '%s\n' 'header limiter left temporary data behind' >&2
    exit 1
done

# Exercise the token-authenticated debug-kube-api path against the same
# unknown-length response. The fake curl requires the header file to contain
# the expected credential, while the limiter still has to stop the response
# at the configured bound and remove both temporary directories.
token_file="$fixture/token"
printf '%s\n' 'fixture-token' >"$token_file"
token_limited_output=$fixture/token-limited-output
token_limited_error=$fixture/token-limited-error
if EXPECTED_AUTH_HEADER='Authorization: Bearer fixture-token' TMPDIR="$fixture" WORKLOAD_DEBUG_MAX_BYTES=64 \
    debug-kube-api --server http://fixture --token "$token_file" /chunked \
    >"$token_limited_output" 2>"$token_limited_error"; then
    printf '%s\n' 'token-authenticated debug-kube-api accepted an unknown-length response over the limit' >&2
    exit 1
fi
token_output_bytes=$(wc -c <"$token_limited_output")
[ "$token_output_bytes" -eq $((header_bytes + 64)) ] || {
    printf 'token streaming limiter emitted %s bytes, expected %s\n' "$token_output_bytes" "$((header_bytes + 64))" >&2
    exit 1
}
grep -F 'response body exceeds 64 bytes' "$token_limited_error" >/dev/null
assert_not_contains "$(cat "$token_limited_output" "$token_limited_error")" 'fixture-token'
for leftover in "$fixture"/workload-debug-auth.* "$fixture"/workload-debug-response.*; do
    [ -e "$leftover" ] || continue
    printf '%s\n' 'token-authenticated limiter left temporary data behind' >&2
    exit 1
done

# The auth file contains the actual bearer credential, not a redacted marker,
# while remaining private to the helper and disappearing after the request.
# The fake curl above validates that it received the exact header value.

auth_oversized_output=$fixture/auth-oversized-output
auth_oversized_error=$fixture/auth-oversized-error
if OVERSIZED_HEADERS=1 EXPECTED_AUTH_HEADER='Authorization: Bearer fixture-token' \
    TMPDIR="$fixture" WORKLOAD_DEBUG_MAX_BYTES=64 \
    debug-kube-api --server http://fixture --token "$token_file" /oversized \
    >"$auth_oversized_output" 2>"$auth_oversized_error"; then
    printf '%s\n' 'token-authenticated debug-kube-api accepted oversized response headers' >&2
    exit 1
fi
[ "$(wc -c <"$auth_oversized_output")" -eq 0 ] || {
    printf '%s\n' 'oversized authenticated response headers were emitted' >&2
    exit 1
}
grep -F 'response headers exceed 64 bytes' "$auth_oversized_error" >/dev/null

# A read-only root filesystem commonly makes TMPDIR unusable. The bounded
# helper must choose an available ephemeral fallback instead of failing before
# it can execute the request. The normal host /tmp fallback is the behavioral
# oracle here; no source or implementation file is inspected.
readonly_tmp=$fixture/readonly-tmp
mkdir "$readonly_tmp"
chmod 0555 "$readonly_tmp"
if ! TMPDIR="$readonly_tmp" WORKLOAD_DEBUG_MAX_BYTES=2048 debug-http http://fixture/short >"$fixture/fallback-output"; then
    printf '%s\n' 'debug-http failed when TMPDIR was read-only despite an available fallback' >&2
    exit 1
fi
assert_contains "$(cat "$fixture/fallback-output")" 'HTTP/1.1 200 OK'
assert_contains "$(cat "$fixture/fallback-output")" 'x'
chmod 0755 "$readonly_tmp"
for leftover in "$readonly_tmp"/workload-debug-response.*; do
    [ -e "$leftover" ] || continue
    printf '%s\n' 'bounded helper left temporary data in an unusable TMPDIR' >&2
    exit 1
done

if debug-tls --timeout 0 example.invalid >/dev/null 2>&1; then
    printf '%s\n' 'debug-tls accepted an unbounded timeout' >&2
    exit 1
fi
tls_host=$(debug-tls example.invalid:443)
assert_contains "$tls_host" 'TLS endpoint: example.invalid:443'
tls_ipv6=$(debug-tls '[2001:db8::1]:443')
assert_contains "$tls_ipv6" 'TLS endpoint: 2001:db8::1:443'
if debug-dns --server '127.0.0.1#0' example.invalid >/dev/null 2>&1; then
    printf '%s\n' 'debug-dns accepted an invalid resolver port' >&2
    exit 1
fi
if PATH="$root/scripts:$no_nslookup" debug-dns --server 127.0.0.1 example.invalid >/dev/null 2>"$fixture/dns-server-error"; then
    printf '%s\n' 'debug-dns accepted --server without nslookup' >&2
    exit 1
fi
assert_contains "$(cat "$fixture/dns-server-error")" '--server requires nslookup'
if debug-tls 2001:db8::1 >/dev/null 2>&1; then
    printf '%s\n' 'debug-tls accepted an ambiguous bare IPv6 endpoint' >&2
    exit 1
fi
if debug-kube-api /version >/dev/null 2>&1; then
    printf '%s\n' 'debug-kube-api unexpectedly used controller metadata' >&2
    exit 1
fi
if WORKLOAD_DEBUG_TIMEOUT=0 debug-kube-api --server https://invalid.example >/dev/null 2>&1; then
    printf '%s\n' 'debug-kube-api accepted an unbounded timeout' >&2
    exit 1
fi
if WORKLOAD_DEBUG_MAX_BYTES=0 debug-kube-api --server https://invalid.example >/dev/null 2>&1; then
    printf '%s\n' 'debug-kube-api accepted an unbounded response size' >&2
    exit 1
fi

report=$(debug-report)
assert_contains "$report" 'workload-debug report'
assert_contains "$report" 'kubernetes service environment:'
assert_contains "$report" 'checks_failed: 0'

printf '%s\n' 'workload-debug helper tests passed'
