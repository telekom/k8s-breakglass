#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -eu

root=$(cd -- "$(dirname "$0")/.." && pwd)
fixture=$(mktemp -d)
trap 'rm -rf "$fixture"' EXIT HUP INT TERM
cat >"$fixture/curl" <<'EOF'
#!/bin/sh
set -eu
log=${WORKLOAD_DEBUG_CURL_LOG:?}
echo "$*" >"$log"
header_file=
dump_file=
while [ "$#" -gt 0 ]; do
    case "$1" in
        --header) case "$2" in @*) header_file=${2#@} ;; esac; shift 2 ;;
        --dump-header) dump_file=$2; shift 2 ;;
        *) shift ;;
    esac
done
[ -n "$dump_file" ] && echo 'HTTP/1.1 200 OK' >"$dump_file"
[ -z "$header_file" ] || cat "$header_file" >"${log}.header"
echo fixture
EOF
chmod +x "$fixture/curl"
token_file=$fixture/token
echo real-test-token >"$token_file"
PATH="$root/scripts:$fixture:$PATH" WORKLOAD_DEBUG_CURL_LOG="$fixture/curl.log" \
    KUBE_TOKEN_FILE="$token_file" debug-kube-api --server https://api.example.test /version >/dev/null
if grep -F real-test-token "$fixture/curl.log" >/dev/null; then
    echo 'debug-kube-api leaked token in curl argv' >&2
    exit 1
fi
if [ -e "$fixture/curl.log.header" ]; then
    echo 'debug-kube-api sent an implicit token to an overridden server' >&2
    exit 1
fi
PATH="$root/scripts:$fixture:$PATH" WORKLOAD_DEBUG_CURL_LOG="$fixture/curl-auth.log" \
    KUBE_TOKEN_FILE="$token_file" debug-kube-api --server https://api.example.test \
    --token "$token_file" /version >/dev/null
if grep -F real-test-token "$fixture/curl-auth.log" >/dev/null; then
    echo 'debug-kube-api leaked token in authenticated curl argv' >&2
    exit 1
fi
grep -Fx 'Authorization: Bearer real-test-token' "$fixture/curl-auth.log.header" >/dev/null
echo 'token handling test passed'
