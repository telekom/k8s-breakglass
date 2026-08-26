#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -eu

root=$(cd -- "$(dirname "$0")/.." && pwd)
PATH="$root/scripts:$PATH"
export PATH

assert_contains() {
    haystack=$1
    needle=$2
    printf '%s' "$haystack" | grep -F "$needle" >/dev/null || {
        printf 'expected %s to contain %s\n' "$haystack" "$needle" >&2
        exit 1
    }
}

workload-debug --help | grep -F 'kube-api' >/dev/null
debug-dns --help | grep -F 'Usage:' >/dev/null
debug-tls --help | grep -F 'Usage:' >/dev/null
debug-http --help | grep -F 'Usage:' >/dev/null
debug-kube-api --help | grep -F 'Usage:' >/dev/null
debug-report --help | grep -F 'Usage:' >/dev/null

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
if debug-tls --timeout 0 example.invalid >/dev/null 2>&1; then
    printf '%s\n' 'debug-tls accepted an unbounded timeout' >&2
    exit 1
fi
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
