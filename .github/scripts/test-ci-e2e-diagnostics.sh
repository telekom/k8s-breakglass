#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

source "$(dirname "$0")/ci-e2e-diagnostics.sh"

tmp_dir="$(mktemp -d)"
trap 'rm -rf "$tmp_dir"' EXIT
redacted_output="$tmp_dir/redacted.log"
bounded_output="$tmp_dir/bounded.log"
pem_tail_output="$tmp_dir/pem-tail.log"

printf '%s\n' \
  'Authorization: Bearer visible-token' \
	'Set-Cookie: session=visible-cookie; Secure; HttpOnly' \
	'Cookie: session=visible-request-cookie' \
	'X-Api-Key: visible-header-key' \
	'X-Auth-Token: visible-header-token' \
  'password=visible-password' \
  'password = "visible password with spaces, braces } and # text"' \
  'api_key: ''visible yaml key with spaces # inside quotes''' \
  '{"client_secret":"visible-json-secret, with spaces and } braces","status":"useful"}' \
  'token=visible-inline-token status=healthy' \
  '-----BEGIN RSA PRIVATE KEY-----' \
  'visible-private-key-material' \
  '-----END RSA PRIVATE KEY-----' \
  'user=operator@example.com' \
  'status=healthy component=controller latency=12ms' \
  'eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJvcGVyYXRvciJ9.qwertyuiopasdfghjklzxcvbnm123456' \
  | ci_write_bounded_redacted_file "$redacted_output" 20 4096

test -z "$(grep -E 'visible|operator@example.com|eyJhbGci' "$redacted_output" || true)"
test "$(grep -c '\[REDACTED' "$redacted_output")" -eq 13
grep -Fq '"status":"useful"' "$redacted_output"
grep -Fq 'status=healthy component=controller latency=12ms' "$redacted_output"
grep -Fq 'token=[REDACTED] status=healthy' "$redacted_output"
test -z "$(grep -E 'END .*PRIVATE KEY|private-key-material' "$redacted_output" || true)"

seq 1 20 | ci_write_bounded_redacted_file "$bounded_output" 5 8
test "$(wc -l < "$bounded_output" | tr -d ' ')" -le 5
test "$(wc -c < "$bounded_output" | tr -d ' ')" -le 8

{
  printf '%s\n' '-----BEGIN OPENSSH PRIVATE KEY-----'
  seq 1 20 | sed 's/^/private-key-tail-/'
  printf '%s\n' '-----END OPENSSH PRIVATE KEY-----' 'useful final diagnostic'
} | ci_write_bounded_redacted_file "$pem_tail_output" 5 4096
test -z "$(grep -E 'private-key-tail|PRIVATE KEY' "$pem_tail_output" || true)"
grep -Fq 'useful final diagnostic' "$pem_tail_output"
