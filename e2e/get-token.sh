#!/usr/bin/env bash

# SPDX-FileCopyrightText: 2025 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

set -euo pipefail
HUB=${HUB:-breakglass-hub}
USER=${1:-test-user}
PASS=${2:-test-password}
REALM=breakglass-e2e
KUBECTL=${KUBECTL:-kubectl}

# Port-forward keycloak if not already running (default to HTTPS forwarded port)
PORT=${PORT:-8443}
CA=${CA:-}
HOST_HEADER=${HOST_HEADER:-keycloak.keycloak.svc.cluster.local}
PROTO=${PROTO:-https}
curl_args=(-s -H "Host: $HOST_HEADER" -d grant_type=password -d client_id=breakglass-ui -d username="${USER}" -d password="${PASS}")
if [ "$PROTO" = "https" ]; then
  if [ -n "$CA" ]; then curl_args+=(--cacert "$CA"); else curl_args+=(-k); fi
fi
URL_BASE="${PROTO}://localhost:${PORT}"
resp=$(curl "${curl_args[@]}" "$URL_BASE/realms/${REALM}/protocol/openid-connect/token" || true)
if [ -z "$resp" ] || ! printf '%s' "$resp" | grep -q 'access_token'; then
  # Fallback to plain HTTP port if HTTPS failed and fallback allowed
  if [ "$PROTO" = "https" ]; then
    # Fallback to HTTP alt port if HTTPS token fetch fails; default to 8080
    alt_port=${ALT_HTTP_PORT:-8080}
    URL_BASE="http://localhost:${alt_port}"
    resp=$(curl -s -H "Host: $HOST_HEADER" -d grant_type=password -d client_id=breakglass-ui -d username="${USER}" -d password="${PASS}" "$URL_BASE/realms/${REALM}/protocol/openid-connect/token" || true)
  fi
fi
token=$(printf '%s' "$resp" | jq -r '.access_token // empty' 2>/dev/null || true)
if [ -z "$token" ] || [ "${#token}" -lt 50 ]; then
  printf 'ERROR: token fetch failed for %s (len=%s) raw=%s\n' "$USER" "${#token}" "$resp" >&2
  exit 1
fi
printf '%s' "$token"
