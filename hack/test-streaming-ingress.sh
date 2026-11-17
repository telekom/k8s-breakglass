#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

# Render check for config/components/streaming-ingress: default renders carry no
# streaming settings; the opt-in component adds them to the Ingress or HTTPRoute.
set -euo pipefail
cd "$(dirname "$0")/.."
KUSTOMIZE=${KUSTOMIZE:-./bin/kustomize}
fail() { echo "FAIL: $*" >&2; exit 1; }
base=$($KUSTOMIZE build config/base)
gw=$($KUSTOMIZE build config/test-overlays/gateway-api)
ing=$($KUSTOMIZE build config/test-overlays/streaming-ingress)
gwi=$($KUSTOMIZE build config/test-overlays/streaming-gateway-api)
grep -q 'proxy-buffering' <<<"$base" && fail "default Ingress render must not change"
grep -q 'timeouts:' <<<"$gw" && fail "default HTTPRoute render must not change"
for a in proxy-request-buffering proxy-buffering proxy-read-timeout proxy-send-timeout proxy-body-size; do
  grep -q "nginx.ingress.kubernetes.io/$a:" <<<"$ing" || fail "Ingress lacks $a"
done
grep -q 'kind: HTTPRoute' <<<"$gwi" || fail "gateway overlay lost its HTTPRoute"
grep -q 'kind: Ingress' <<<"$gwi" && fail "gateway overlay still renders an Ingress"
grep -A3 'timeouts:' <<<"$gwi" | grep -q 'request: 0s' || fail "HTTPRoute lacks request timeout"
echo "streaming-ingress render checks passed"
