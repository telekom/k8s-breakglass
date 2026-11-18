#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

# Opt-in: install ingress-nginx in the single-cluster kind hub and expose the
# breakglass API through the Ingress rendered from
# config/components/streaming-ingress, so the recorded terminal runs through a
# proxy that drops response trailers. Used by the artifacts-local CI lane.
#
#   bash e2e/kind-setup-single.sh                    # hub as usual
#   bash e2e/ingress-nginx.sh                        # then this
#   export E2E_INGRESS_URL=http://localhost:8088     # then run the e2e tests
#
# Starts a keepalive port-forward to the ingress controller on :8088 and, in
# CI, writes E2E_INGRESS_URL to $GITHUB_ENV.
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
# shellcheck source=e2e/lib/common.sh
source "$root/e2e/lib/common.sh"
# shellcheck source=e2e/lib/port-forward.sh
source "$root/e2e/lib/port-forward.sh"
KUBECTL=${KUBECTL:-kubectl}
KUBECONFIG=${HUB_KUBECONFIG:-${KUBECONFIG:-}}
export KUBECONFIG
NGINX_VERSION=${INGRESS_NGINX_VERSION:-controller-v1.12.1}
PORT=${E2E_INGRESS_PORT:-8088}

# The kind provider manifest schedules the controller on nodes labelled
# ingress-ready=true.
$KUBECTL label nodes --all ingress-ready=true --overwrite
for attempt in 1 2 3; do
  $KUBECTL apply -f "https://raw.githubusercontent.com/kubernetes/ingress-nginx/${NGINX_VERSION}/deploy/static/provider/kind/deploy.yaml" && break
  [[ $attempt -lt 3 ]] || exit 1
  sleep 10
done
# nginx re-arms client_body_timeout (default 60s) while it waits for request
# body: an idle terminal would be cut. This is controller-wide (no annotation);
# docs/terminal-recording.md documents it with the component.
$KUBECTL -n ingress-nginx patch configmap ingress-nginx-controller --type merge -p '{"data":{"client-body-timeout":"3600"}}'
$KUBECTL -n ingress-nginx rollout status deployment/ingress-nginx-controller --timeout=300s
$KUBECTL -n ingress-nginx wait --for=condition=complete job/ingress-nginx-admission-patch --timeout=180s

# The Ingress is the shipped component's render, pointed at this hub's Service
# and matched without a host.
ingress_doc=$($KUBECTL kustomize "$root/config/test-overlays/streaming-ingress" | python3 -c '
import sys
docs = sys.stdin.read().split("\n---\n")
print(next(d for d in docs if "\nkind: Ingress\n" in "\n" + d + "\n"))
')
ingress=$($KUBECTL create --dry-run=client -o json -f - <<<"$ingress_doc" | python3 -c '
import json, sys
ing = json.load(sys.stdin)
ing["metadata"] = {"name": "breakglass-e2e-streaming", "namespace": "breakglass-system", "annotations": ing["metadata"]["annotations"]}
ing["spec"]["ingressClassName"] = "nginx"
rule = ing["spec"]["rules"][0]
rule.pop("host", None)
rule["http"]["paths"][0]["backend"]["service"] = {"name": "breakglass-breakglass", "port": {"number": 8080}}
print(json.dumps(ing))
')
# The admission webhook may lag behind the rollout.
for attempt in $(seq 1 30); do
  if $KUBECTL apply -f - <<<"$ingress"; then break; fi
  [[ $attempt -lt 30 ]] || exit 1
  sleep 2
done
start_keepalive_port_forward ingress-nginx ingress-nginx-controller "$PORT" 80
wait_for_http "http://localhost:$PORT/api/config" 90 "breakglass API through ingress-nginx"
echo "E2E_INGRESS_URL=http://localhost:$PORT"
if [[ -n "${GITHUB_ENV:-}" ]]; then
  echo "E2E_INGRESS_URL=http://localhost:$PORT" >> "$GITHUB_ENV"
fi
