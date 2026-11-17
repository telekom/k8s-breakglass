#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

# Opt-in: install ingress-nginx in the single-cluster kind hub and expose the
# breakglass API through a streaming-ready Ingress (the annotations of
# config/components/streaming-ingress), so the recorded terminal can be run
# through a proxy that drops response trailers.
#
#   bash e2e/kind-setup-single.sh                    # hub as usual
#   bash e2e/ingress-nginx.sh                        # then this
#   export E2E_INGRESS_URL=http://localhost:8088     # then run the e2e tests
#
# The script starts a background port-forward to the controller on :8088.
set -euo pipefail
KUBECTL=${KUBECTL:-kubectl}
KUBECONFIG=${HUB_KUBECONFIG:-${KUBECONFIG:-}}
export KUBECONFIG
NGINX_VERSION=${INGRESS_NGINX_VERSION:-controller-v1.12.1}
PORT=${E2E_INGRESS_PORT:-8088}

$KUBECTL apply -f "https://raw.githubusercontent.com/kubernetes/ingress-nginx/${NGINX_VERSION}/deploy/static/provider/kind/deploy.yaml"
$KUBECTL -n ingress-nginx rollout status deployment/ingress-nginx-controller --timeout=180s
# The admission webhook may lag behind the rollout.
for _ in $(seq 1 30); do
  $KUBECTL -n ingress-nginx get endpoints ingress-nginx-controller-admission -o jsonpath='{.subsets[0].addresses[0].ip}' 2>/dev/null | grep -q . && break
  sleep 2
done
# Same annotations as config/components/streaming-ingress (no host: matched by IP).
$KUBECTL apply -f - <<YAML
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: breakglass-e2e-streaming
  namespace: breakglass-system
  annotations:
    nginx.ingress.kubernetes.io/proxy-request-buffering: "off"
    nginx.ingress.kubernetes.io/proxy-buffering: "off"
    nginx.ingress.kubernetes.io/proxy-http-version: "1.1"
    nginx.ingress.kubernetes.io/proxy-read-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-send-timeout: "3600"
    nginx.ingress.kubernetes.io/proxy-body-size: "512m"
spec:
  ingressClassName: nginx
  rules:
    - http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: breakglass-breakglass
                port:
                  number: 8080
YAML
nohup "$KUBECTL" -n ingress-nginx port-forward svc/ingress-nginx-controller "$PORT:80" >/dev/null 2>&1 &
echo "E2E_INGRESS_URL=http://localhost:$PORT"
