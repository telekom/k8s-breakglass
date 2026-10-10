#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$root"
for tool in kind kubectl docker go; do command -v "$tool" >/dev/null; done
docker info >/dev/null
name="audit-delivery-$(date +%s)-$$"
work=".scratch/$name"
umask 077
mkdir -p .scratch
mkdir "$work"
export TMPDIR="$root/$work"
export KUBECONFIG="$root/$work/kubeconfig"
created=false
cleanup() {
  result=$?
  if [[ $created == true ]]; then
    kind delete cluster --name "$name" || result=1
  fi
  exit "$result"
}
trap cleanup EXIT
if kind get clusters | grep -Fxq "$name"; then
  echo "Refusing an existing cluster name" >&2
  exit 1
fi
created=true
kind create cluster --name "$name" --image \
  kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5 \
  --kubeconfig "$KUBECONFIG" --wait 120s
kubectl apply -f config/crd/bases/
kubectl apply -f e2e/fixtures/audit-delivery-broker.yaml
kubectl -n audit-delivery rollout status deployment/broker --timeout=180s
AUDIT_DELIVERY_E2E=true go test -race -v ./e2e/auditdelivery -count=1 -timeout=8m
