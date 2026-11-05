#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
case "$(kubectl config current-context)" in
  kind-*) ;;
  *) echo 'Convergence E2E requires a disposable kind cluster' >&2; exit 1 ;;
esac
if kubectl get namespace flux-system >/dev/null 2>&1; then
  echo 'Refusing to overwrite an existing Flux installation' >&2
  exit 1
fi
manifest=$(mktemp)
trap 'rm -f "$manifest"' EXIT
curl --fail --silent --show-error --location \
  https://github.com/fluxcd/flux2/releases/download/v2.10.0/install.yaml -o "$manifest"
printf '%s  %s\n' a8c838ccd9be5d30eba9df87cd229b7c4eb80c0049fba1bc3b9840829f267f28 "$manifest" | shasum -a 256 -c -
kubectl apply --server-side -f "$manifest"
kubectl -n flux-system rollout status deployment/source-controller --timeout=180s
kubectl -n flux-system rollout status deployment/helm-controller --timeout=180s
