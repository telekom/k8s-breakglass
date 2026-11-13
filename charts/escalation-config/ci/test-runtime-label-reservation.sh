#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

# The chart's runtimeLabelReservation policy must render the same policy as
# config/components/runtime-label-reservation (the envtest-covered source), be
# off by default, refuse Kubernetes < 1.30 and require a controller user.
set -euo pipefail

chart=charts/escalation-config
values=$chart/ci/test-values.yaml
kustomize_bin=${KUSTOMIZE_BIN:-./bin/kustomize}
[[ -x "$kustomize_bin" ]] || kustomize_bin=kustomize
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

if helm template t "$chart" --values "$values" --kube-version 1.30.0 | grep -q breakglass-runtime-label-reservation; then
  echo "runtimeLabelReservation must be off by default" >&2
  exit 1
fi
if helm template t "$chart" --values "$values" --set runtimeLabelReservation.enabled=true --kube-version 1.29.0 >/dev/null 2>&1; then
  echo "runtimeLabelReservation must refuse Kubernetes < 1.30" >&2
  exit 1
fi
if helm template t "$chart" --values "$values" --set runtimeLabelReservation.enabled=true \
  --set 'runtimeLabelReservation.controllerUsers=null' --kube-version 1.30.0 >/dev/null 2>&1; then
  echo "runtimeLabelReservation must require controllerUsers" >&2
  exit 1
fi

helm template t "$chart" --values "$values" --set runtimeLabelReservation.enabled=true \
  --show-only templates/runtime-label-reservation.yaml --kube-version 1.30.0 >"$tmp/helm-default.yaml"
helm template t "$chart" --values "$values" --set runtimeLabelReservation.enabled=true \
  --set 'runtimeLabelReservation.controllerUsers={breakglass-hub}' \
  --show-only templates/runtime-label-reservation.yaml --kube-version 1.30.0 >"$tmp/helm-custom.yaml"
"$kustomize_bin" build config/test-overlays/runtime-label-reservation >"$tmp/kustomize.yaml"

python3 - "$tmp" <<'EOF'
import json, sys, yaml

tmp = sys.argv[1]

def load(name):
    docs = {}
    for doc in yaml.safe_load_all(open(f"{tmp}/{name}")):
        if doc and doc["kind"].startswith("ValidatingAdmissionPolicy"):
            for v in doc["spec"].get("variables", []) + doc["spec"].get("validations", []):
                # kustomize re-folds block scalars; CEL ignores the whitespace.
                v["expression"] = " ".join(v["expression"].split())
                if v.get("name", "").endswith("Users"):
                    v["expression"] = json.loads(v["expression"])
            docs[doc["kind"]] = doc["spec"]
    return docs

kustomize, helm, custom = load("kustomize.yaml"), load("helm-default.yaml"), load("helm-custom.yaml")
assert set(kustomize) == {"ValidatingAdmissionPolicy", "ValidatingAdmissionPolicyBinding"}, kustomize.keys()
assert helm == kustomize, "chart and kustomize component render different policies"
users = {v["name"]: v["expression"] for v in custom["ValidatingAdmissionPolicy"]["variables"]}
assert users["controllerUsers"] == ["breakglass-hub"], users["controllerUsers"]
print("runtime label reservation: chart matches kustomize component")
EOF
