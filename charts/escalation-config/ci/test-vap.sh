#!/usr/bin/env bash
set -euo pipefail

values=charts/escalation-config/ci/test-values.yaml
helm_output=$(helm template test-release charts/escalation-config \
  --values "$values" \
  --set validatingAdmissionPolicy.enabled=true \
  --kube-version 1.30.0)

resource_count=$(printf '%s\n' "$helm_output" | rg -c '^kind: ValidatingAdmissionPolicy$|^kind: ValidatingAdmissionPolicyBinding$' || true)
test "$resource_count" = 8
printf '%s\n' "$helm_output" | rg -q 'resources: \["breakglasssessions", "breakglasssessions/status"\]'
printf '%s\n' "$helm_output" | rg -q 'oldObject == null \|\| object.spec == oldObject.spec'
printf '%s\n' "$helm_output" | rg -q 'oldObject.status.state == object.status.state'

kustomize_bin=${KUSTOMIZE_BIN:-./bin/kustomize}
if [[ ! -x "$kustomize_bin" ]]; then
  kustomize_bin=kustomize
fi
kustomize_output=$("$kustomize_bin" build config/test-overlays/vap)
printf '%s\n' "$kustomize_output" | rg -q -U 'resources:\n\s+- breakglasssessions\n\s+- breakglasssessions/status'
printf '%s\n' "$kustomize_output" | rg -q 'oldObject == null \|\| object.spec == oldObject.spec'
printf '%s\n' "$kustomize_output" | rg -q 'oldObject.status.state == object.status.state'

printf '%s\n' "VAP render coverage passed: Helm=8 resources, status subresource covered in Helm and Kustomize"
