#!/usr/bin/env bash
set -euo pipefail

values=charts/escalation-config/ci/test-values.yaml
helm_output=$(helm template test-release charts/escalation-config \
  --values "$values" \
  --set validatingAdmissionPolicy.enabled=true \
  --kube-version 1.30.0)

resource_count=$(printf '%s\n' "$helm_output" | grep -Ec '^(kind: ValidatingAdmissionPolicy|kind: ValidatingAdmissionPolicyBinding)$' || true)
test "$resource_count" = 8

check_session_policy() {
  awk '
    /^---$/ { in_policy = 0; in_rules = 0 }
    /^[[:space:]]*name: breakglass-session-validation$/ { in_policy = 1 }
    in_policy && /^[[:space:]]*resources:/ {
      in_rules = 1
      if ($0 ~ /breakglasssessions/) parent = 1
      if ($0 ~ /breakglasssessions\/status/) status = 1
    }
    in_policy && in_rules && /breakglasssessions$/ { parent = 1 }
    in_policy && in_rules && /breakglasssessions\/status$/ { status = 1 }
    in_policy && /^[[:space:]]*validations:/ { in_rules = 0 }
    in_policy && /oldObject == null \|\| object.spec == oldObject.spec/ { spec = 1 }
    in_policy && /oldObject.status.state == object.status.state/ { state = 1 }
    END { exit(parent && status && spec && state ? 0 : 1) }
  '
}

printf '%s\n' "$helm_output" | check_session_policy

kustomize_bin=${KUSTOMIZE_BIN:-./bin/kustomize}
if [[ ! -x "$kustomize_bin" ]]; then
  kustomize_bin=kustomize
fi
kustomize_output=$("$kustomize_bin" build config/test-overlays/vap)
printf '%s\n' "$kustomize_output" | check_session_policy

printf '%s\n' "VAP render coverage passed: Helm=8 resources, status subresource covered in Helm and Kustomize"
