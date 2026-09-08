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
      if ($0 ~ /"breakglasssessions"/ || $0 ~ /^[[:space:]]*-[[:space:]]+breakglasssessions[[:space:]]*$/) parent = 1
      if ($0 ~ /"breakglasssessions\/status"/ || $0 ~ /^[[:space:]]*-[[:space:]]+breakglasssessions\/status[[:space:]]*$/) status = 1
    }
    in_policy && in_rules && /^[[:space:]]*-[[:space:]]+breakglasssessions[[:space:]]*$/ { parent = 1 }
    in_policy && in_rules && /^[[:space:]]*-[[:space:]]+breakglasssessions\/status[[:space:]]*$/ { status = 1 }
    in_policy && /^[[:space:]]*validations:/ { in_rules = 0 }
    in_policy && /oldObject == null \|\| object.spec == oldObject.spec/ { spec = 1 }
    in_policy && /oldObject.status.state == object.status.state/ { state = 1 }
    END { exit(parent && status && spec && state ? 0 : 1) }
  '
}

printf '%s\n' "$helm_output" | check_session_policy
if printf '%s\n' "$helm_output" | sed 's/"breakglasssessions", //' | check_session_policy; then
  echo "session policy check accepted missing parent resource" >&2
  exit 1
fi
if printf '%s\n' "$helm_output" | sed 's/"breakglasssessions\/status"//' | check_session_policy; then
  echo "session policy check accepted missing status resource" >&2
  exit 1
fi

kustomize_bin=${KUSTOMIZE_BIN:-./bin/kustomize}
if [[ ! -x "$kustomize_bin" ]]; then
  kustomize_bin=kustomize
fi
kustomize_output=$("$kustomize_bin" build config/test-overlays/vap)
printf '%s\n' "$kustomize_output" | check_session_policy
if printf '%s\n' "$kustomize_output" | sed '/^[[:space:]]*-[[:space:]]*breakglasssessions[[:space:]]*$/d' | check_session_policy; then
  echo "kustomize session policy check accepted missing parent resource" >&2
  exit 1
fi
if printf '%s\n' "$kustomize_output" | sed '/^[[:space:]]*-[[:space:]]*breakglasssessions\/status[[:space:]]*$/d' | check_session_policy; then
  echo "kustomize session policy check accepted missing status resource" >&2
  exit 1
fi

printf '%s\n' "VAP render coverage passed: Helm=8 resources, status subresource covered in Helm and Kustomize"
