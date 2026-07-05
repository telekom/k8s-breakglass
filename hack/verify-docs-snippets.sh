#!/usr/bin/env bash

set -euo pipefail

paths=(README.md docs .github)
patterns=(
  '30081'
  'deployment/breakglass-controller([^[:alnum:]_-]|$)'
  'deployment/breakglass-controller-manager([^[:alnum:]_-]|$)'
  'deploy/breakglass-controller([^[:alnum:]_-]|$)'
  'svc/breakglass-controller-metrics([^[:alnum:]_-]|$)'
  'app=breakglass-manager([^[:alnum:]_-]|$)'
  '-n breakglass([[:space:]]|$)'
  'namespace:[[:space:]]+breakglass([[:space:]]|$)'
)

found=0
for pattern in "${patterns[@]}"; do
  if grep -RInE -- "${pattern}" "${paths[@]}"; then
    found=1
  fi
done

if [ "${found}" -ne 0 ]; then
  cat >&2 <<'EOF'
Stale docs/workflow snippet found.

Use the current dev workload names:
- deployment/breakglass-manager
- container breakglass
- namespace breakglass-system
- pod label app=breakglass
- e2e NODEPORT default 31081
EOF
  exit 1
fi
