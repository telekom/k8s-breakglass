#!/usr/bin/env bash
set -euo pipefail
KIND=${KIND:-kind}
KUBECTL=${KUBECTL:-kubectl}
KEEP_CLUSTERS=${KEEP_CLUSTERS:-false}

echo "[e2e] Teardown starting"
# Kill persistent port-forwards if pid file exists
PF_FILE="e2e/port-forward-pids"
if [[ -f "$PF_FILE" ]]; then
  while read -r pid; do
    if [[ -n "$pid" ]]; then
      kill "$pid" >/dev/null 2>&1 || true
    fi
  done < "$PF_FILE"
  rm -f "$PF_FILE"
  echo "[e2e] Port-forwards terminated"
fi

if [[ "$KEEP_CLUSTERS" != "true" ]]; then
  echo "[e2e] Deleting kind clusters"
  $KIND delete cluster --name breakglass-hub || true
  $KIND delete cluster --name tenant-a || true
else
  echo "[e2e] Keeping clusters (KEEP_CLUSTERS=true)"
fi

echo "[e2e] Teardown complete"
