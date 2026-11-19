#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
#
# Builds a controller image with test-only fault injection: the e2e image with
# its binary rebuilt with -tags $TAGS. Release and regular e2e images never
# contain it.
#   TAGS=e2e_ha (default): cleanup acknowledgement claim hold for the HA e2e
#     test (e2e/api/debug_session_cleanup_acknowledgement_ha_test.go).
#   TAGS=e2e_fault HA_IMAGE=breakglass:e2e-fault: terminal output admission
#     fault (e2e/api/debug_session_terminal_recording_completeness_test.go).
set -euo pipefail
BASE_IMAGE=${BASE_IMAGE:-breakglass:e2e}
TAGS=${TAGS:-e2e_ha}
HA_IMAGE=${HA_IMAGE:-breakglass:e2e-ha}
CLUSTER_NAME=${CLUSTER_NAME:-breakglass-hub}
KIND=${KIND:-kind}
case "$TAGS" in
  e2e_ha) MARKER=BREAKGLASS_E2E_HOLD_CLEANUP_ACKNOWLEDGEMENT_CLAIM ;;
  e2e_fault) MARKER=BREAKGLASS_E2E_FAIL_TERMINAL_OUTPUT_ADMISSION ;;
  *) echo "unknown fault-injection build tag: $TAGS" >&2; exit 2 ;;
esac

dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
CGO_ENABLED=0 GOOS=linux GOARCH="${GOARCH:-$(go env GOARCH)}" go build -tags "$TAGS" -trimpath -o "$dir/breakglass" ./cmd
grep -q "$MARKER" "$dir/breakglass" || { echo "$TAGS build lacks the fault injection" >&2; exit 1; }
printf 'FROM %s\nCOPY breakglass /breakglass\n' "$BASE_IMAGE" > "$dir/Dockerfile"
docker build -t "$HA_IMAGE" "$dir"
"$KIND" load docker-image "$HA_IMAGE" --name "$CLUSTER_NAME"
