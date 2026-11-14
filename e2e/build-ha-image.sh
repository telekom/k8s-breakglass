#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
#
# Builds the controller image for the HA e2e test
# (e2e/api/debug_session_cleanup_acknowledgement_ha_test.go): the e2e image
# with its binary rebuilt with -tags e2e_ha, which adds the test-only claim
# fault injection. Release and regular e2e images never contain it.
set -euo pipefail
BASE_IMAGE=${BASE_IMAGE:-breakglass:e2e}
HA_IMAGE=${HA_IMAGE:-breakglass:e2e-ha}
CLUSTER_NAME=${CLUSTER_NAME:-breakglass-hub}
KIND=${KIND:-kind}

dir=$(mktemp -d)
trap 'rm -rf "$dir"' EXIT
CGO_ENABLED=0 GOOS=linux GOARCH="${GOARCH:-$(go env GOARCH)}" go build -tags e2e_ha -trimpath -o "$dir/breakglass" ./cmd
grep -q BREAKGLASS_E2E_HOLD_CLEANUP_ACKNOWLEDGEMENT_CLAIM "$dir/breakglass" || { echo "e2e_ha build lacks the fault injection" >&2; exit 1; }
printf 'FROM %s\nCOPY breakglass /breakglass\n' "$BASE_IMAGE" > "$dir/Dockerfile"
docker build -t "$HA_IMAGE" "$dir"
"$KIND" load docker-image "$HA_IMAGE" --name "$CLUSTER_NAME"
