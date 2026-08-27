#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

# Bind an SPDX document to the exact packaged chart that was scanned. The
# annotation is part of SPDX and prevents a later loop from accidentally
# reusing one chart's SBOM for another chart subject.

set -Eeuo pipefail

package="${1:?chart package is required}"
sbom="${2:?SBOM path is required}"

[[ -f "${package}" ]] || { echo "chart package not found: ${package}" >&2; exit 1; }
[[ -f "${sbom}" ]] || { echo "SBOM not found: ${sbom}" >&2; exit 1; }

if command -v sha256sum >/dev/null 2>&1; then
  digest="$(sha256sum "${package}" | awk '{print $1}')"
else
  digest="$(shasum -a 256 "${package}" | awk '{print $1}')"
fi
[[ "${digest}" =~ ^[0-9a-f]{64}$ ]] || { echo "could not hash chart package" >&2; exit 1; }

package_name="$(basename -- "${package}")"
annotation_date="$(date -u +%Y-%m-%dT%H:%M:%SZ)"
temporary="${sbom}.tmp.$$"
trap 'rm -f -- "${temporary}"' EXIT

jq --arg package "${package_name}" --arg digest "${digest}" \
  --arg date "${annotation_date}" \
  '.annotations = ((.annotations // []) | map(select((.comment // "") != ("Chart artifact: " + $package + " sha256:" + $digest))) + [{annotationDate:$date,annotationType:"OTHER",annotator:"Tool: k8s-breakglass-release",comment:("Chart artifact: " + $package + " sha256:" + $digest)}])' \
  "${sbom}" >"${temporary}"
mv -- "${temporary}" "${sbom}"
