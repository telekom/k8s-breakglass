#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

# Verify the semantic SPDX contract produced for one packaged chart. This
# intentionally checks decoded JSON and the package digest, rather than
# looking for workflow/source strings.

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
package_name="$(basename -- "${package}")"

# Validate the vendored upstream schema before checking our chart binding.
script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
python3 - "${script_dir}/schemas/spdx-2.3.schema.json" "${sbom}" <<'PYTHON'
import json
import sys
from jsonschema import Draft7Validator

with open(sys.argv[1], encoding="utf-8") as source:
    schema = json.load(source)
with open(sys.argv[2], encoding="utf-8") as source:
    document = json.load(source)
errors = sorted(Draft7Validator(schema).iter_errors(document), key=lambda error: str(error.path))
if errors:
    for error in errors:
        print(f"Invalid SPDX document at {error.json_path}: {error.message}", file=sys.stderr)
    sys.exit(1)
PYTHON

jq -e --arg package "${package_name}" --arg digest "${digest}" '
  (.spdxVersion == "SPDX-2.3") and
  (.SPDXID == "SPDXRef-DOCUMENT") and
  (.dataLicense == "CC0-1.0") and
  (.documentNamespace | type == "string" and length > 0) and
  (.creationInfo | type == "object") and
  (
    any((.packages // [])[]?;
      type == "object" and
      (.SPDXID | type == "string" and length > 0) and
      (.name | type == "string" and length > 0)
    ) or
    any((.files // [])[]?;
      type == "object" and
      (.SPDXID | type == "string" and length > 0) and
      (.fileName | type == "string" and length > 0)
    )
  ) and
  ([.annotations[]? |
    select(.annotationType == "OTHER" and .annotator == "Tool: k8s-breakglass-release" and
      ((.comment // "") | startswith("Chart artifact: "))) ] | length == 1) and
  ([.annotations[]? |
    select(.annotationType == "OTHER" and .annotator == "Tool: k8s-breakglass-release" and
      .comment == ("Chart artifact: " + $package + " sha256:" + $digest)) ] | length == 1)
' "${sbom}" >/dev/null || {
  echo "SBOM lacks a meaningful SPDX packages/files graph or is not bound to chart package ${package_name}@sha256:${digest}" >&2
  exit 1
}
