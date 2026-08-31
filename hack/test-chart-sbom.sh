#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

# Behavioral test for the chart SBOM subject binding. It proves that the
# generated SPDX document accepts the exact package and rejects changed or
# different package bytes.

set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
test_dir="$(mktemp -d)"
trap 'rm -rf -- "${test_dir}"' EXIT

package="${test_dir}/debug-session-catalogue-0.2.0.tgz"
sbom="${test_dir}/debug-session-catalogue.spdx.json"
printf 'chart payload\n' >"${package}"
cat >"${sbom}" <<'EOF'
{
  "spdxVersion": "SPDX-2.3",
  "creationInfo": {"created": "2026-08-27T00:00:00Z", "creators": ["Tool: syft"]},
  "name": "debug-session-catalogue",
  "packages": [
    {"SPDXID": "SPDXRef-Package-chart", "name": "debug-session-catalogue"}
  ]
}
EOF

"${script_dir}/attach-chart-subject.sh" "${package}" "${sbom}"
"${script_dir}/verify-chart-sbom.sh" "${package}" "${sbom}"

printf 'changed chart payload\n' >"${package}"
if "${script_dir}/verify-chart-sbom.sh" "${package}" "${sbom}" >/dev/null 2>&1; then
  echo "changed chart package was accepted by its old SBOM" >&2
  exit 1
fi

printf 'chart payload\n' >"${package}"
wrong_package="${test_dir}/other-chart-0.2.0.tgz"
printf 'other chart payload\n' >"${wrong_package}"
if "${script_dir}/verify-chart-sbom.sh" "${wrong_package}" "${sbom}" >/dev/null 2>&1; then
  echo "different chart package was accepted by the SBOM" >&2
  exit 1
fi

empty_graph="${test_dir}/empty-graph.spdx.json"
jq '.packages = [] | .files = []' "${sbom}" >"${empty_graph}"
if "${script_dir}/verify-chart-sbom.sh" "${package}" "${empty_graph}" >/dev/null 2>&1; then
  echo "SPDX SBOM with an empty packages/files graph was accepted" >&2
  exit 1
fi

echo "Chart SBOM subject binding behavior passed"
