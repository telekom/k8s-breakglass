#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

# Behavioral test for release image value generation. It executes the same
# generator used by the release workflow and parses its public YAML output.

set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
test_dir="$(mktemp -d)"
trap 'rm -rf "${test_dir}"' EXIT
mkdir -p "${test_dir}/refs"

digest="sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef"
for record in \
  "workload|ghcr.io/telekom/k8s-breakglass/utils/workload-debug|${digest}" \
  "network|ghcr.io/telekom/k8s-breakglass/utils/network-debug|${digest}" \
  "storage|ghcr.io/telekom/k8s-breakglass/utils/storage-debug|${digest}" \
  "node|ghcr.io/telekom/k8s-breakglass/utils/node-maintenance|${digest}" \
  "diagnostic-artifact-collector|ghcr.io/telekom/k8s-breakglass/utils/diagnostic-artifact-collector|${digest}"; do
  name="${record%%|*}"
  printf '%s|verified|verified|verified\n' "${record}" >"${test_dir}/refs/${name}.ref"
done

output="${test_dir}/release-values.yaml"
"${script_dir}/generate-release-values.sh" "${test_dir}/refs" "${output}"
ruby -ryaml -e '
  values = YAML.safe_load(File.read(ARGV.fetch(0)), aliases: false)
  images = values.fetch("images")
  abort("unexpected image count") unless images.size == 8
  images.each_value do |image|
    abort("unresolved image digest") unless image.fetch("digest").match?(/\Asha256:[0-9a-f]{64}\z/i)
  end
' "${output}"

refs_output="${test_dir}/catalogue-image-refs.txt"
render_values="${test_dir}/render-values.yaml"
ruby -ryaml -e '
  base = YAML.safe_load(File.read(ARGV.fetch(0)), aliases: false)
  release = YAML.safe_load(File.read(ARGV.fetch(1)), aliases: false)
  base["images"] = release.fetch("images")
  File.write(ARGV.fetch(2), base.to_yaml)
' "${script_dir}/../charts/debug-session-catalogue/values.yaml" "${output}" "${render_values}"
helm lint "${script_dir}/../charts/debug-session-catalogue" --strict --values "${render_values}" >/dev/null
helm template release-proof "${script_dir}/../charts/debug-session-catalogue" --values "${render_values}" >/dev/null
"${script_dir}/extract-catalogue-image-refs.sh" "${render_values}" "${refs_output}"
[ "$(wc -l <"${refs_output}" | tr -d ' ')" -eq 5 ] || { echo "unexpected public utility image count" >&2; exit 1; }
if rg -q 'example\.invalid|:0\.1\.0$' "${refs_output}"; then
  echo "non-public placeholder or mutable image leaked into supply-chain refs" >&2
  exit 1
fi

printf '%s\n' 'workload|ghcr.io/telekom/k8s-breakglass/workload-debug|not-a-digest' >"${test_dir}/refs/workload.ref"
if "${script_dir}/generate-release-values.sh" "${test_dir}/refs" "${output}" >/dev/null 2>&1; then
  echo "invalid utility digest was accepted" >&2
  exit 1
fi

printf '%s\n' "workload|ghcr.io/telekom/k8s-breakglass/workload-debug|${digest}|missing|verified|verified" >"${test_dir}/refs/workload.ref"
if "${script_dir}/generate-release-values.sh" "${test_dir}/refs" "${output}" >/dev/null 2>&1; then
  echo "missing utility signature evidence was accepted" >&2
  exit 1
fi

echo "Release value generation behavior passed"
