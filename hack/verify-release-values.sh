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
  "workload|ghcr.io/telekom/k8s-breakglass/workload-debug|${digest}" \
  "network|ghcr.io/telekom/k8s-breakglass/network-debug|${digest}" \
  "storage|ghcr.io/telekom/k8s-breakglass/storage-debug|${digest}" \
  "node|ghcr.io/telekom/k8s-breakglass/node-maintenance|${digest}" \
  "diagnostic-artifact-collector|ghcr.io/telekom/k8s-breakglass/diagnostic-artifact-collector|${digest}"; do
  name="${record%%|*}"
  printf '%s|verified|verified|verified\n' "${record}" >"${test_dir}/refs/${name}.ref"
done

output="${test_dir}/release-values.yaml"
"${script_dir}/generate-release-values.sh" "${test_dir}/refs" "${output}"
ruby -ryaml -e '
  values = YAML.safe_load(File.read(ARGV.fetch(0)), aliases: false)
  images = values.fetch("images")
  abort("unexpected image count") unless images.size == 8
  abort("dump-access placeholder was not preserved") unless images.fetch("dumpAccess").fetch("repository") == "example.invalid/breakglass/dump-reader-not-published"
  abort("cluster validator placeholder was not preserved") unless images.fetch("clusterValidation").fetch("repository") == "example.invalid/breakglass/cluster-validator-internal"
  images.each_value do |image|
    abort("unresolved image digest") unless image.fetch("digest").match?(/\Asha256:[0-9a-f]{64}\z/i)
  end
' "${output}"

helm lint "${script_dir}/../charts/debug-session-catalogue" --strict --values "${output}" >/dev/null
helm template release-proof "${script_dir}/../charts/debug-session-catalogue" --values "${output}" >/dev/null

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
