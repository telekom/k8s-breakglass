#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

# Extract only the five published catalogue utility images from rendered chart
# values. Explicit example.invalid placeholders are intentionally excluded;
# every canonical public utility image must be present exactly once.

set -Eeuo pipefail

values_file="${1:?catalogue values file is required}"
output_file="${2:?image reference output file is required}"
[[ -f "${values_file}" ]] || { echo "catalogue values file is missing" >&2; exit 1; }
tmp_file="$(mktemp)"
trap 'rm -f "${tmp_file}"' EXIT

ruby -ryaml -e '
  values = YAML.safe_load(File.read(ARGV.fetch(0)), aliases: false) || {}
  images = values.fetch("images", {})
  expected = {
    "ghcr.io/telekom/k8s-breakglass/utils/workload-debug" => "workload",
    "ghcr.io/telekom/k8s-breakglass/utils/network-debug" => "network",
    "ghcr.io/telekom/k8s-breakglass/utils/storage-debug" => "storage",
    "ghcr.io/telekom/k8s-breakglass/utils/node-maintenance" => "node-maintenance",
    "ghcr.io/telekom/k8s-breakglass/utils/diagnostic-artifact-collector" => "diagnostic-artifact-collector"
  }
  public = {}
  images.each_value do |image|
    repository = image.fetch("repository").to_s
    digest = image.fetch("digest").to_s
    if repository.start_with?("ghcr.io/telekom/k8s-breakglass/utils/")
      name = expected[repository] or abort("unexpected public utility repository: #{repository}")
      abort("public utility #{name} is not digest-pinned") unless digest.match?(/\Asha256:[0-9a-f]{64}\z/)
      abort("conflicting public utility digest: #{repository}") if public.key?(repository) && public[repository] != "#{repository}@#{digest}"
      public[repository] = "#{repository}@#{digest}"
    elsif repository != "example.invalid/breakglass/dump-reader-not-published" && repository != "example.invalid/breakglass/cluster-validator-internal"
      abort("unexpected non-public utility repository: #{repository}")
    end
  end
  abort("public utility image set mismatch: #{public.keys.sort.inspect}") unless public.keys.sort == expected.keys.sort
  puts public.values.sort
' "${values_file}" >"${tmp_file}"
mv "${tmp_file}" "${output_file}"
trap - EXIT
