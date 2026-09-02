#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

# Behavioral proof for the object-axis x platform-axis expansion used by the
# GitHub workflows. It evaluates the actual workflow's matrix and field
# mappings, then verifies that every declared image receives exactly both
# supported platforms and that no rendered job label is duplicated.
set -Eeuo pipefail

root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
contract="${root}/hack/utility-release-contract.sh"
matrix="$("${contract}" matrix "${root}")"

command -v ruby >/dev/null 2>&1 || {
	printf '%s\n' 'utility matrix expansion: ruby is required to parse the workflow' >&2
	exit 1
}

# Parse the workflow rather than checking for snippets in its source. The
# evaluator below resolves the exact matrix.image.name/context/file expressions
# used by the build job against the contract output, and renders the job name
# for every Cartesian pair.
UTILITY_MATRIX_JSON="${matrix}" ruby -ryaml -rjson - "${root}/.github/workflows/utility-image-security.yml" <<'RUBY'
workflow_path = ARGV.fetch(0)
workflow = YAML.safe_load(File.read(workflow_path), aliases: false)
matrix = JSON.parse(ENV.fetch("UTILITY_MATRIX_JSON"))

abort "utility matrix expansion: contract matrix must contain exactly five images" unless matrix.is_a?(Array) && matrix.length == 5

scan = workflow.fetch("jobs").fetch("scan")
strategy_matrix = scan.fetch("strategy").fetch("matrix")
image_axis = strategy_matrix.fetch("image").to_s.strip
expected_axis = "${{ fromJSON(needs.discover.outputs.matrix) }}"
abort "utility matrix expansion: scan image axis is not discover output" unless image_axis == expected_axis

platforms = strategy_matrix.fetch("platform")
abort "utility matrix expansion: scan platform axis must be amd64 and arm64" unless platforms == ["linux/amd64", "linux/arm64"]

build_step = scan.fetch("steps").find { |step| step["name"] == "Build exact platform image for scanning" }
abort "utility matrix expansion: build step is missing" unless build_step
build_env = build_step.fetch("env")

def resolve_field(expression, image, platform)
  case expression.to_s.strip
  when "${{ matrix.image.name }}"
    image.fetch("name")
  when "${{ matrix.image.context }}"
    image.fetch("context")
  when "${{ matrix.image.file }}"
    image.fetch("file")
  when "${{ matrix.platform }}"
    platform
  else
    abort "utility matrix expansion: unsupported workflow field mapping #{expression.inspect}"
  end
end

def render_label(template, image, platform)
  rendered = template.to_s
  {
    "${{ matrix.image.name }}" => image.fetch("name"),
    "${{ matrix.platform }}" => platform
  }.each { |expression, value| rendered = rendered.gsub(expression, value) }
  abort "utility matrix expansion: unresolved job-label expression #{rendered.inspect}" if rendered.include?("${{")
  rendered
end

labels = []
matrix.each do |image|
  platforms.each do |platform|
    abort "utility matrix expansion: context mapping does not resolve" unless resolve_field(build_env.fetch("CONTEXT"), image, platform) == image.fetch("context")
    abort "utility matrix expansion: Dockerfile mapping does not resolve" unless resolve_field(build_env.fetch("DOCKERFILE"), image, platform) == image.fetch("file")
    abort "utility matrix expansion: platform mapping does not resolve" unless resolve_field(build_env.fetch("PLATFORM"), image, platform) == platform
    labels << render_label(scan.fetch("name"), image, platform)
  end
end

expected_labels = matrix.flat_map do |image|
  platforms.map { |platform| "Utility image vulnerability (#{image.fetch("name")} / #{platform})" }
end
abort "utility matrix expansion: expected ten rendered labels" unless labels.length == 10 && labels.sort == expected_labels.sort
abort "utility matrix expansion: rendered labels are not unique" unless labels.uniq.length == labels.length
RUBY

printf '%s\n' 'utility matrix expansion behavioral proof passed (5 images x 2 platforms)'
