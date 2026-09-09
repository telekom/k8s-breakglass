#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
command -v ruby >/dev/null 2>&1 || {
	printf '%s\n' 'utility image security contract: ruby is required' >&2
	exit 1
}

ruby -ryaml - "${root}/.github/workflows/utility-image-security.yml" <<'RUBY'
workflow = YAML.safe_load(File.read(ARGV.fetch(0)), aliases: false)
steps = workflow.fetch("jobs").fetch("scan").fetch("steps")
build = steps.find { |step| step["name"] == "Build exact platform image for scanning" }
scan = steps.find { |step| step["name"] == "Scan the exact built image" }
verify = steps.find { |step| step["name"] == "Ensure the scanned image was not replaced" }
abort "security contract: exact-image build step is missing" unless build
abort "security contract: Trivy step is missing" unless scan
abort "security contract: post-scan identity check is missing" unless verify

image_id = "${{ steps.build.outputs.image_id }}"
abort "security contract: Trivy must scan the captured immutable image ID" unless scan.fetch("with").fetch("image-ref") == image_id
abort "security contract: build must publish image_id" unless build.fetch("id") == "build"
abort "security contract: scan identity check must use captured image ID" unless verify.fetch("env").fetch("EXPECTED_IMAGE_ID") == image_id
abort "security contract: mutable IMAGE_REF may not be Trivy subject" if scan.fetch("with").fetch("image-ref").include?("IMAGE_REF")
RUBY

printf '%s\n' 'utility image security scans the captured immutable image ID before tag equality verification'
