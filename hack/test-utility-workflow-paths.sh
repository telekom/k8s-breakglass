#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -Eeuo pipefail

root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
command -v ruby >/dev/null 2>&1 || {
	printf '%s\n' 'utility workflow path contract: ruby is required' >&2
	exit 1
}

ruby -ryaml - "${root}" <<'RUBY'
root = ARGV.fetch(0)
required = %w[
  hack/docker-image-ownership.sh
  hack/docker-resource-ownership.sh
  hack/kind-ownership.sh
  hack/kubernetes-delete-uid.sh
  hack/kubernetes-storage-cleanup.sh
  hack/test-utility-workflow-paths.sh
  hack/test-utility-image-security-contract.sh
]

%w[utility-release.yml utility-image-security.yml].each do |workflow_name|
  workflow = YAML.safe_load(File.read(File.join(root, ".github/workflows", workflow_name)), aliases: false)
  trigger = workflow.fetch(true).fetch("pull_request")
  paths = trigger.fetch("paths")
  missing = required.reject { |path| paths.include?(path) }
  abort "#{workflow_name} is missing release-gate path filters: #{missing.join(', ')}" unless missing.empty?
end
RUBY

printf '%s\n' 'utility workflow path filters cover shared ownership and security contracts'
