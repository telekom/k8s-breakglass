#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

# Contract test for the normal CI path. The behavioral security tests must be
# reachable from the pull-request workflow, not only from a developer target.

set -Eeuo pipefail

workflow="$(CDPATH='' cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)/.github/workflows/ci.yml"

ruby -e '
  workflow = File.read(ARGV.fetch(0))
  abort "CI workflow does not invoke test-release-security" unless
    workflow.lines.any? { |line| line.match?(/^\s+run:\s+make test-release-security\s*$/) }
' "${workflow}"

echo "release security behavioral tests are wired into CI"
