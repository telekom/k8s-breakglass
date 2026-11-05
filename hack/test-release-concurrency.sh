#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

repo_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
ruby -ryaml -e '
  workflow = YAML.load_file(ARGV.fetch(0))
  concurrency = workflow.fetch("concurrency")
  abort "release concurrency group is not static" unless concurrency.fetch("group") == "breakglass-release-publication"
  abort "release runs must queue rather than cancel" unless concurrency.fetch("cancel-in-progress") == false
' "${repo_dir}/.github/workflows/release.yml"
echo "Release concurrency invariant passed"
