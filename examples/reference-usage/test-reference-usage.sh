#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -eu

script_dir=$(CDPATH= cd -- "$(dirname -- "$0")" && pwd)
script="${script_dir}/reference-usage.sh"

bash -n "${script}"
awk '/--wait/ && !/--timeout/ { bad = 1 } END { exit bad }' "${script}"
grep -Fq '`workloadType` accepts `DaemonSet`, `Deployment`, or `Job`.' \
  "${script_dir}/../../docs/api-reference.md"
echo "reference usage safety checks passed"
