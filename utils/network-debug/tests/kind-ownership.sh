#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

# shellcheck source=../../../hack/kind-ownership.sh
# shellcheck disable=SC1091
helper_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
. "${helper_dir}/../../../hack/kind-ownership.sh"
