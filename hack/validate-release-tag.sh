#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

validate_release_tag() {
  local tag="$1" prerelease identifier
  [[ "${tag}" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$|^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)-([0-9A-Za-z]+(\.[0-9A-Za-z]+)*)$ ]] || return 1
  [[ "${tag}" == *-* ]] || return 0
  prerelease="${tag#*-}"
  IFS='.' read -r -a identifiers <<<"${prerelease}"
  for identifier in "${identifiers[@]}"; do
    if [[ "${identifier}" =~ ^0[0-9]+$ ]]; then
      return 1
    fi
  done
}
