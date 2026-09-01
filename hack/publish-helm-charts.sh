#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

chart_dir="${1:?chart package directory is required}"
chart_repo="${2:?OCI chart repository is required}"
release_tag="${3:?release tag is required}"

package_digest() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | awk '{print $1}'
  else
    shasum -a 256 "$1" | awk '{print $1}'
  fi
}

shopt -s nullglob
chart_packages=("${chart_dir}"/*.tgz)
[ "${#chart_packages[@]}" -gt 0 ] || {
  echo "No chart packages found in ${chart_dir}" >&2
  exit 1
}

for chart_package in "${chart_packages[@]}"; do
  chart_metadata="$(helm show chart "${chart_package}")"
  chart_name="$(printf '%s\n' "${chart_metadata}" | awk '/^name:/ {print $2}')"
  chart_version="$(printf '%s\n' "${chart_metadata}" | awk '/^version:/ {print $2}')"
  chart_app_version="$(printf '%s\n' "${chart_metadata}" | awk '/^appVersion:/ {print $2}' | tr -d '"')"
  if [ -z "${chart_name}" ] || [ -z "${chart_version}" ] || [ -z "${chart_app_version}" ]; then
    echo "Invalid chart metadata: ${chart_package}" >&2
    exit 1
  fi
  [ "${chart_app_version}" = "${release_tag}" ] || {
    echo "${chart_name}:${chart_version} appVersion ${chart_app_version} does not match ${release_tag}" >&2
    exit 1
  }

  remote="${chart_repo}/${chart_name}"
  set +e
  remote_output="$(helm show chart "${remote}" --version "${chart_version}" 2>&1)"
  remote_status=$?
  set -e
  if [ "${remote_status}" -eq 0 ]; then
    remote_app_version="$(printf '%s\n' "${remote_output}" | awk '/^appVersion:/ {print $2}' | tr -d '"')"
    [ -n "${remote_app_version}" ] || {
      echo "Remote ${chart_name}:${chart_version} has no appVersion" >&2
      exit 1
    }
    [ "${remote_app_version}" = "${chart_app_version}" ] || {
      echo "${chart_name}:${chart_version} exists with appVersion ${remote_app_version}; bump chart version" >&2
      exit 1
    }

    # Metadata alone is not an identity check. Pull the remote package and
    # require byte identity before allowing a rerun to continue to signing.
    remote_dir="$(mktemp -d)"
    if ! helm pull "${remote}" --version "${chart_version}" --destination "${remote_dir}" >/dev/null 2>&1; then
      rm -rf "${remote_dir}"
      echo "Could not pull existing ${remote}:${chart_version} for content comparison" >&2
      exit 1
    fi
    remote_package="${remote_dir}/$(basename "${chart_package}")"
    if [ ! -f "${remote_package}" ]; then
      rm -rf "${remote_dir}"
      echo "Pulled ${remote}:${chart_version} did not contain $(basename "${chart_package}")" >&2
      exit 1
    fi
    local_digest="$(package_digest "${chart_package}")"
    remote_digest="$(package_digest "${remote_package}")"
    rm -rf "${remote_dir}"
    [ "${local_digest}" = "${remote_digest}" ] || {
      echo "${chart_name}:${chart_version} exists but its package bytes differ; refusing to sign or replace it" >&2
      exit 1
    }
    echo "Chart ${chart_name}:${chart_version} already present and byte-identical; skipping push."
    continue
  fi

  if ! printf '%s\n' "${remote_output}" | grep -Eiq '(^Error: .*(not found|manifest unknown)|(^|[[:space:]])manifest unknown([[:space:][:punct:]]|$))'; then
    echo "Failed to inspect ${remote}" >&2
    printf '%s\n' "${remote_output}" >&2
    exit "${remote_status}"
  fi

  helm push "${chart_package}" "${chart_repo}"
  echo "Published ${chart_package} to ${chart_repo}"
done
