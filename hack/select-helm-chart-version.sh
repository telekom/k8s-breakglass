#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

# Select a chart version from the authoritative OCI tag set. Chart versions
# remain independent from the application version; the release tag is stored
# in appVersion only.

set -Eeuo pipefail

chart_dir="${1:?chart directory is required}"
chart_repo="${2:?OCI chart repository is required}"
release_tag="${3:?release tag is required}"

chart_metadata="$(helm show chart "${chart_dir}")"
chart_name="$(printf '%s\n' "${chart_metadata}" | awk '/^name:/ {print $2; exit}')"
chart_version="$(printf '%s\n' "${chart_metadata}" | awk '/^version:/ {print $2; exit}')"

if [[ -z "${chart_name}" || ! "${chart_version}" =~ ^[0-9]+\.[0-9]+\.[0-9]+([+-][0-9A-Za-z.-]+)?$ ]]; then
  echo "Invalid chart name or patch-versioned chart metadata in ${chart_dir}" >&2
  exit 1
fi

repo_ref="${chart_repo#oci://}"
registry_host="${repo_ref%%/*}"
repository="${repo_ref#*/}/${chart_name}"
registry_prefix="https://${registry_host}"
[[ -n "${registry_host}" && "${repository}" != "${repo_ref}" ]] || {
  echo "Invalid OCI chart repository: ${chart_repo}" >&2
  exit 1
}

validate_registry_host_url() {
  local url="${1}"
  [[ "${url}" == https://* ]] || return 1
  local authority="${url#https://}"
  local host="${authority%%/*}"
  [ "${host}" = "${registry_host}" ] || return 1
  [[ "${authority}" != */* ]] && return 1
  return 0
}

registry_config="${HELM_REGISTRY_CONFIG:-}"
if [ -z "${registry_config}" ]; then
  registry_config="$(helm env HELM_REGISTRY_CONFIG | sed -E 's/^HELM_REGISTRY_CONFIG="?(.*)"?$/\1/')"
fi
registry_auth="$(jq -er --arg host "${registry_host}" '.auths[$host].auth // empty' "${registry_config}" 2>/dev/null)" || {
  echo "No Helm registry credentials found for ${registry_host}" >&2
  exit 1
}

work_dir="$(mktemp -d)"
trap 'rm -rf "${work_dir}"' EXIT

# Exchange the Helm registry credential for a repository-scoped bearer token.
# The initial request is intentionally unauthenticated: its challenge is the
# registry's authoritative token service and scope.
challenge_headers="${work_dir}/challenge.headers"
challenge_body="${work_dir}/challenge.body"
challenge_status="$(curl -sS -D "${challenge_headers}" -o "${challenge_body}" -w '%{http_code}' \
  "https://${registry_host}/v2/${repository}/tags/list?n=1" || true)"
[ "${challenge_status}" = 401 ] || {
  echo "Registry tag-list challenge failed with HTTP ${challenge_status}" >&2
  cat "${challenge_body}" >&2
  exit 1
}
challenge="$(awk 'BEGIN {IGNORECASE=1} /^www-authenticate:/ {sub(/^[^:]+:[[:space:]]*/, ""); print; exit}' "${challenge_headers}")"
realm="$(printf '%s\n' "${challenge}" | sed -nE 's/.*realm="([^"]+)".*/\1/p')"
service="$(printf '%s\n' "${challenge}" | sed -nE 's/.*service="([^"]+)".*/\1/p')"
scope="$(printf '%s\n' "${challenge}" | sed -nE 's/.*scope="([^"]+)".*/\1/p')"
[ -n "${realm}" ] && [ -n "${service}" ] && [ -n "${scope}" ] || {
  echo "Registry challenge lacks realm, service, or scope" >&2
  exit 1
}
validate_registry_host_url "${realm}" || {
  echo "Registry challenge points to an untrusted token realm" >&2
  exit 1
}
[ "${service}" = "${registry_host}" ] || {
  echo "Registry challenge has an unexpected service" >&2
  exit 1
}
[ "${scope}" = "repository:${repository}:pull" ] || {
  echo "Registry challenge has an unexpected scope" >&2
  exit 1
}
token_json="$(curl -fsS -H "Authorization: Basic ${registry_auth}" \
  "${realm}?service=${service}&scope=${scope}")" || {
  echo "Registry bearer-token exchange failed" >&2
  exit 1
}
bearer_token="$(printf '%s\n' "${token_json}" | jq -er '.token // .access_token // empty')" || {
  echo "Registry bearer-token response lacks a token" >&2
  exit 1
}

tags_file="${work_dir}/tags"
: >"${tags_file}"
tags_url="https://${registry_host}/v2/${repository}/tags/list?n=100"
seen_urls="${work_dir}/seen-urls"
: >"${seen_urls}"
page_count=0
while [ -n "${tags_url}" ]; do
  page_count=$((page_count + 1))
  [ "${page_count}" -le 10000 ] || {
    echo "Registry tag-list pagination exceeded 10000 pages" >&2
    exit 1
  }
  grep -Fqx -- "${tags_url}" "${seen_urls}" && {
    echo "Registry tag-list pagination repeated ${tags_url}" >&2
    exit 1
  }
  printf '%s\n' "${tags_url}" >>"${seen_urls}"
  validate_registry_host_url "${tags_url}" || {
    echo "Registry pagination points to an untrusted URL" >&2
    exit 1
  }
  tags_path="${tags_url#"${registry_prefix}"}"
  [[ "${tags_path}" == /v2/* ]] || {
    echo "Registry pagination points outside the v2 API" >&2
    exit 1
  }
  page_headers="${work_dir}/page.headers"
  page_body="${work_dir}/page.body"
  curl -fsS -D "${page_headers}" -o "${page_body}" \
    -H "Authorization: Bearer ${bearer_token}" "${tags_url}" || {
    echo "Registry tag-list request failed" >&2
    exit 1
  }
  jq -e '.tags | type == "array" and all(.[]; type == "string")' "${page_body}" >/dev/null || {
    echo "Registry tag-list response has no valid tags array" >&2
    exit 1
  }
  jq -r '.tags[]' "${page_body}" >>"${tags_file}"
  next_link="$(awk 'BEGIN {IGNORECASE=1} /^link:/ {sub(/^[^:]+:[[:space:]]*/, ""); print}' "${page_headers}" | \
    tr ',' '\n' | sed -nE 's/.*<([^>]+)>[[:space:]]*;[[:space:]]*rel="?next"?.*/\1/p' | head -n1)"
  if [ -z "${next_link}" ]; then
    tags_url=""
  elif [[ "${next_link}" == /* && "${next_link}" != //* ]]; then
    tags_url="https://${registry_host}${next_link}"
  elif [[ "${next_link}" == https://* ]] && validate_registry_host_url "${next_link}"; then
    next_path="${next_link#"${registry_prefix}"}"
    [[ "${next_path}" == /v2/* ]] || {
      echo "Registry pagination points outside the v2 API" >&2
      exit 1
    }
    tags_url="${next_link}"
  else
    echo "Registry pagination points to an untrusted or malformed URL" >&2
    exit 1
  fi
done

semver_tags="${work_dir}/semver-tags"
tag_refs="${work_dir}/tag-refs"
while IFS= read -r tag; do
  # Cosign stores signatures and attestations beside the chart manifest as
  # digest-derived OCI tags. They are not Helm chart versions.
  if [[ "${tag}" =~ ^sha256-[0-9a-f]{64}(\.(sig|att))?$ ]]; then
    continue
  fi
  if [[ "${tag}" =~ ^([0-9]+\.[0-9]+\.[0-9]+)_([0-9A-Za-z.-]+)$ ]]; then
    normalized_tag="${BASH_REMATCH[1]}+${BASH_REMATCH[2]}"
  else
    normalized_tag="${tag}"
  fi
  printf '%s\n' "${normalized_tag}" >>"${semver_tags}"
  printf '%s\t%s\n' "${tag}" "${normalized_tag}" >>"${tag_refs}"
done <"${tags_file}"
touch "${semver_tags}"

# Validate the complete tag set before any chart lookup. This prevents an
# unrelated or malformed tag from being silently ignored during a rerun.
ruby -e '
  pattern = /\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?\z/
  ARGF.each_line do |line|
    version = line.strip
    match = pattern.match(version) or abort("invalid OCI chart SemVer: #{version}")
    pre = match[4]&.split(".")
    abort("invalid OCI chart SemVer prerelease identifier: #{version}") if pre&.any? { |part| part.match?(/\A[0-9]+\z/) && part.length > 1 && part.start_with?("0") }
  end
' "${semver_tags}"

# Inspect every published chart version so a rerun can find its exact release
# even when newer versions exist or a lower tag has been deleted.
matching_versions="${work_dir}/matching-versions"
: >"${matching_versions}"
while IFS=$'\t' read -r tag normalized_tag; do
  [ -n "${tag}" ] || continue
  remote_metadata="$(helm show chart "${chart_repo}/${chart_name}" --version "${tag}")" || {
    echo "Could not inspect published chart ${chart_name}:${tag}" >&2
    exit 1
  }
  remote_app_version="$(printf '%s\n' "${remote_metadata}" | awk '/^appVersion:/ {print $2; exit}' | tr -d '"')"
  [ -n "${remote_app_version}" ] || {
    echo "Published ${chart_name}:${tag} has no appVersion" >&2
    exit 1
  }
  [ "${remote_app_version}" = "${release_tag}" ] && printf '%s\n' "${normalized_tag}" >>"${matching_versions}"
done <"${tag_refs}"

semver_max() {
  ruby -e '
    pattern = /\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?\z/
    parse = lambda do |version|
      match = pattern.match(version) or abort("invalid OCI chart SemVer: #{version}")
      pre = match[4]&.split(".")
      if pre&.any? { |part| part.match?(/\A[0-9]+\z/) && part.length > 1 && part.start_with?("0") }
        abort("invalid OCI chart SemVer prerelease identifier: #{version}")
      end
      [match[1].to_i, match[2].to_i, match[3].to_i, pre, match[5]]
    end
    compare = lambda do |left, right|
      (0..2).each { |index| result = left[index] <=> right[index]; return result unless result == 0 }
      return 0 if left[3].nil? && right[3].nil?
      return 1 if left[3].nil?
      return -1 if right[3].nil?
      left[3].zip(right[3]).each do |a, b|
        return -1 if a.nil?; return 1 if b.nil?
        an = a.match?(/\A[0-9]+\z/); bn = b.match?(/\A[0-9]+\z/)
        return (a.to_i <=> b.to_i) if an && bn && a.to_i != b.to_i
        return -1 if an && !bn; return 1 if !an && bn
        return (a <=> b) if a != b
      end
      left[3].length <=> right[3].length
    end
    versions = STDIN.read.lines.map(&:strip).reject(&:empty?)
    parsed = versions.map { |version| [version, parse.call(version)] }
    puts parsed.max { |left, right| compare.call(left[1], right[1]) }&.first
  ' <"${1}"
}

next_semver() {
  ruby -e '
    version = ARGV.fetch(0)
    match = /\A(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(?:-([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?(?:\+([0-9A-Za-z-]+(?:\.[0-9A-Za-z-]+)*))?\z/.match(version) or abort("invalid OCI chart SemVer: #{version}")
    if match[4]
      puts "#{match[1]}.#{match[2]}.#{match[3]}"
    else
      puts "#{match[1]}.#{match[2]}.#{match[3].to_i + 1}"
    end
  ' "${1}"
}

set_chart_version() {
  local version="${1}"
  local chart_file="${chart_dir}/Chart.yaml"
  local temporary
  temporary="$(mktemp)"
  if ! sed -E "s/^(version:[[:space:]]*).*/\\1${version}/" "${chart_file}" >"${temporary}"; then
    rm -f "${temporary}"
    return 1
  fi
  if ! awk -v expected="${version}" '$1 == "version:" && $2 == expected { found = 1 } END { exit !found }' "${temporary}"; then
    rm -f "${temporary}"
    echo "Could not update chart version in ${chart_file}" >&2
    return 1
  fi
  mv -- "${temporary}" "${chart_file}"
}

if [ -s "${matching_versions}" ]; then
  selected_version="$(semver_max "${matching_versions}")"
  set_chart_version "${selected_version}"
  printf 'Reusing %s:%s for rerun of release %s\n' "${chart_name}" "${selected_version}" "${release_tag}"
  exit 0
fi

max_version="$(semver_max "${semver_tags}")"
if [ -n "${max_version}" ]; then
  printf '%s\n%s\n' "${max_version}" "${chart_version}" >"${work_dir}/effective-versions"
  effective_max="$(semver_max "${work_dir}/effective-versions")"
else
  effective_max="${chart_version}"
fi
if [ -z "${max_version}" ]; then
  selected_version="${chart_version}"
elif [ "${max_version}" != "${chart_version}" ] && [ "${effective_max}" = "${chart_version}" ]; then
  selected_version="${chart_version}"
else
  selected_version="$(next_semver "${effective_max}")"
fi
set_chart_version "${selected_version}"
printf 'Selected %s:%s for release %s (published maximum: %s)\n' \
  "${chart_name}" "${selected_version}" "${release_tag}" "${max_version:-none}"
