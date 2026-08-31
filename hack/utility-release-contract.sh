#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

# Small, executable contracts shared by the utility-image workflow and its CI
# test. Keeping discovery and reference validation here makes the matrix
# independent of a particular utility implementation or directory layout.
set -Eeuo pipefail

die() {
	printf 'utility release contract: %s\n' "$*" >&2
	exit 1
}

usage() {
	cat >&2 <<'EOF'
usage:
  utility-release-contract.sh matrix [REPOSITORY_ROOT]
  utility-release-contract.sh required-checks [REPOSITORY_ROOT]
  utility-release-contract.sh tag EVENT REF_NAME [PUBLISH_ROLLING]
  utility-release-contract.sh subject IMAGE DIGEST
EOF
	exit 2
}

canonical_image() {
	local image="$1"
	[[ "${image}" =~ ^ghcr\.io/telekom/k8s-breakglass/utils/[a-z0-9]+([.-][a-z0-9]+)*$ ]] ||
		die "non-canonical utility image: ${image}"
	[[ "${image}" != *:* && "${image}" != *@* ]] || die "image must not contain a tag or digest: ${image}"
}

valid_digest() {
	[[ "$1" =~ ^sha256:[0-9a-f]{64}$ ]]
}

matrix() {
	local root="${1:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
	local prefix="${UTILITY_IMAGE_PREFIX:-ghcr.io/telekom/k8s-breakglass/utils}"
	local manifest="${UTILITY_IMAGE_MANIFEST:-${root}/hack/utility-image-matrix.json}"

	command -v jq >/dev/null 2>&1 || die 'jq is required to produce the matrix'
	[[ -f "${manifest}" ]] || die "utility image manifest does not exist: ${manifest}"
	[[ "${prefix}" == ghcr.io/telekom/k8s-breakglass/utils ]] ||
		die "invalid utility image prefix: ${prefix}"

	jq -e '(.schemaVersion == 1) and (.images|type=="array" and length>0) and
		(([.images[].name]|length) == ([.images[].name]|unique|length)) and
		(([.images[].file]|length) == ([.images[].file]|unique|length)) and
		all(.images[]; (.name|test("^[a-z0-9]+([.-][a-z0-9]+)*$")) and
		(.context|test("^utils/[A-Za-z0-9._/-]+$")) and
		(.context|contains("..")|not) and (.context|contains("//")|not) and
		(.file == (.context + "/Dockerfile")) and
		(.smokeCommand|type=="array" and length>0 and all(.[]; type=="string" and length>0)) and
		(.smokeOutput|type=="string" and length>0) and
		(.requiredChecks|type=="array" and length>0 and all(.[]; type=="string" and length>0)) and
		(.behaviorWorkflows|type=="array" and length>0 and all(.[]; type=="string" and test("^\\.github/workflows/[A-Za-z0-9._-]+\\.yml$")))) and
		(([.images[].requiredChecks[]]|length) == ([.images[].requiredChecks[]]|unique|length))' "${manifest}" >/dev/null || die 'invalid utility image manifest'
	while IFS= read -r path; do [[ -d "${root}/${path}" ]] || die "manifest context does not exist: ${path}"; done < <(jq -r '.images[].context' "${manifest}")
	while IFS= read -r path; do [[ -f "${root}/${path}" ]] || die "manifest Dockerfile does not exist: ${path}"; done < <(jq -r '.images[].file' "${manifest}")
	while IFS= read -r path; do [[ -f "${root}/${path}" ]] || die "behavior workflow does not exist: ${path}"; done < <(jq -r '.images[].behaviorWorkflows[]' "${manifest}")
	jq -cS --arg prefix "${prefix}" '[.images[] | . + {image:($prefix+"/"+.name)}] | sort_by(.name)' "${manifest}"
}

required_checks() {
	local root="${1:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
	local core="${root}/hack/release-required-checks.json" manifest="${root}/hack/utility-image-matrix.json"
	jq -e 'type=="array" and length>0 and all(.[]; type=="string" and length>0) and length==(unique|length)' "${core}" >/dev/null || die 'invalid core required-check inventory'
	matrix "${root}" >/dev/null
	jq -cs '.[0] + [.[1].images[].requiredChecks[]] | unique' "${core}" "${manifest}"
}

release_tag() {
	local event="$1" ref_name="$2" publish_rolling="${3:-false}"
	case "${event}" in
		push)
			local identifier='(0|[1-9][0-9]*|[0-9A-Za-z-]*[A-Za-z-][0-9A-Za-z-]*)'
			local version_re="^v(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)\\.(0|[1-9][0-9]*)(-${identifier}(\\.${identifier})*)?$"
			[[ "${ref_name}" =~ ${version_re} ]] ||
				die "push ref is not a release tag: ${ref_name}"
			printf '%s\n' "${ref_name}"
			;;
		schedule)
			printf '%s\n' nightly
			;;
		workflow_dispatch)
			[[ "${ref_name}" == main && "${publish_rolling}" == true ]] ||
				die 'rolling publication requires workflow_dispatch on the main branch with publish_rolling=true'
			printf '%s\n' rolling
			;;
		*)
			die "utility publication is only supported for release tags, the weekly schedule, or an explicit rolling dispatch (got ${event})"
			;;
	esac
}

subject() {
	local image="$1" digest="$2"
	canonical_image "${image}"
	valid_digest "${digest}" || die "invalid immutable digest: ${digest}"
	printf '%s@%s\n' "${image}" "${digest}"
}

[[ $# -ge 1 ]] || usage
case "$1" in
	matrix)
		[[ $# -le 2 ]] || usage
		matrix "${2:-}"
		;;
	required-checks)
		[[ $# -le 2 ]] || usage
		required_checks "${2:-}"
		;;
	tag)
		[[ $# == 3 || $# == 4 ]] || usage
		release_tag "$2" "$3" "${4:-false}"
		;;
	subject)
		[[ $# == 3 ]] || usage
		subject "$2" "$3"
		;;
	*) usage ;;
esac
