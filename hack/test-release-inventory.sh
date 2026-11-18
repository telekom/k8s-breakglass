#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
# shellcheck disable=SC2016 # needles are literal workflow/script text

# Negative tests for hack/verify-release-inventory.sh: each mutation of a
# scratch copy of the release inputs must make the gate fail.

set -Eeuo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "${tmp}"' EXIT
verify="${root}/hack/verify-release-inventory.sh"
inventory="${root}/hack/release-artifact-inventory.json"
sources="$(cd "${root}" && find . \( -name node_modules -o -name .git -o -name vendor \) -prune -o \( -type f -o -type l \) \
  \( -iname 'Dockerfile' -o -iname 'Dockerfile.*' -o -iname '*.Dockerfile' -o -iname 'Containerfile' -o -iname 'Containerfile.*' -o -name Chart.yaml -o -name Chart.yml \) -print)"

fresh() { # fresh <name>: scratch tree with real gate files and empty source stubs
  local d="${tmp}/$1" f; rm -rf "${d}"; mkdir -p "${d}/.github" "${d}/hack"
  cp -R "${root}/.github/workflows" "${d}/.github/workflows"
  cp "${root}"/hack/*.sh "${root}"/hack/*.json "${d}/hack/"
  while IFS= read -r f; do
    mkdir -p "${d}/$(dirname "${f}")"
    if [[ -L "${root}/${f}" ]]; then ln -s "$(readlink "${root}/${f}")" "${d}/${f}"; else : >"${d}/${f}"; fi
  done <<<"${sources}"
  printf '%s' "${d}"
}
expect_fail() { # expect_fail <label> <dir>
  if "${verify}" "$2" >"${tmp}/out" 2>&1; then echo "gate accepted: $1" >&2; exit 1; fi
}
# Remove every line of $2 (relative to dir $1) containing fixed string $3.
drop_line() { local f="$1/$2"; grep -qF -- "$3" "${f}" || { echo "needle not found in $2: $3" >&2; exit 1; }; grep -vF -- "$3" "${f}" >"${f}.new"; mv "${f}.new" "${f}"; }
# Rewrite the scratch inventory with jq filter $2.
edit_inventory() { jq "$2" "$1/hack/release-artifact-inventory.json" >"$1/inv.json"; mv "$1/inv.json" "$1/hack/release-artifact-inventory.json"; }

d="$(fresh base)"; "${verify}" "${d}" >/dev/null

d="$(fresh unlisted-dockerfile)"; mkdir -p "${d}/utils/new-tool"; : >"${d}/utils/new-tool/Dockerfile"
expect_fail 'unlisted Dockerfile' "${d}"
d="$(fresh unlisted-containerfile)"; mkdir -p "${d}/utils/new-tool"; : >"${d}/utils/new-tool/Containerfile"
expect_fail 'unlisted Containerfile' "${d}"
d="$(fresh unlisted-symlink)"; ln -s utils/workload-debug/Dockerfile "${d}/Dockerfile.alias"
expect_fail 'unlisted symlinked Dockerfile' "${d}"
d="$(fresh unlisted-chart)"; mkdir -p "${d}/charts/new-chart"; : >"${d}/charts/new-chart/Chart.yaml"
expect_fail 'unlisted chart' "${d}"
d="$(fresh matrix-drift)"; sed -i.bak 's#context: utils/node-maintenance#context: utils/other#' "${d}/.github/workflows/release.yml"
expect_fail 'release.yml matrix context differs from utility inventory' "${d}"
d="$(fresh matrix-name-drift)"; sed -i.bak 's#- name: node-maintenance#- name: node-maint#' "${d}/.github/workflows/release.yml"
expect_fail 'release.yml matrix name differs from utility inventory' "${d}"
d="$(fresh listed-missing)"; rm "${d}/charts/escalation-config/Chart.yaml"
expect_fail 'inventoried source missing' "${d}"
d="$(fresh exclusion-without-reason)"; edit_inventory "${d}" '.excluded[0].reason = " "'
expect_fail 'exclusion without reason' "${d}"
d="$(fresh published-source-excluded)"; edit_inventory "${d}" '.artifacts |= map(select(.name != "controller")) | .excluded += [{source: "Dockerfile", reason: "x"}]'
expect_fail 'published controller moved to excluded' "${d}"
d="$(fresh symlink-to-unlisted)"; rm "${d}/Dockerfile.validator"; ln -s e2e/images/tmux-debug/Dockerfile "${d}/Dockerfile.validator"
expect_fail 'excluded symlink to a non-inventoried source' "${d}"

d="$(fresh tag-only-subject)"; sed -i.bak 's#"subject": "\\"${IMAGE}@${DIGEST}\\""#"subject": "\\"${IMAGE}:latest\\""#' "${d}/hack/release-artifact-inventory.json"
printf 'tag_only: "${IMAGE}:latest"\n' >>"${d}/.github/workflows/release.yml"
expect_fail 'tag-only subject' "${d}"
d="$(fresh subject-unbound)"; sed -i.bak 's#subject="${docker_remote}@${digest}"#subject="${docker_remote}:${chart_version}"#' "${d}/.github/workflows/release.yml"
expect_fail 'publisher no longer binds digest subject' "${d}"
d="$(fresh single-gate-entry)"; edit_inventory "${d}" '.gateSets.chart.sbom |= .[:1]'
expect_fail 'gate class without a publish and a verify entry' "${d}"

d="$(fresh commented-gate)"; sed -i.bak 's#^\([[:space:]]*\)cosign sign --yes ${{ env.REGISTRY }}#\1\# cosign sign --yes ${{ env.REGISTRY }}#' "${d}/.github/workflows/release.yml"
grep -qF '# cosign sign --yes ${{ env.REGISTRY }}' "${d}/.github/workflows/release.yml"
expect_fail 'commented-out controller sign gate' "${d}"

# Every signature/SBOM/provenance gate and every gate-script invocation in the
# inventory: dropping its line must fail the check.
i=0
while IFS=$'\t' read -r file needle; do
  i=$((i + 1)); d="$(fresh "gate-${i}")"; drop_line "${d}" "${file}" "${needle}"
  expect_fail "missing gate in ${file}: ${needle}" "${d}"
done < <(jq -r '(.gateSets[][][], .invocations[]) | [.file, .contains] | @tsv' "${inventory}")
echo "release inventory negative tests passed (${i} gates)"
