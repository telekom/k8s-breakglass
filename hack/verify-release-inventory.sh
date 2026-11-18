#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

# Machine check of hack/release-artifact-inventory.json. Fails when
#   - a Dockerfile or Chart.yaml exists that is neither inventoried nor excluded,
#   - an inventoried source does not exist,
#   - a utility image in hack/utility-image-matrix.json and the release.yml build
#     matrix disagree,
#   - an exclusion has no reason, or is neither an e2e/ fixture nor a symlink
#     to an inventoried source,
#   - an artifact's publisher does not bind a digest subject,
#   - a signature, SBOM or provenance publish/verify gate is no longer present
#     (comment lines do not count), or
#   - a release workflow no longer invokes a gate script ("invocations").
# Static by design: it runs on every PR and before any release publishing.
# Usage: verify-release-inventory.sh [REPO_ROOT]

set -Eeuo pipefail
root="${1:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)}"
inventory="${root}/hack/release-artifact-inventory.json"
matrix="${root}/hack/utility-image-matrix.json"
release="${root}/.github/workflows/release.yml"
command -v jq >/dev/null 2>&1 || { echo 'jq is required' >&2; exit 2; }
for f in "${inventory}" "${matrix}" "${release}"; do [[ -f "${f}" ]] || { echo "missing ${f}" >&2; exit 2; }; done

errors=0
fail() { printf 'release inventory: %s\n' "$*" >&2; errors=$((errors + 1)); }

# Flat artifact list: explicit entries plus one per utility image in the matrix.
artifacts="$(jq -c --slurpfile m "${matrix}" '
  .utilityImages as $u
  | .artifacts + [$m[0].images[] | {name: ("utils/" + .name), kind: "image", source: .file,
      publisher: $u.publisher, subject: $u.subject, gateSet: $u.gateSet, context: .context}]
  | .[]' "${inventory}")"

# 1. Everything buildable/packageable is inventoried or explicitly excluded.
inventoried="$(jq -r '.source' <<<"${artifacts}")"
listed="${inventoried}"$'\n'"$(jq -r '.excluded[].source' "${inventory}")"
while IFS= read -r found; do
  found="${found#./}"
  grep -Fxq -- "${found}" <<<"${listed}" || fail "${found} is not in the inventory (list it with signing gates, or exclude it with a reason)"
done < <(cd "${root}" && find . \( -name node_modules -o -name .git -o -name vendor \) -prune -o \( -type f -o -type l \) \
  \( -iname 'Dockerfile' -o -iname 'Dockerfile.*' -o -iname '*.Dockerfile' -o -iname 'Containerfile' -o -iname 'Containerfile.*' -o -name Chart.yaml -o -name Chart.yml \) -print | sort)
# 2. Everything inventoried exists. Exclusions carry a reason and are e2e/
#    fixtures or symlinks to an inventoried source, so a published artifact
#    cannot be moved out of the gates.
while IFS= read -r source; do
  [[ -f "${root}/${source}" ]] || fail "inventoried source ${source} does not exist"
done <<<"${listed}"
while IFS=$'\t' read -r source reason; do
  [[ -n "${reason// /}" ]] || fail "excluded ${source} has no reason"
  [[ "${source}" == e2e/* ]] && continue
  target=""
  if [[ -L "${root}/${source}" ]]; then target="$(readlink "${root}/${source}")"; fi
  if [[ -z "${target}" ]] || ! grep -Fxq -- "${target}" <<<"${inventoried}"; then
    fail "excluded ${source} is not an e2e/ fixture or a symlink to an inventoried source"
  fi
done < <(jq -r '.excluded[] | [.source, (.reason // "")] | @tsv' "${inventory}")

# 3. The hardcoded release.yml utility build matrix (name + context pairs)
#    equals the utility inventory.
want="$(jq -r '.images[] | "name: \(.name) context: \(.context)"' "${matrix}" | sort)"
have="$(grep -B1 -E '^[[:space:]]+context: utils/' "${release}" | grep -v '^--$' | sed -E 's/^[[:space:]]+(- )?//' | paste -d' ' - - | sort)"
[[ "${want}" == "${have}" ]] || fail "release.yml utility build matrix differs from hack/utility-image-matrix.json"

# 4. Each artifact binds a digest subject and has every gate present.
# Comment lines do not count: a commented-out gate is a missing gate.
contains() { awk -v n="$2" '!/^[[:space:]]*#/ && index($0, n) { f = 1; exit } END { exit !f }' "${root}/$1"; }
while IFS= read -r artifact; do
  [[ -n "${artifact}" ]] || continue
  name="$(jq -r .name <<<"${artifact}")"
  publisher="$(jq -r .publisher <<<"${artifact}")"
  subject="$(jq -r .subject <<<"${artifact}")"
  set_name="$(jq -r .gateSet <<<"${artifact}")"
  [[ -f "${root}/${publisher}" ]] || { fail "${name}: publisher ${publisher} missing"; continue; }
  contains "${publisher}" "${subject}" || fail "${name}: digest subject ${subject} not found in ${publisher}"
  [[ "${subject}" == *@* ]] || fail "${name}: subject ${subject} is not digest-bound (tag-only references are mutable)"
  for gate in signature sbom provenance; do
    n="$(jq --arg s "${set_name}" --arg g "${gate}" '.gateSets[$s][$g] // [] | length' "${inventory}")"
    [[ "${n}" -ge 2 ]] || fail "${name}: gate set ${set_name} needs at least a publish and a verify entry for ${gate}"
    while IFS=$'\t' read -r file needle; do
      if [[ ! -f "${root}/${file}" ]] || ! contains "${file}" "${needle}"; then fail "${name}: ${gate} gate missing in ${file}: ${needle}"; fi
    done < <(jq -r --arg s "${set_name}" --arg g "${gate}" '.gateSets[$s][$g][]? | [.file, .contains] | @tsv' "${inventory}")
  done
done <<<"${artifacts}"

# 5. The gate scripts are still invoked from the release workflows.
while IFS=$'\t' read -r file needle; do
  if [[ ! -f "${root}/${file}" ]] || ! contains "${file}" "${needle}"; then fail "gate invocation missing in ${file}: ${needle}"; fi
done < <(jq -r '.invocations[] | [.file, .contains] | @tsv' "${inventory}")

if [[ "${errors}" -gt 0 ]]; then echo "release inventory: ${errors} problem(s)" >&2; exit 1; fi
echo "release inventory verified ($(wc -l <<<"${artifacts}" | tr -d ' ') artifacts)"
