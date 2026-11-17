#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

# Negative tests for hack/verify-release-inventory.sh: each mutation of a
# scratch copy of the release inputs must make the gate fail.

set -Eeuo pipefail
root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)"
tmp="$(mktemp -d)"; trap 'rm -rf "${tmp}"' EXIT
verify="${root}/hack/verify-release-inventory.sh"

fresh() { # fresh <name>: scratch tree with real gate files and empty source stubs
  local d="${tmp}/$1"; rm -rf "${d}"; mkdir -p "${d}/.github" "${d}/hack"
  cp -R "${root}/.github/workflows" "${d}/.github/workflows"
  cp "${root}"/hack/*.sh "${root}"/hack/*.json "${d}/hack/"
  (cd "${root}" && find . \( -name node_modules -o -name .git -o -name vendor \) -prune -o -type f \( -name 'Dockerfile' -o -name 'Dockerfile.*' -o -name '*.Dockerfile' -o -name Chart.yaml \) -print) |
    while IFS= read -r f; do mkdir -p "${d}/$(dirname "${f}")"; : >"${d}/${f}"; done
  printf '%s' "${d}"
}
expect_fail() { # expect_fail <label> <dir>
  if "${verify}" "$2" >"${tmp}/out" 2>&1; then echo "gate accepted: $1" >&2; exit 1; fi
}
# Remove the first line of $2 (relative to dir $1) containing fixed string $3.
drop_line() { local f="$1/$2"; grep -vF -m1 -- "$3" "${f}" >/dev/null; awk -v n="$3" 'index($0,n)&&!d{d=1;next}1' "${f}" >"${f}.new"; mv "${f}.new" "${f}"; }

d="$(fresh base)"; "${verify}" "${d}" >/dev/null

d="$(fresh unlisted-dockerfile)"; mkdir -p "${d}/utils/new-tool"; : >"${d}/utils/new-tool/Dockerfile"
expect_fail 'unlisted Dockerfile' "${d}"
d="$(fresh unlisted-chart)"; mkdir -p "${d}/charts/new-chart"; : >"${d}/charts/new-chart/Chart.yaml"
expect_fail 'unlisted chart' "${d}"
d="$(fresh matrix-drift)"; sed -i.bak 's#context: utils/node-maintenance#context: utils/other#' "${d}/.github/workflows/release.yml"
expect_fail 'release.yml matrix differs from utility inventory' "${d}"
d="$(fresh listed-missing)"; rm "${d}/charts/escalation-config/Chart.yaml"
expect_fail 'inventoried source missing' "${d}"

d="$(fresh tag-only-subject)"; sed -i.bak 's#"subject": "\\"${IMAGE}@${DIGEST}\\""#"subject": "\\"${IMAGE}:latest\\""#' "${d}/hack/release-artifact-inventory.json"
printf '# \"${IMAGE}:latest\"\n' >>"${d}/.github/workflows/release.yml"
expect_fail 'tag-only subject' "${d}"
d="$(fresh subject-unbound)"; sed -i.bak 's#subject="${docker_remote}@${digest}"#subject="${docker_remote}:${chart_version}"#' "${d}/.github/workflows/release.yml"
expect_fail 'publisher no longer binds digest subject' "${d}"

# Missing signature, SBOM or provenance: publisher side and verifier side.
for case in \
  'controller-sign|.github/workflows/release.yml|cosign sign --yes ${{ env.REGISTRY }}/${{ env.IMAGE_NAME }}@' \
  'controller-sbom-verify|.github/workflows/release.yml|cosign verify-attestation "${REGISTRY_IMAGE}@${DIGEST}"' \
  'controller-provenance-verify|.github/workflows/release.yml|gh attestation verify "oci://${REGISTRY_IMAGE}' \
  'utility-sig-verify|hack/resolve-release-refs.sh|cosign verify "${subject}"' \
  'utility-sbom-verify|hack/verify-utility-publication.sh|cosign verify-attestation "${sbom_subject}"' \
  'utility-provenance-attest|.github/workflows/release.yml|--predicate "utility-${{ matrix.name }}.provenance.json"' \
  'chart-sign|.github/workflows/release.yml|cosign sign --yes "${subject}"' \
  'chart-sbom-attest|.github/workflows/release.yml|cosign attest --yes --type spdxjson --predicate "${sbom}"' \
  'chart-provenance-verify|.github/workflows/release.yml|verify-attestation "${subject}" --type slsaprovenance1'; do
  IFS='|' read -r label file needle <<<"${case}"
  d="$(fresh "${label}")"; drop_line "${d}" "${file}" "${needle}"
  expect_fail "missing gate ${label}" "${d}"
done
echo "release inventory negative tests passed"
