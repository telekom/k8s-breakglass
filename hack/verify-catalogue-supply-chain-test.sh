#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="$(mktemp -d)"
trap 'rm -rf "${TEST_DIR}"' EXIT

mkdir -p "${TEST_DIR}/bin"
export TEST_DIR
printf '%s\n' \
  'ghcr.io/example/utility@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
  '# comments and blank lines are ignored' \
  >"${TEST_DIR}/images"

cat >"${TEST_DIR}/bin/docker" <<'EOF'
#!/usr/bin/env bash
case "${TEST_MANIFEST_VARIANT:-valid}" in
  valid)
    manifests='{"platform":{"os":"linux","architecture":"amd64"}},{"platform":{"os":"linux","architecture":"arm64"}}'
    ;;
  attestation)
    manifests='{"platform":{"os":"linux","architecture":"amd64"}},{"platform":{"os":"linux","architecture":"arm64"}},{"annotations":{"vnd.docker.reference.type":"attestation-manifest"}}'
    ;;
  duplicate)
    manifests='{"platform":{"os":"linux","architecture":"amd64"}},{"platform":{"os":"linux","architecture":"amd64"}},{"platform":{"os":"linux","architecture":"arm64"}}'
    ;;
  extra)
    manifests='{"platform":{"os":"linux","architecture":"amd64"}},{"platform":{"os":"linux","architecture":"arm64"}},{"platform":{"os":"linux","architecture":"s390x"}}'
    ;;
  *)
    echo "unknown manifest variant" >&2
    exit 1
    ;;
esac
printf '{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[%s]}\n' "$manifests"
EOF
cat >"${TEST_DIR}/bin/cosign" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${TEST_DIR}/cosign-args"
# COSIGN_FAIL=<signature|sbom|provenance> fails that evidence class;
# COSIGN_FAIL_SUBJECT limits the failure to subjects containing the substring.
if [[ -n "${COSIGN_FAIL:-}" && "$*" == *"${COSIGN_FAIL_SUBJECT:-}"* ]]; then
  case "${COSIGN_FAIL}:$1:$*" in
    signature:verify:*|sbom:verify-attestation:*--type\ spdxjson*|provenance:verify-attestation:*--type\ slsaprovenance1*) exit 1 ;;
  esac
fi
exit 0
EOF
chmod +x "${TEST_DIR}/bin/docker" "${TEST_DIR}/bin/cosign"

SUPPLY_CHAIN_RELEASE_TAG=v1.2.3 PATH="${TEST_DIR}/bin:${PATH}" "${SCRIPT_DIR}/verify-catalogue-supply-chain.sh" \
  --images-file "${TEST_DIR}/images" \
  --chart 'ghcr.io/example/catalogue@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' \
  >/dev/null
grep -F -- '--certificate-identity https://github.com/telekom/k8s-breakglass/.github/workflows/release.yml@refs/tags/v1.2.3' "${TEST_DIR}/cosign-args" >/dev/null
if grep -F -- '--certificate-identity-regexp' "${TEST_DIR}/cosign-args" >/dev/null; then
  echo "catalogue verification used a broad identity regexp" >&2
  exit 1
fi

SUPPLY_CHAIN_RELEASE_TAG=v1.2.3-rc-1 PATH="${TEST_DIR}/bin:${PATH}" "${SCRIPT_DIR}/verify-catalogue-supply-chain.sh" \
  --images-file "${TEST_DIR}/images" \
  --chart 'ghcr.io/example/catalogue@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' \
  >/dev/null

for variant in duplicate extra; do
  if TEST_MANIFEST_VARIANT="$variant" SUPPLY_CHAIN_RELEASE_TAG=v1.2.3 PATH="${TEST_DIR}/bin:${PATH}" \
    "${SCRIPT_DIR}/verify-catalogue-supply-chain.sh" \
    --images-file "${TEST_DIR}/images" \
    --chart 'ghcr.io/example/catalogue@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' \
    >/dev/null 2>&1; then
    echo "${variant} image manifest was accepted" >&2
    exit 1
  fi
done

TEST_MANIFEST_VARIANT=attestation SUPPLY_CHAIN_RELEASE_TAG=v1.2.3 PATH="${TEST_DIR}/bin:${PATH}" \
  "${SCRIPT_DIR}/verify-catalogue-supply-chain.sh" \
  --images-file "${TEST_DIR}/images" \
  --chart 'ghcr.io/example/catalogue@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' \
  >/dev/null

printf '%s\n' 'ghcr.io/example/utility:mutable' >"${TEST_DIR}/invalid-images"
if SUPPLY_CHAIN_RELEASE_TAG=v1.2.3 PATH="${TEST_DIR}/bin:${PATH}" "${SCRIPT_DIR}/verify-catalogue-supply-chain.sh" \
  --images-file "${TEST_DIR}/invalid-images" \
  --chart 'ghcr.io/example/catalogue@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' \
  >/dev/null 2>&1; then
  echo "mutable utility image reference was accepted" >&2
  exit 1
fi

for invalid_tag in v1.2 v1.2.3-. v1.2.3-a..b v1.2.3-01; do
  if SUPPLY_CHAIN_RELEASE_TAG="${invalid_tag}" PATH="${TEST_DIR}/bin:${PATH}" "${SCRIPT_DIR}/verify-catalogue-supply-chain.sh" \
    --images-file "${TEST_DIR}/images" \
    --chart 'ghcr.io/example/catalogue@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' \
    >/dev/null 2>&1; then
    echo "invalid semver release tag was accepted for exact identity binding: ${invalid_tag}" >&2
    exit 1
  fi
done

# Missing signature, missing/tampered SBOM and missing/tampered provenance
# (cosign refusing the evidence) must each fail, for a utility image and for
# the catalogue chart subject independently.
chart_ref='ghcr.io/example/catalogue@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb'
for failing in signature sbom provenance; do
  for only in utility catalogue; do
    if COSIGN_FAIL="${failing}" COSIGN_FAIL_SUBJECT="example/${only}" SUPPLY_CHAIN_RELEASE_TAG=v1.2.3 PATH="${TEST_DIR}/bin:${PATH}" \
      "${SCRIPT_DIR}/verify-catalogue-supply-chain.sh" --images-file "${TEST_DIR}/images" --chart "${chart_ref}" >/dev/null 2>&1; then
      echo "failing ${failing} evidence for ${only} was accepted" >&2
      exit 1
    fi
  done
done

# Mutable (tag-only) chart references are refused just like utility images.
for mutable_chart in ghcr.io/example/catalogue:latest ghcr.io/example/catalogue:v1.2.3 oci://ghcr.io/example/catalogue@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb; do
  if SUPPLY_CHAIN_RELEASE_TAG=v1.2.3 PATH="${TEST_DIR}/bin:${PATH}" "${SCRIPT_DIR}/verify-catalogue-supply-chain.sh" \
    --images-file "${TEST_DIR}/images" --chart "${mutable_chart}" >/dev/null 2>&1; then
    echo "mutable chart reference was accepted: ${mutable_chart}" >&2
    exit 1
  fi
done

# Empty or tag-only inventories cannot satisfy the gate.
: >"${TEST_DIR}/empty-images"
if SUPPLY_CHAIN_RELEASE_TAG=v1.2.3 PATH="${TEST_DIR}/bin:${PATH}" "${SCRIPT_DIR}/verify-catalogue-supply-chain.sh" \
  --images-file "${TEST_DIR}/empty-images" --chart "${chart_ref}" >/dev/null 2>&1; then
  echo "empty utility image list was accepted" >&2
  exit 1
fi

echo "catalogue supply-chain verification behavior passed"
