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
cat <<'JSON'
{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"platform":{"os":"linux","architecture":"amd64"}},{"platform":{"os":"linux","architecture":"arm64"}}]}
JSON
EOF
cat >"${TEST_DIR}/bin/cosign" <<'EOF'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "${TEST_DIR}/cosign-args"
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

printf '%s\n' 'ghcr.io/example/utility:mutable' >"${TEST_DIR}/invalid-images"
if SUPPLY_CHAIN_RELEASE_TAG=v1.2.3 PATH="${TEST_DIR}/bin:${PATH}" "${SCRIPT_DIR}/verify-catalogue-supply-chain.sh" \
  --images-file "${TEST_DIR}/invalid-images" \
  --chart 'ghcr.io/example/catalogue@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' \
  >/dev/null 2>&1; then
  echo "mutable utility image reference was accepted" >&2
  exit 1
fi

if SUPPLY_CHAIN_RELEASE_TAG=v1.2 PATH="${TEST_DIR}/bin:${PATH}" "${SCRIPT_DIR}/verify-catalogue-supply-chain.sh" \
  --images-file "${TEST_DIR}/images" \
  --chart 'ghcr.io/example/catalogue@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' \
  >/dev/null 2>&1; then
  echo "non-semver release tag was accepted for exact identity binding" >&2
  exit 1
fi

echo "catalogue supply-chain verification behavior passed"
