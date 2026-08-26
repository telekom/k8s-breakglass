#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
TEST_DIR="$(mktemp -d)"
trap 'rm -rf "${TEST_DIR}"' EXIT

mkdir -p "${TEST_DIR}/bin"
printf '%s\n' \
  'ghcr.io/example/utility@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa' \
  '# comments and blank lines are ignored' \
  > "${TEST_DIR}/images"

cat > "${TEST_DIR}/bin/docker" <<'EOF'
#!/usr/bin/env bash
cat <<'JSON'
{"schemaVersion":2,"mediaType":"application/vnd.oci.image.index.v1+json","manifests":[{"platform":{"os":"linux","architecture":"amd64"}},{"platform":{"os":"linux","architecture":"arm64"}}]}
JSON
EOF
cat > "${TEST_DIR}/bin/cosign" <<'EOF'
#!/usr/bin/env bash
exit 0
EOF
chmod +x "${TEST_DIR}/bin/docker" "${TEST_DIR}/bin/cosign"

PATH="${TEST_DIR}/bin:${PATH}" "${SCRIPT_DIR}/verify-catalogue-supply-chain.sh" \
  --images-file "${TEST_DIR}/images" \
  --chart 'ghcr.io/example/catalogue@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' \
  >/dev/null

printf '%s\n' 'ghcr.io/example/utility:mutable' > "${TEST_DIR}/invalid-images"
if PATH="${TEST_DIR}/bin:${PATH}" "${SCRIPT_DIR}/verify-catalogue-supply-chain.sh" \
  --images-file "${TEST_DIR}/invalid-images" \
  --chart 'ghcr.io/example/catalogue@sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb' \
  >/dev/null 2>&1; then
  echo "mutable utility image reference was accepted" >&2
  exit 1
fi

python3 - "${SCRIPT_DIR}/../.github/workflows/release.yml" <<'PY'
import sys
from pathlib import Path

workflow = Path(sys.argv[1]).read_text()
publish = workflow.split("Publish debug-session-catalogue chart when present", 1)[1]
publish = publish.split("Sign and verify immutable chart contracts", 1)[0]
assert 'helm push "${chart_package}" "${CHART_REPO}"' in publish, "catalogue package is not published"
assert "remote_metadata" in publish, "catalogue publication is not rerun-safe"
assert "SUPPLY_CHAIN_IDENTITY_REGEXP: https://github.com/telekom/k8s-breakglass/.github/workflows/release.yml@refs/tags/v[0-9].*" in workflow, "identity scope is too broad"
assert 'cosign verify-attestation "${subject}" --type slsaprovenance' in workflow, "chart provenance is not verified"
integration = Path(sys.argv[1]).with_name("catalogue-utility-integration.yml").read_text()
assert "docker/setup-qemu-action@29109295f81e9208d7d86ff1c6c12d2833863392" in integration, "QEMU action is not pinned"
assert "docker/setup-buildx-action@37fe631027851001ddb9b187196cc803ef7f5f0e" in integration, "Buildx action is not pinned"
assert "linux/amd64,linux/arm64" in integration, "integration proof does not build both architectures"
PY

echo "catalogue supply-chain verification tests passed"
