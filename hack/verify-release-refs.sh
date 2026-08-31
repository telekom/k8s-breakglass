#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

# Behavioral contract test for release reference production. The fake docker
# command proves tags are resolved to one immutable manifest digest and that a
# malformed registry response fails closed.

set -Eeuo pipefail

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
test_dir="$(mktemp -d)"
trap 'rm -rf "${test_dir}"' EXIT
mkdir -p "${test_dir}/bin" "${test_dir}/refs"
ruby -ryaml -e '
  values = YAML.safe_load(File.read(ARGV.fetch(0)), aliases: false)
  %w[workload network storage networkRepair diagnosticArtifactCollector].each do |key|
    values.fetch("images").fetch(key).delete("digest")
    values.fetch("images").fetch(key)["tag"] = "0.1.0"
  end
  File.write(ARGV.fetch(1), values.to_yaml)
' "${script_dir}/../charts/debug-session-catalogue/values.yaml" "${test_dir}/values.yaml"

cat >"${test_dir}/bin/cosign" <<'EOF'
#!/usr/bin/env bash
set -eu
case "$1" in
  verify|verify-attestation) exit 0 ;;
  *) exit 64 ;;
esac
EOF
chmod 700 "${test_dir}/bin/cosign"

cat >"${test_dir}/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -eu
[ "$1 $2 $3" = "buildx imagetools inspect" ]
printf 'Name: %s\nDigest: sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n' "$4"
EOF
chmod 700 "${test_dir}/bin/docker"

PATH="${test_dir}/bin:${PATH}" "${script_dir}/resolve-release-refs.sh" \
  "${test_dir}/values.yaml" "${test_dir}/refs" v0.1.0
[ "$(find "${test_dir}/refs" -name '*.ref' | wc -l | tr -d ' ')" -eq 5 ]
while IFS= read -r ref; do
  IFS='|' read -r name repository digest sbom provenance signature <"${ref}"
  [[ "${name}" =~ ^[a-z][a-z-]*$ ]]
  [[ "${repository}" =~ ^ghcr\.io/telekom/k8s-breakglass/utils/(workload-debug|network-debug|storage-debug|node-maintenance|diagnostic-artifact-collector)$ ]]
  [[ "${digest}" =~ ^sha256:[a-f0-9]{64}$ ]]
  [[ "${sbom}" == verified && "${provenance}" == verified && "${signature}" == verified ]]
done < <(find "${test_dir}/refs" -name '*.ref' -print | sort)

cat >"${test_dir}/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -eu
printf 'Name: %s\nDigest: not-a-digest\n' "$4"
EOF
chmod 700 "${test_dir}/bin/docker"
if PATH="${test_dir}/bin:${PATH}" "${script_dir}/resolve-release-refs.sh" \
  "${test_dir}/values.yaml" "${test_dir}/refs" v0.1.0; then
  echo "malformed registry digest was accepted" >&2
  exit 1
fi

cp "${test_dir}/values.yaml" "${test_dir}/wrong-path-values.yaml"
ruby -pi -e 'gsub("ghcr.io/telekom/k8s-breakglass/utils/workload-debug", "ghcr.io/telekom/k8s-breakglass/workload-debug")' "${test_dir}/wrong-path-values.yaml"
if PATH="${test_dir}/bin:${PATH}" "${script_dir}/resolve-release-refs.sh" \
  "${test_dir}/wrong-path-values.yaml" "${test_dir}/refs" v0.1.0 >/dev/null 2>&1; then
  echo "legacy sibling utility repository was accepted" >&2
  exit 1
fi

if PATH="${test_dir}/bin:${PATH}" "${script_dir}/resolve-release-refs.sh" \
  "${test_dir}/values.yaml" "${test_dir}/refs" v0.1 >/dev/null 2>&1; then
  echo "non-semver release tag was accepted for exact identity binding" >&2
  exit 1
fi

echo "Release reference production behavior passed"
