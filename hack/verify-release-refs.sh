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

ruby -ryaml -e '
  values = YAML.load_file(ARGV.fetch(0))
  %w[workload network storage networkRepair diagnosticArtifactCollector].each do |key|
    values.fetch("images").fetch(key).delete("digest")
    values.fetch("images").fetch(key)["tag"] = "ci"
  end
  File.write(ARGV.fetch(1), values.to_yaml)
' "${script_dir}/../charts/debug-session-catalogue/values.yaml" "${test_dir}/values.yaml"

PATH="${test_dir}/bin:${PATH}" "${script_dir}/resolve-release-refs.sh" \
  "${test_dir}/values.yaml" "${test_dir}/refs"
[ "$(find "${test_dir}/refs" -name '*.ref' | wc -l | tr -d ' ')" -eq 5 ]
while IFS= read -r ref; do
  [[ "$(cat "${ref}")" =~ ^[a-z-]+\|ghcr\.io/telekom/k8s-breakglass/[^|]+\|sha256:[a-f0-9]{64}$ ]]
done < <(find "${test_dir}/refs" -name '*.ref' -print | sort)

cat >"${test_dir}/bin/docker" <<'EOF'
#!/usr/bin/env bash
set -eu
printf 'Name: %s\nDigest: not-a-digest\n' "$4"
EOF
chmod 700 "${test_dir}/bin/docker"
if PATH="${test_dir}/bin:${PATH}" "${script_dir}/resolve-release-refs.sh" \
  "${test_dir}/values.yaml" "${test_dir}/refs"; then
  echo "malformed registry digest was accepted" >&2
  exit 1
fi

echo "Release reference production behavior passed"
