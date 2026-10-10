#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
chart_dir="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
for kind in ConfigMap Secret; do
  helm template artifact-ca "$chart_dir" --values "$chart_dir/ci/artifact-upload-ca-values.yaml" \
    --set "profiles[0].artifactCollection.uploadCABundleRef.kind=$kind" |
    ruby -ryaml -e '
      docs = YAML.load_stream(STDIN.read)
      spec = docs.find { |d| d && d["kind"] == "DebugSessionTemplate" }.fetch("spec")
      expected = {"kind"=>ARGV[0], "name"=>"artifact-upload-ca", "key"=>"ca.pem"}
      abort("CA reference render mismatch") unless spec.fetch("artifactCollection").fetch("uploadCABundleRef") == expected
    ' "$kind"
done
if helm template artifact-ca "$chart_dir" --values "$chart_dir/ci/artifact-upload-ca-values.yaml" \
  --set 'profiles[0].artifactCollection.uploadCABundleRef.kind=HostPath' >/dev/null 2>&1; then
  echo "invalid CA bundle kind accepted" >&2
  exit 1
fi
