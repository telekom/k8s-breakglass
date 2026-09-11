#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
: "${GITHUB_ENV:?CI fixture only}"
ns=breakglass-system
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
config=$(kubectl -n "$ns" get deployment breakglass-manager -o jsonpath='{.spec.template.spec.volumes[?(@.name=="config")].configMap.name}')
kubectl -n "$ns" get configmap "$config" -o json > "$work/config.json"
python3 - "$work/config.json" <<'PY'
import json,sys
p=sys.argv[1]; d=json.load(open(p)); text=d['data']['config.yaml']
assert '\n  backend: local\n' in text
text=text.replace('\n  backend: local\n','\n  backend: s3\n')
text=text[:text.index('\n  local:\n')]+'''
  s3:
    endpoint: https://artifact-s3.breakglass-system.svc:9000
    region: us-east-1
    bucket: artifact-kind
    prefix: e2e
    instanceID: kind-artifact-s3-fixture-v1
    usePathStyle: true
    requireVersioned: true
    credentialsSecretName: artifact-e2e-s3
'''
d['data']['config.yaml']=text
open(p,'w').write(json.dumps(d))
PY
kubectl replace -f "$work/config.json"
kubectl -n "$ns" rollout restart deployment/breakglass-manager
kubectl -n "$ns" rollout status deployment/breakglass-manager --timeout=180s
printf 'E2E_ARTIFACT_BACKEND=s3\n' >> "$GITHUB_ENV"
