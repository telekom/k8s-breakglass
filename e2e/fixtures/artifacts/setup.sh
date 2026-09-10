#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
# This script modifies only the disposable single-cluster E2E fixture.
: "${GITHUB_ENV:?run in the single-cluster CI job}"
: "${KUBECONFIG:?source the single-cluster e2e environment first}"
ns=breakglass-system
cluster=${CLUSTER_NAME:-breakglass-hub}
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
nodes=$(kind get nodes --name "$cluster")
test -n "$nodes"
# Fresh keys belong only to this disposable fixture and are never logged.
openssl req -x509 -newkey rsa:2048 -nodes -days 1 -subj /CN=artifact-kind-ca -keyout "$work/ca.key" -out "$work/ca.crt" >/dev/null 2>&1
openssl req -newkey rsa:2048 -nodes -subj /CN=artifact-e2e -keyout "$work/tls.key" -out "$work/tls.csr" >/dev/null 2>&1
printf 'subjectAltName=DNS:artifact-e2e.breakglass-system.svc,DNS:artifact-e2e.breakglass-system.svc.cluster.local\nextendedKeyUsage=serverAuth\n' > "$work/extensions"
openssl x509 -req -in "$work/tls.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" -CAcreateserial -days 1 -extfile "$work/extensions" -out "$work/tls.crt" >/dev/null 2>&1
kubectl -n "$ns" create secret tls artifact-e2e-tls --cert="$work/tls.crt" --key="$work/tls.key"
openssl rand 32 > "$work/signing"
kubectl -n "$ns" create secret generic artifact-e2e-signing --from-file=kind="$work/signing"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$work/fixture" ./e2e/fixtures/artifacts
docker build -t artifact-collector-e2e:source utils/images/diagnostic-artifact-collector
cat > "$work/Dockerfile" <<'DOCKER'
FROM artifact-collector-e2e:source
USER 0
COPY ca.crt /tmp/fixture-ca.crt
RUN cat /tmp/fixture-ca.crt >> /etc/ssl/certs/ca-certificates.crt && rm /tmp/fixture-ca.crt
COPY --chmod=0755 fixture /fixture
USER 65532:65532
DOCKER
printf '*\n!Dockerfile\n!ca.crt\n!fixture\n' > "$work/.dockerignore"
docker build -t artifact-collector-e2e:trusted "$work"
docker save artifact-collector-e2e:trusted -o "$work/image.tar"
digest=""
for node in $nodes; do
 docker cp "$work/image.tar" "$node:/tmp/artifact-e2e.tar"
 docker exec "$node" ctr -n k8s.io images import /tmp/artifact-e2e.tar >/dev/null
 current=$(docker exec "$node" ctr -n k8s.io images list | awk '$1 == "docker.io/library/artifact-collector-e2e:trusted" {print $3}')
 [[ "$current" =~ ^sha256:[a-f0-9]{64}$ ]]
 if [[ -n "$digest" && "$digest" != "$current" ]]; then echo "node image digest mismatch" >&2; exit 1; fi
 digest=$current
 docker exec "$node" ctr -n k8s.io images tag docker.io/library/artifact-collector-e2e:trusted "docker.io/library/artifact-collector-e2e@$digest" >/dev/null
 docker exec "$node" rm /tmp/artifact-e2e.tar
done
image="docker.io/library/artifact-collector-e2e@$digest"
export ARTIFACT_FIXTURE_IMAGE="$image"
kubectl -n "$ns" get deployment breakglass-manager -o json > "$work/deployment.json"
config=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(next(v["configMap"]["name"] for v in d["spec"]["template"]["spec"]["volumes"] if v["name"]=="config"))' "$work/deployment.json")
kubectl -n "$ns" get configmap "$config" -o json > "$work/config.json"
python3 - "$work" <<'PY'
import json,os,sys
from pathlib import Path
p=Path(sys.argv[1]); image=os.environ['ARTIFACT_FIXTURE_IMAGE']
c=json.loads((p/'config.json').read_text())
c['data']['config.yaml']+='''
artifacts:
  enabled: true
  backend: local
  stagingDir: /artifacts/uploads
  collectorImage: '''+image+'''
  controllerURL: https://artifact-e2e.breakglass-system.svc:8444
  uploadMaxBytes: 16777216
  tokenSecretName: artifact-e2e-signing
  tokenSignerKeyID: kind
  local:
    privateRootAcknowledged: true
    artifactRoot: /artifacts/objects
    stagingRoot: /artifacts/staging
    instanceID: kind-artifact-fixture-v1
    expectedUID: 65532
    expectedGID: 65532
    servingReplicas: 1
    accessMode: ReadWriteOnce
    deploymentStrategy: Recreate
    encryptionAcknowledged: true
    snapshotPolicy: prohibited
    maximumObjectBytes: 16777216
'''
(p/'config.json').write_text(json.dumps(c))
d=json.loads((p/'deployment.json').read_text()); d['spec']['replicas']=1; d['spec']['strategy']={'type':'Recreate'}
s=d['spec']['template']['spec']; s['volumes'] += [{'name':'artifact-data','persistentVolumeClaim':{'claimName':'artifact-e2e'}},{'name':'artifact-tls','secret':{'secretName':'artifact-e2e-tls'}}]
mount={'name':'artifact-data','mountPath':'/artifacts'}
next(c for c in s['containers'] if c['name']=='breakglass')['volumeMounts'].append(mount)
security={'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']},'runAsUser':65532,'runAsGroup':65532}
s.setdefault('initContainers',[]).append({'name':'artifact-provision','image':image,'imagePullPolicy':'IfNotPresent','command':['/fixture','provision'],'volumeMounts':[mount],'securityContext':security})
s['containers'].append({'name':'artifact-tls','image':image,'imagePullPolicy':'IfNotPresent','command':['/fixture','serve'],'volumeMounts':[mount,{'name':'artifact-tls','mountPath':'/fixture-tls','readOnly':True}],'securityContext':security})
(p/'deployment.json').write_text(json.dumps(d))
PY
kubectl -n "$ns" apply -f - <<'YAML'
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: artifact-e2e
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 1Gi
---
apiVersion: v1
kind: Service
metadata:
  name: artifact-e2e
spec:
  selector:
    app: breakglass
  ports:
    - port: 8444
      targetPort: 8444
YAML
kubectl replace -f "$work/config.json"
kubectl replace -f "$work/deployment.json"
kubectl -n "$ns" rollout status deployment/breakglass-manager --timeout=180s
printf 'E2E_ARTIFACT_IMAGE_DIGEST=%s\n' "$image" >> "$GITHUB_ENV"
