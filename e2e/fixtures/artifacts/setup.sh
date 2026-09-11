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
printf 'subjectAltName=DNS:artifact-e2e.breakglass-system.svc,DNS:artifact-e2e.breakglass-system.svc.cluster.local,DNS:artifact-s3.breakglass-system.svc\nextendedKeyUsage=serverAuth\n' > "$work/extensions"
openssl x509 -req -in "$work/tls.csr" -CA "$work/ca.crt" -CAkey "$work/ca.key" -CAcreateserial -days 1 -extfile "$work/extensions" -out "$work/tls.crt" >/dev/null 2>&1
kubectl -n "$ns" create secret generic artifact-e2e-tls --type=kubernetes.io/tls --from-file=tls.crt="$work/tls.crt" --from-file=tls.key="$work/tls.key" --from-file=ca.crt="$work/ca.crt"
openssl rand 32 > "$work/signing"
kubectl -n "$ns" create secret generic artifact-e2e-signing --from-file=kind="$work/signing"
openssl rand -hex 12 | tr -d '\n' > "$work/accessKeyID"
openssl rand -hex 24 | tr -d '\n' > "$work/secretAccessKey"
kubectl -n "$ns" create secret generic artifact-e2e-s3 --from-file=accessKeyID="$work/accessKeyID" --from-file=secretAccessKey="$work/secretAccessKey"
# Official source-only security release; never use the older registry image.
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 GOBIN="$work" go install github.com/minio/minio@9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a
module_dir=$(go mod download -json github.com/minio/minio@9e49d5e7a648f00e26f2246f4dc28e6b07f8c84a | python3 -c 'import json,sys; print(json.load(sys.stdin)["Dir"])')
cp "$module_dir/LICENSE" "$work/MINIO-LICENSE"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o "$work/fixture" ./e2e/fixtures/artifacts
docker build -t artifact-collector-e2e:source utils/images/diagnostic-artifact-collector
cat > "$work/Dockerfile" <<'DOCKER'
FROM artifact-collector-e2e:source
USER 0
COPY ca.crt /tmp/fixture-ca.crt
RUN cat /tmp/fixture-ca.crt >> /etc/ssl/certs/ca-certificates.crt && rm /tmp/fixture-ca.crt
COPY --chmod=0755 fixture /fixture
COPY --chmod=0755 minio /minio
COPY MINIO-LICENSE /usr/share/licenses/minio/LICENSE
USER 65532:65532
DOCKER
printf '*\n!Dockerfile\n!ca.crt\n!fixture\n!minio\n!MINIO-LICENSE\n' > "$work/.dockerignore"
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
 # Harmless synthetic source exists only inside this disposable Kind node.
 docker exec "$node" mkdir -p /var/lib/systemd/coredump
 docker exec "$node" sh -c 'printf "artifact-kind-synthetic-dump\n" > /var/lib/systemd/coredump/core.artifact-kind-fixture; chmod 0644 /var/lib/systemd/coredump/core.artifact-kind-fixture'
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
s=d['spec']['template']['spec']; s['volumes'] += [{'name':'artifact-data','persistentVolumeClaim':{'claimName':'artifact-e2e'}},{'name':'artifact-tls','secret':{'secretName':'artifact-e2e-tls'}},{'name':'artifact-s3-credentials','secret':{'secretName':'artifact-e2e-s3'}},{'name':'artifact-s3-tls','secret':{'secretName':'artifact-e2e-tls','items':[{'key':'tls.crt','path':'public.crt'},{'key':'tls.key','path':'private.key'},{'key':'ca.crt','path':'CAs/fixture-ca.crt'}]}}]
mount={'name':'artifact-data','mountPath':'/artifacts'}
controller=next(c for c in s['containers'] if c['name']=='breakglass')
controller['volumeMounts'].append(mount)
controller.setdefault('env',[]).append({'name':'SSL_CERT_FILE','value':'/artifacts/ca-bundle.pem'})
security={'allowPrivilegeEscalation':False,'readOnlyRootFilesystem':True,'capabilities':{'drop':['ALL']},'runAsUser':65532,'runAsGroup':65532}
s.setdefault('initContainers',[]).append({'name':'artifact-provision','image':image,'imagePullPolicy':'IfNotPresent','command':['/fixture','provision'],'volumeMounts':[mount],'securityContext':security})
s['containers'].append({'name':'artifact-tls','image':image,'imagePullPolicy':'IfNotPresent','command':['/fixture','serve'],'volumeMounts':[mount,{'name':'artifact-tls','mountPath':'/fixture-tls','readOnly':True},{'name':'artifact-s3-credentials','mountPath':'/fixture-s3','readOnly':True}],'securityContext':security})
s['containers'].append({'name':'artifact-s3','image':image,'imagePullPolicy':'IfNotPresent','command':['/minio','server','/artifacts/minio','--certs-dir','/s3-tls','--address',':9000'],'env':[{'name':'MINIO_ROOT_USER','valueFrom':{'secretKeyRef':{'name':'artifact-e2e-s3','key':'accessKeyID'}}},{'name':'MINIO_ROOT_PASSWORD','valueFrom':{'secretKeyRef':{'name':'artifact-e2e-s3','key':'secretAccessKey'}}},{'name':'MINIO_BROWSER','value':'off'}],'volumeMounts':[mount,{'name':'artifact-s3-tls','mountPath':'/s3-tls','readOnly':True}],'securityContext':security})
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
kubectl -n "$ns" apply -f - <<'YAML'
apiVersion: v1
kind: Service
metadata:
  name: artifact-s3
spec:
  selector:
    app: breakglass
  ports:
    - port: 9000
      targetPort: 9002
YAML
kubectl replace -f "$work/config.json"
kubectl replace -f "$work/deployment.json"
kubectl -n "$ns" rollout status deployment/breakglass-manager --timeout=180s
for attempt in $(seq 1 30); do
 if kubectl -n "$ns" exec deployment/breakglass-manager -c artifact-tls -- /fixture s3-ready; then break; fi
 if [[ "$attempt" == 30 ]]; then exit 1; fi
 sleep 2
done
kubectl -n "$ns" exec deployment/breakglass-manager -c artifact-tls -- /fixture s3-provision
printf 'E2E_ARTIFACT_BACKEND=local\n' >> "$GITHUB_ENV"
printf 'E2E_ARTIFACT_IMAGE_DIGEST=%s\n' "$image" >> "$GITHUB_ENV"
