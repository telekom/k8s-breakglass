#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0
set -euo pipefail
# shellcheck source=e2e/lib/common.sh
source "$(dirname -- "${BASH_SOURCE[0]}")/../../lib/common.sh"
# This script modifies only the disposable Kind E2E fixture.
: "${GITHUB_ENV:?run in the E2E CI job}"
: "${KUBECONFIG:?source the e2e environment first}"
ns=breakglass-system
cluster=${CLUSTER_NAME:-breakglass-hub}
work="$PWD/.artifact-fixture-$$"
mkdir -m 0700 "$work"
trap 'rm -rf "$work"' EXIT
nodes=$(kind get nodes --name "$cluster")
if [[ "${E2E_MULTI_CLUSTER:-false}" == "true" ]]; then
 : "${E2E_SPOKE_A_KUBECONFIG:?source the multi-cluster e2e environment first}"
 nodes="$nodes $(kind get nodes --name spoke-cluster-a)"
fi
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
COPY ca.crt /fixture-ca.crt
RUN cat /fixture-ca.crt >> /etc/ssl/certs/ca-certificates.crt && rm /fixture-ca.crt
COPY --chmod=0755 fixture /fixture
COPY --chmod=0755 minio /minio
COPY MINIO-LICENSE /usr/share/licenses/minio/LICENSE
USER 65532:65532
DOCKER
printf '*\n!Dockerfile\n!ca.crt\n!fixture\n!minio\n!MINIO-LICENSE\n' > "$work/.dockerignore"
docker build -t artifact-collector-e2e:trusted "$work"
docker save artifact-collector-e2e:trusted artifact-collector-e2e:source -o "$work/image.tar"
digest=""
collector_digest=""
for node in $nodes; do
 docker exec -i "$node" ctr -n k8s.io images import - < "$work/image.tar" >/dev/null
 current=$(docker exec "$node" ctr -n k8s.io images list | awk '$1 == "docker.io/library/artifact-collector-e2e:trusted" {print $3}')
 [[ "$current" =~ ^sha256:[a-f0-9]{64}$ ]]
 if [[ -n "$digest" && "$digest" != "$current" ]]; then echo "node image digest mismatch" >&2; exit 1; fi
 digest=$current
 docker exec "$node" ctr -n k8s.io images tag docker.io/library/artifact-collector-e2e:trusted "docker.io/library/artifact-collector-e2e@$digest" >/dev/null
 # Collector Jobs use the untouched production image, not the TLS/backend
 # fixture layer whose system roots include the disposable private CA.
 current_collector=$(docker exec "$node" ctr -n k8s.io images list | awk '$1 == "docker.io/library/artifact-collector-e2e:source" {print $3}')
 [[ "$current_collector" =~ ^sha256:[a-f0-9]{64}$ ]]
 if [[ -n "$collector_digest" && "$collector_digest" != "$current_collector" ]]; then echo "node collector image digest mismatch" >&2; exit 1; fi
 collector_digest=$current_collector
 docker exec "$node" ctr -n k8s.io images tag docker.io/library/artifact-collector-e2e:source "docker.io/library/artifact-collector-e2e@$collector_digest" >/dev/null
 # Harmless synthetic source exists only inside this disposable Kind node.
 docker exec "$node" mkdir -p /var/lib/systemd/coredump
 docker exec "$node" sh -c 'printf "artifact-kind-synthetic-dump\n" > /var/lib/systemd/coredump/core.artifact-kind-fixture; chmod 0644 /var/lib/systemd/coredump/core.artifact-kind-fixture'
done
image="docker.io/library/artifact-collector-e2e@$digest"
export ARTIFACT_FIXTURE_IMAGE="$image"
export ARTIFACT_COLLECTOR_IMAGE="docker.io/library/artifact-collector-e2e@$collector_digest"
# Fail-closed evidence: the controller exits during artifact startup and logs
# the reason. Only the newest Pod counts, so an earlier Pod cannot satisfy it.
expect_fail_closed() {
 local reason=$1 pod
 for _ in $(seq 1 60); do
  pod=$(kubectl -n "$ns" get pods -l app=breakglass --sort-by=.metadata.creationTimestamp -o jsonpath='{.items[-1:].metadata.name}')
  if [[ -n "$pod" ]] && { kubectl -n "$ns" logs "$pod" -c breakglass --tail=200 2>/dev/null || true; kubectl -n "$ns" logs "$pod" -c breakglass --previous --tail=200 2>/dev/null || true; } | grep -F -- "$reason" >/dev/null; then
   echo "controller Pod $pod failed closed: $reason"
   return 0
  fi
  sleep 3
 done
 echo "controller did not fail closed with: $reason" >&2
 kubectl -n "$ns" get pods -l app=breakglass -o wide >&2 || true
 return 1
}
# Renders the opt-in provisioning component as shipped, pointed at the fixture
# claim, the given controller config and the controller image.
provision_job() {
 local name=$1 configmap=$2
 kubectl kustomize config/test-overlays/artifact-local-provision > "$work/overlay.yaml"
 python3 - "$work/overlay.yaml" > "$work/job.yaml" <<'PY'
import sys
docs=open(sys.argv[1]).read().split('\n---\n')
print(next(d for d in docs if '\nkind: Job\n' in '\n'+d+'\n'))
PY
 kubectl create --dry-run=client -o json -f "$work/job.yaml" > "$work/job.json"
 python3 - "$work/job.json" "$name" "$configmap" "$(cat "$work/controller-image")" <<'PY'
import json,sys
path,name,configmap,image=sys.argv[1:]
j=json.load(open(path)); j['metadata']['name']=name; s=j['spec']['template']['spec']
c=s['containers'][0]; c['image']=image; c['imagePullPolicy']='IfNotPresent'
for v in s['volumes']:
    if v['name']=='config': v['configMap']['name']=configmap
    if v['name']=='artifact-data': v['persistentVolumeClaim']['claimName']='artifact-e2e'
open(path,'w').write(json.dumps(j))
PY
 kubectl -n "$ns" apply -f "$work/job.json"
}
set_artifact_claim() {
 local index
 index=$(kubectl -n "$ns" get deployment breakglass-manager -o json | python3 -c 'import json,sys; print(next(i for i,v in enumerate(json.load(sys.stdin)["spec"]["template"]["spec"]["volumes"]) if v["name"]=="artifact-data"))')
 kubectl -n "$ns" patch deployment breakglass-manager --type=json -p "[{\"op\":\"replace\",\"path\":\"/spec/template/spec/volumes/$index/persistentVolumeClaim/claimName\",\"value\":\"$1\"}]"
}
provision_volume() {
 # Opt-in off: a fresh PVC without the provisioning Job keeps failing closed.
 expect_fail_closed "open local artifact root"
 # A stagingDir outside the volume is refused before anything is written; the
 # real Job below must then still report a fresh "provisioned" volume.
 kubectl -n "$ns" get configmap "$config" -o json | python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]; d["config.yaml"]=d["config.yaml"].replace("stagingDir: /artifacts/uploads","stagingDir: /var/lib/breakglass/upload-staging"); print(json.dumps({"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"artifact-e2e-outside-config"},"data":d}))' | kubectl -n "$ns" apply -f -
 provision_job artifact-e2e-outside-provision artifact-e2e-outside-config
 kubectl -n "$ns" wait --for=condition=failed job/artifact-e2e-outside-provision --timeout=180s
 kubectl -n "$ns" logs job/artifact-e2e-outside-provision | grep -F "artifact upload staging directory"
 provision_job breakglass-artifact-provision "$config"
 if ! kubectl -n "$ns" wait --for=condition=complete job/breakglass-artifact-provision --timeout=180s; then
  kubectl -n "$ns" logs job/breakglass-artifact-provision >&2 || true
  exit 1
 fi
 kubectl -n "$ns" logs job/breakglass-artifact-provision | grep -F "local artifact storage provisioned (instance kind-artifact-fixture-v1)"
 # A foreign instance ID on the provisioned volume is refused.
 kubectl -n "$ns" get configmap "$config" -o json | python3 -c 'import json,sys; d=json.load(sys.stdin)["data"]; d["config.yaml"]=d["config.yaml"].replace("instanceID: kind-artifact-fixture-v1","instanceID: kind-artifact-foreign-v1"); print(json.dumps({"apiVersion":"v1","kind":"ConfigMap","metadata":{"name":"artifact-e2e-foreign-config"},"data":d}))' | kubectl -n "$ns" apply -f -
 provision_job artifact-e2e-foreign-provision artifact-e2e-foreign-config
 kubectl -n "$ns" wait --for=condition=failed job/artifact-e2e-foreign-provision --timeout=180s
 kubectl -n "$ns" logs job/artifact-e2e-foreign-provision | grep -F "verify local artifact sentinel"
 # Skip the crash-loop back-off of the fail-closed Pod.
 kubectl -n "$ns" delete pod -l app=breakglass --wait=false
 kubectl -n "$ns" rollout status deployment/breakglass-manager --timeout=180s
 # A repointed, empty volume still fails closed: startup never provisions.
 kubectl -n "$ns" apply -f - <<'YAML'
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: artifact-e2e-repointed
spec:
  accessModes: [ReadWriteOnce]
  resources:
    requests:
      storage: 1Gi
YAML
 set_artifact_claim artifact-e2e-repointed
 expect_fail_closed "open local artifact root"
 set_artifact_claim artifact-e2e
 kubectl -n "$ns" rollout status deployment/breakglass-manager --timeout=180s
}
kubectl -n "$ns" get deployment breakglass-manager -o json > "$work/deployment.json"
config=$(python3 -c 'import json,sys; d=json.load(open(sys.argv[1])); print(next(v["configMap"]["name"] for v in d["spec"]["template"]["spec"]["volumes"] if v["name"]=="config"))' "$work/deployment.json")
kubectl -n "$ns" get configmap "$config" -o json > "$work/config.json"
python3 - "$work" <<'PY'
import json,os,sys
from pathlib import Path
p=Path(sys.argv[1]); image=os.environ['ARTIFACT_FIXTURE_IMAGE']; collector_image=os.environ['ARTIFACT_COLLECTOR_IMAGE']
c=json.loads((p/'config.json').read_text())
c['data']['config.yaml']+='''
artifacts:
  enabled: true
  backend: local
  stagingDir: /artifacts/uploads
  collectorImage: '''+collector_image+'''
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
s.setdefault('initContainers',[]).append({'name':'artifact-ca-bundle','image':image,'imagePullPolicy':'IfNotPresent','command':['/fixture','ca-bundle'],'volumeMounts':[mount],'securityContext':security})
s['containers'].append({'name':'artifact-tls','image':image,'imagePullPolicy':'IfNotPresent','command':['/fixture','serve'],'volumeMounts':[mount,{'name':'artifact-tls','mountPath':'/fixture-tls','readOnly':True},{'name':'artifact-s3-credentials','mountPath':'/fixture-s3','readOnly':True}],'securityContext':security})
s['containers'].append({'name':'artifact-s3','image':image,'imagePullPolicy':'IfNotPresent','command':['/minio','server','/artifacts/minio','--certs-dir','/s3-tls','--address',':9000'],'env':[{'name':'MINIO_ROOT_USER','valueFrom':{'secretKeyRef':{'name':'artifact-e2e-s3','key':'accessKeyID'}}},{'name':'MINIO_ROOT_PASSWORD','valueFrom':{'secretKeyRef':{'name':'artifact-e2e-s3','key':'secretAccessKey'}}},{'name':'MINIO_BROWSER','value':'off'}],'volumeMounts':[mount,{'name':'artifact-s3-tls','mountPath':'/s3-tls','readOnly':True}],'securityContext':security})
(p/'deployment.json').write_text(json.dumps(d))
(p/'controller-image').write_text(controller['image'])
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
if [[ "${E2E_MULTI_CLUSTER:-false}" == "true" ]]; then
 # Spoke Pods use the same verified TLS name, routed to the hub's NodePort.
 # No hub TLS private key, signing key or provider credential leaves the hub.
 kubectl -n "$ns" patch service artifact-e2e --type=merge -p '{"spec":{"type":"NodePort","ports":[{"port":8444,"targetPort":8444,"nodePort":30444}]}}'
 hub_ip=$(docker inspect -f '{{(index .NetworkSettings.Networks "kind").IPAddress}}' "$cluster-control-plane")
 test -n "$hub_ip"
 kubectl --kubeconfig "$E2E_SPOKE_A_KUBECONFIG" -n "$ns" apply -f - <<YAML
apiVersion: v1
kind: Service
metadata:
  name: artifact-e2e
spec:
  ports:
    - name: https
      port: 8444
      targetPort: 30444
---
apiVersion: discovery.k8s.io/v1
kind: EndpointSlice
metadata:
  name: artifact-e2e-hub
  labels:
    kubernetes.io/service-name: artifact-e2e
    endpointslice.kubernetes.io/managed-by: artifact-e2e-fixture
addressType: IPv4
ports:
  - name: https
    protocol: TCP
    port: 30444
endpoints:
  - addresses: ["$hub_ip"]
    conditions:
      ready: true
YAML
fi
kubectl -n "$ns" apply -f - <<'YAML'
apiVersion: v1
kind: Service
metadata:
  name: artifact-s3
spec:
  # Startup verifies this sidecar before the controller Pod can become ready.
  publishNotReadyAddresses: true
  selector:
    app: breakglass
  ports:
    - port: 9000
      targetPort: 9002
YAML
kubectl replace -f "$work/config.json"
kubectl replace -f "$work/deployment.json"
provision_volume
for attempt in $(seq 1 30); do
 if kubectl -n "$ns" exec deployment/breakglass-manager -c artifact-tls -- /fixture s3-ready; then break; fi
 if [[ "$attempt" == 30 ]]; then exit 1; fi
 sleep 2
done
kubectl -n "$ns" exec deployment/breakglass-manager -c artifact-tls -- /fixture s3-provision
wait_for_http "${BREAKGLASS_API_URL:-http://localhost:8080}/api/config" 60 "artifact fixture API port-forward"
printf 'E2E_ARTIFACT_BACKEND=local\n' >> "$GITHUB_ENV"
printf 'E2E_ARTIFACT_IMAGE_DIGEST=%s\n' "$ARTIFACT_COLLECTOR_IMAGE" >> "$GITHUB_ENV"
