#!/bin/sh
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -eu

root=$(cd -- "$(dirname -- "$0")/.." && pwd)
image=diagnostic-artifact-collector:kind-test
cluster=diagnostic-artifact-collector
pod=diagnostic-artifact-collector
KIND_NODE_IMAGE=${KIND_NODE_IMAGE:-kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5}
cleanup() {
	kind delete cluster --name "$cluster" >/dev/null 2>&1 || true
	docker image rm "$image" >/dev/null 2>&1 || true
}
trap cleanup EXIT HUP INT TERM

command -v docker >/dev/null 2>&1 || { echo 'Docker is required for Kind fsGroup proof' >&2; exit 1; }
command -v kind >/dev/null 2>&1 || { echo 'Kind is required for fsGroup proof' >&2; exit 1; }
command -v kubectl >/dev/null 2>&1 || { echo 'kubectl is required for fsGroup proof' >&2; exit 1; }

docker build --tag "$image" "$root"
kind create cluster --name "$cluster" --image "$KIND_NODE_IMAGE" --wait 90s
kind load docker-image "$image" --name "$cluster"
kubectl apply -f - <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: $pod
spec:
  restartPolicy: Never
  securityContext:
    runAsNonRoot: true
    runAsUser: 65532
    runAsGroup: 65532
    fsGroup: 65532
    fsGroupChangePolicy: OnRootMismatch
  containers:
  - name: collector
    image: $image
    imagePullPolicy: Never
    command: ["/usr/local/bin/diagnostic-artifact-collector"]
    args: ["collect", "--recipe", "system-summary.v1", "--output", "/output/artifact.tar.gz"]
    securityContext:
      allowPrivilegeEscalation: false
      capabilities:
        drop: ["ALL"]
      readOnlyRootFilesystem: true
    volumeMounts:
    - name: output
      mountPath: /output
  volumes:
  - name: output
    emptyDir: {}
EOF
kubectl wait --for=jsonpath='{.status.phase}'=Succeeded "pod/$pod" --timeout=120s

# A successful pod proves kubelet applied fsGroup to the emptyDir and the
# non-root image was able to create its complete three-file hand-off there.
kubectl logs "$pod" >/dev/null
kubectl get pod "$pod" -o jsonpath='{.spec.securityContext.fsGroup}' | grep -Fx 65532 >/dev/null

echo 'Kind emptyDir fsGroup behavior passed'
