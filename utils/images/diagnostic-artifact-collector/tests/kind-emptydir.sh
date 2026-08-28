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
# shellcheck disable=SC2154
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
    env:
    - name: BREAKGLASS_ARTIFACT_ID
      value: dsa-0123456789abcdef01234567
    - name: BREAKGLASS_ARTIFACT_SESSION_NAMESPACE
      value: breakglass-test
    - name: BREAKGLASS_ARTIFACT_SESSION_NAME
      value: diagnostic-smoke
    - name: BREAKGLASS_ARTIFACT_SESSION_UID
      value: uid-0123456789abcdef
    - name: BREAKGLASS_ARTIFACT_REDACTION_PROFILE
      value: credential-text.v1
    - name: BREAKGLASS_ARTIFACT_REDACTION_VERSION
      value: "1"
    - name: BREAKGLASS_ARTIFACT_UPLOAD_URL
      value: https://127.0.0.1:1/collector
    - name: BREAKGLASS_ARTIFACT_UPLOAD_TOKEN
      value: kind-end-to-end-token
    command: ["/bin/sh", "-ceu"]
    args:
    - |
      /usr/local/bin/diagnostic-artifact-collector collect --recipe system-summary.v1 --output /output/artifact.tar.gz
      for file in artifact.tar.gz artifact.manifest.json artifact.ready; do
        [ "\$(stat -c '%u:%g %a' "/output/\$file")" = '65532:65532 600' ]
        stat -c "/output/\$file %u:%g %a" "/output/\$file"
      done
      if /usr/local/bin/diagnostic-artifact-collector upload --archive /output/artifact.tar.gz >/output/uploader.log 2>&1; then
        echo 'uploader unexpectedly succeeded against closed endpoint' >&2
        exit 1
      fi
      grep -F 'send upload' /output/uploader.log >/dev/null
      rm -f /output/uploader.log
      touch /output/uploader-end-to-end
      echo 'exact uploader contract completed before expected network failure'
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

# A successful pod proves kubelet applied fsGroup to the emptyDir, the
# non-root image created the complete hand-off with its expected ownership and
# modes, and the exact archive reached the real packaged uploader. The closed
# endpoint is intentional: it proves contract verification completed before
# the expected network failure, without introducing a test-only plaintext
# transport.
logs=$(kubectl logs "$pod")
printf '%s\n' "$logs"
printf '%s\n' "$logs" | grep -F '/output/artifact.tar.gz 65532:65532 600' >/dev/null
printf '%s\n' "$logs" | grep -F '/output/artifact.manifest.json 65532:65532 600' >/dev/null
printf '%s\n' "$logs" | grep -F '/output/artifact.ready 65532:65532 600' >/dev/null
printf '%s\n' "$logs" | grep -F 'exact uploader contract completed before expected network failure' >/dev/null
kubectl get pod "$pod" -o jsonpath='{.spec.securityContext.fsGroup}' | grep -Fx 65532 >/dev/null

echo 'Kind emptyDir fsGroup and exact uploader behavior passed'
