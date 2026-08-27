#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
# SPDX-License-Identifier: Apache-2.0

set -Eeuo pipefail

IMAGE=${STORAGE_DEBUG_IMAGE:?STORAGE_DEBUG_IMAGE must name the already-built local image}
KIND_NODE_IMAGE=${KIND_NODE_IMAGE:-kindest/node:v1.36.1@sha256:3489c7674813ba5d8b1a9977baea8a6e553784dab7b84759d1014dbd78f7ebd5}
RUN_ID="storage-proof-${RANDOM}-${RANDOM}"
CLUSTER=$RUN_ID
NAMESPACE=${RUN_ID}-session
SENTINEL_NAMESPACE=${RUN_ID}-sentinel
STORAGE_CLASS=${RUN_ID}-sc
PV_NAME=${RUN_ID}-pv
ATTACHED_PV_NAME=${RUN_ID}-attached-pv
ATTACHED_PVC_NAME=${RUN_ID}-attached-pvc
ATTACHED_POD_NAME=${RUN_ID}-attached-volume
RUNNER_SA=${RUN_ID}-runner
ROLE=${RUN_ID}-role
CLUSTER_ROLE=${RUN_ID}-cluster-role
JOB=${RUN_ID}-performance
KUBECONFIG_FILE=$(mktemp "${TMPDIR:-/tmp}/storage-kubestr-kubeconfig.XXXXXX")
CLUSTER_CREATED=false

fail() {
    printf 'storage kubestr Kind proof: %s\n' "$1" >&2
    exit 1
}

cleanup() {
    status=$?
    set +e
    if [ "$CLUSTER_CREATED" = true ]; then
        docker exec "${CLUSTER}-control-plane" sh -c \
            "rm -rf -- /var/local/${RUN_ID} /var/local/${RUN_ID}-attached" >/dev/null 2>&1 || status=1
        kind delete cluster --name "$CLUSTER" >/dev/null 2>&1 || status=1
        if kind get clusters 2>/dev/null | grep -Fx -- "$CLUSTER" >/dev/null; then
            printf 'storage kubestr Kind proof: owned cluster survived cleanup: %s\n' "$CLUSTER" >&2
            status=1
        fi
    fi
    rm -f "$KUBECONFIG_FILE"
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' HUP INT TERM

for command_name in docker kind kubectl jq timeout; do
    command -v "$command_name" >/dev/null 2>&1 || fail "$command_name is required"
done
docker image inspect "$IMAGE" >/dev/null 2>&1 || fail "local image is unavailable: $IMAGE"
if kind get clusters 2>/dev/null | grep -Fx -- "$CLUSTER" >/dev/null; then
    fail "refusing to reuse existing cluster $CLUSTER"
fi

kind create cluster --name "$CLUSTER" --image "$KIND_NODE_IMAGE" --kubeconfig "$KUBECONFIG_FILE" --wait 180s >/dev/null
CLUSTER_CREATED=true
kind load docker-image "$IMAGE" --name "$CLUSTER" >/dev/null
export KUBECONFIG=$KUBECONFIG_FILE

image_with_default_tag="${IMAGE}:latest"
mapfile -t source_refs < <(docker exec "${CLUSTER}-control-plane" ctr --namespace k8s.io images list --quiet | \
    awk -v image="$IMAGE" -v image_latest="$image_with_default_tag" '
        $0 == image || $0 == image_latest ||
        (length($0) > length(image) && substr($0, length($0) - length(image) + 1) == image) ||
        (length($0) > length(image_latest) && substr($0, length($0) - length(image_latest) + 1) == image_latest) { print }
    ')
[ "${#source_refs[@]}" -ge 1 ] || fail "could not find a Kind containerd reference for $IMAGE"

source_ref="${source_refs[0]}"
manifest_digest=$(docker exec "${CLUSTER}-control-plane" ctr --namespace k8s.io images list | \
    awk -v ref="$source_ref" '$1 == ref { print $3 }')
if [ "${#source_refs[@]}" -gt 1 ]; then
    mapfile -t matching_digests < <(docker exec "${CLUSTER}-control-plane" ctr --namespace k8s.io images list | \
        awk -v image="$IMAGE" -v image_latest="$image_with_default_tag" '
            $1 == image || $1 == image_latest ||
            (length($1) > length(image) && substr($1, length($1) - length(image) + 1) == image) ||
            (length($1) > length(image_latest) && substr($1, length($1) - length(image_latest) + 1) == image_latest) { print $3 }
        ' | sort -u)
    [ "${#matching_digests[@]}" -eq 1 ] || fail "could not resolve exactly one Kind image digest for $IMAGE"
    manifest_digest="${matching_digests[0]}"
fi
printf '%s\n' "$manifest_digest" | grep -Eq '^sha256:[0-9a-f]{64}$' || \
    fail "Kind did not expose a manifest digest for loaded image $IMAGE"
loaded_ref="docker.io/library/storage-debug@${manifest_digest}"
docker exec "${CLUSTER}-control-plane" ctr --namespace k8s.io images tag "$source_ref" "$loaded_ref" >/dev/null
docker exec "${CLUSTER}-control-plane" ctr --namespace k8s.io images inspect "$loaded_ref" >/dev/null || \
    fail "immutable local containerd reference was not created"

kubectl create namespace "$NAMESPACE" >/dev/null
kubectl label namespace "$NAMESPACE" \
    pod-security.kubernetes.io/enforce=baseline \
    pod-security.kubernetes.io/audit=restricted \
    pod-security.kubernetes.io/warn=restricted >/dev/null
kubectl create namespace "$SENTINEL_NAMESPACE" >/dev/null
kubectl create configmap outside-sentinel --namespace "$SENTINEL_NAMESPACE" --from-literal=value=preserve >/dev/null

for _ in $(seq 1 30); do
    kubectl get serviceaccount default --namespace "$NAMESPACE" >/dev/null 2>&1 && break
    sleep 1
done
kubectl patch serviceaccount default --namespace "$NAMESPACE" --type merge \
    --patch '{"automountServiceAccountToken":false}' >/dev/null

kubectl apply -f - >/dev/null <<YAML
apiVersion: v1
kind: ServiceAccount
metadata:
  name: ${RUNNER_SA}
  namespace: ${NAMESPACE}
automountServiceAccountToken: true
---
apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: ${ROLE}
  namespace: ${NAMESPACE}
rules:
  - apiGroups: [""]
    resources: ["configmaps", "persistentvolumeclaims", "pods"]
    verbs: ["create", "get", "list", "watch", "delete"]
  - apiGroups: [""]
    resources: ["pods/exec"]
    verbs: ["create"]
  - apiGroups: [""]
    resources: ["events"]
    verbs: ["list"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: RoleBinding
metadata:
  name: ${ROLE}
  namespace: ${NAMESPACE}
subjects:
  - kind: ServiceAccount
    name: ${RUNNER_SA}
    namespace: ${NAMESPACE}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: Role
  name: ${ROLE}
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: ${CLUSTER_ROLE}
rules:
  - apiGroups: [""]
    resources: ["nodes"]
    verbs: ["list"]
  - apiGroups: [""]
    resources: ["persistentvolumes"]
    resourceNames: ["${PV_NAME}"]
    verbs: ["get"]
  - apiGroups: [""]
    resources: ["namespaces"]
    resourceNames: ["${NAMESPACE}"]
    verbs: ["get"]
  - apiGroups: ["storage.k8s.io"]
    resources: ["storageclasses"]
    resourceNames: ["${STORAGE_CLASS}"]
    verbs: ["get"]
---
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRoleBinding
metadata:
  name: ${CLUSTER_ROLE}
subjects:
  - kind: ServiceAccount
    name: ${RUNNER_SA}
    namespace: ${NAMESPACE}
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: ${CLUSTER_ROLE}
YAML

runner_identity="system:serviceaccount:${NAMESPACE}:${RUNNER_SA}"
kubectl auth can-i --as "$runner_identity" list nodes | grep -Fx yes >/dev/null || fail "runner cannot perform required node discovery"
kubectl auth can-i --as "$runner_identity" create pods --namespace "$NAMESPACE" | grep -Fx yes >/dev/null || fail "runner cannot create the kubestr child Pod"
for denied in \
    "get secrets --namespace $NAMESPACE" \
    "create roles --namespace $NAMESPACE" \
    "create rolebindings --namespace $NAMESPACE" \
    "create clusterroles" \
    "delete namespaces"; do
    # shellcheck disable=SC2086 # each entry is an intentional kubectl argument vector
    if kubectl auth can-i --as "$runner_identity" $denied | grep -Fx yes >/dev/null; then
        fail "runner received forbidden authorization: $denied"
    fi
done

docker exec "${CLUSTER}-control-plane" sh -c \
    "mkdir -p /var/local/${RUN_ID} /var/local/${RUN_ID}-attached && chown 65532:65532 /var/local/${RUN_ID} /var/local/${RUN_ID}-attached && chmod 0755 /var/local/${RUN_ID} /var/local/${RUN_ID}-attached"
kubectl apply -f - >/dev/null <<YAML
apiVersion: storage.k8s.io/v1
kind: StorageClass
metadata:
  name: ${STORAGE_CLASS}
provisioner: kubernetes.io/no-provisioner
volumeBindingMode: Immediate
---
apiVersion: v1
kind: PersistentVolume
metadata:
  name: ${PV_NAME}
spec:
  capacity:
    storage: 4Gi
  accessModes: ["ReadWriteOnce"]
  persistentVolumeReclaimPolicy: Retain
  storageClassName: ${STORAGE_CLASS}
  hostPath:
    path: /var/local/${RUN_ID}
    type: Directory
---
apiVersion: v1
kind: PersistentVolume
metadata:
  name: ${ATTACHED_PV_NAME}
spec:
  capacity:
    storage: 4Gi
  accessModes: ["ReadWriteOnce"]
  persistentVolumeReclaimPolicy: Retain
  storageClassName: ${STORAGE_CLASS}
  hostPath:
    path: /var/local/${RUN_ID}-attached
    type: Directory
---
apiVersion: v1
kind: ConfigMap
metadata:
  name: session-sentinel
  namespace: ${NAMESPACE}
data:
  value: preserve
---
apiVersion: v1
kind: Pod
metadata:
  name: session-sentinel
  namespace: ${NAMESPACE}
spec:
  automountServiceAccountToken: false
  restartPolicy: Never
  containers:
    - name: sentinel
      image: ${loaded_ref}
      imagePullPolicy: IfNotPresent
      command: ["/bin/sh", "-c", "sleep 600"]
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        seccompProfile:
          type: RuntimeDefault
        capabilities:
          drop: ["ALL"]
YAML
if ! kubectl wait --namespace "$NAMESPACE" --for=condition=Ready pod/session-sentinel --timeout=120s >/dev/null; then
    kubectl describe pod session-sentinel --namespace "$NAMESPACE" >&2 || true
    fail "session sentinel Pod did not become ready"
fi

kubectl apply -f - >/dev/null <<YAML
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: ${ATTACHED_PVC_NAME}
  namespace: ${NAMESPACE}
spec:
  accessModes: ["ReadWriteOnce"]
  resources:
    requests:
      storage: 4Gi
  storageClassName: ${STORAGE_CLASS}
  volumeName: ${ATTACHED_PV_NAME}
---
apiVersion: v1
kind: Pod
metadata:
  name: ${ATTACHED_POD_NAME}
  namespace: ${NAMESPACE}
spec:
  automountServiceAccountToken: false
  restartPolicy: Never
  containers:
    - name: diagnostics
      image: ${loaded_ref}
      imagePullPolicy: IfNotPresent
      args: ["mounted-volume", "--path", "/scratch", "--size-mb", "1", "--runtime-seconds", "1", "--ioping-count", "1"]
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        runAsGroup: 65532
        allowPrivilegeEscalation: false
        readOnlyRootFilesystem: true
        seccompProfile:
          type: RuntimeDefault
        capabilities:
          drop: ["ALL"]
      volumeMounts:
        - name: attached-volume
          mountPath: /scratch
        - name: tmp
          mountPath: /tmp
  volumes:
    - name: attached-volume
      persistentVolumeClaim:
        claimName: ${ATTACHED_PVC_NAME}
    - name: tmp
      emptyDir:
        sizeLimit: 64Mi
YAML

kubectl wait --namespace "$NAMESPACE" --for=jsonpath='{.status.phase}'=Bound pvc/"$ATTACHED_PVC_NAME" --timeout=120s >/dev/null
attached_phase=
for _ in $(seq 1 120); do
    attached_phase=$(kubectl get pod "$ATTACHED_POD_NAME" --namespace "$NAMESPACE" -o jsonpath='{.status.phase}')
    case "$attached_phase" in
        Succeeded) break ;;
        Failed)
            kubectl logs "$ATTACHED_POD_NAME" --namespace "$NAMESPACE" >&2 || true
            fail "mounted-volume operation against an existing Pod PVC failed"
            ;;
    esac
    sleep 1
done
[ "$attached_phase" = Succeeded ] || fail "mounted-volume Pod PVC proof exceeded its 120-second bound"
attached_report=$(kubectl logs "$ATTACHED_POD_NAME" --namespace "$NAMESPACE")
printf '%s\n' "$attached_report" | grep -Fx 'fio_status=pass' >/dev/null || fail "attached PVC fio did not pass"
printf '%s\n' "$attached_report" | grep -Fx 'ioping_status=pass' >/dev/null || fail "attached PVC ioping did not pass"
printf '%s\n' "$attached_report" | grep -Fx 'overall_status=pass' >/dev/null || fail "attached PVC report did not pass"

kubectl delete pod "$ATTACHED_POD_NAME" --namespace "$NAMESPACE" --wait --timeout=120s >/dev/null
kubectl delete pvc "$ATTACHED_PVC_NAME" --namespace "$NAMESPACE" --wait --timeout=120s >/dev/null
kubectl get pod "$ATTACHED_POD_NAME" --namespace "$NAMESPACE" >/dev/null 2>&1 && fail "attached PVC proof Pod survived cleanup"
kubectl get pvc "$ATTACHED_PVC_NAME" --namespace "$NAMESPACE" >/dev/null 2>&1 && fail "attached PVC survived cleanup"
kubectl delete pv "$ATTACHED_PV_NAME" --wait --timeout=120s >/dev/null
kubectl get pv "$ATTACHED_PV_NAME" >/dev/null 2>&1 && fail "attached PVC proof PV survived cleanup"
docker exec "${CLUSTER}-control-plane" sh -c \
    "rm -rf -- /var/local/${RUN_ID}-attached"
if ! docker exec "${CLUSTER}-control-plane" sh -c \
    "test ! -e /var/local/${RUN_ID}-attached"; then
    fail "attached PVC proof hostPath data survived cleanup"
fi

kubectl apply -f - >/dev/null <<YAML
apiVersion: batch/v1
kind: Job
metadata:
  name: ${JOB}
  namespace: ${NAMESPACE}
spec:
  backoffLimit: 0
  activeDeadlineSeconds: 660
  ttlSecondsAfterFinished: 600
  template:
    spec:
      serviceAccountName: ${RUNNER_SA}
      automountServiceAccountToken: true
      restartPolicy: Never
      containers:
        - name: diagnostics
          image: ${loaded_ref}
          imagePullPolicy: IfNotPresent
          args: ["performance", "--storage-class", "${STORAGE_CLASS}", "--pvc-size", "4Gi"]
          env:
            - name: POD_NAMESPACE
              valueFrom:
                fieldRef:
                  fieldPath: metadata.namespace
            - name: STORAGE_DEBUG_WORKLOAD_IMAGE
              value: ${loaded_ref}
          securityContext:
            runAsNonRoot: true
            runAsUser: 65532
            runAsGroup: 65532
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            seccompProfile:
              type: RuntimeDefault
            capabilities:
              drop: ["ALL"]
          volumeMounts:
            - name: tmp
              mountPath: /tmp
      volumes:
        - name: tmp
          emptyDir:
            sizeLimit: 64Mi
YAML

child_pod=
for _ in $(seq 1 180); do
    child_pod=$(kubectl get pods --namespace "$NAMESPACE" -o json | jq -r '
      [.items[] | select(.metadata.generateName == "kubestr-fio-pod-") | .metadata.name] | first // empty
    ')
    [ -z "$child_pod" ] || break
    if kubectl get job "$JOB" --namespace "$NAMESPACE" -o json | jq -e '.status.failed > 0' >/dev/null 2>&1; then
        kubectl logs "job/${JOB}" --namespace "$NAMESPACE" >&2 || true
        fail "kubestr runner failed before creating a child Pod"
    fi
    sleep 1
done
[ -n "$child_pod" ] || fail "did not observe the real kubestr fio child Pod"

kubectl get pod "$child_pod" --namespace "$NAMESPACE" -o json | jq -e --arg image "$loaded_ref" '
  (.spec.hostNetwork // false) == false and
  (.spec.hostPID // false) == false and
  (.spec.hostIPC // false) == false and
  .spec.serviceAccountName == "default" and
  all(.spec.volumes[];
    has("hostPath") | not
  ) and
  all(.spec.volumes[];
    has("projected") | not
  ) and
  (.spec.containers | length == 1) and
  .spec.containers[0].image == $image and
  (.spec.containers[0].securityContext.privileged // false) == false and
  ((.spec.containers[0].securityContext.capabilities.add // []) | length) == 0
' >/dev/null || fail "kubestr child Pod escaped the expected image/namespace/volume/capability boundary"

job_complete=false
for _ in $(seq 1 650); do
    job_status=$(kubectl get job "$JOB" --namespace "$NAMESPACE" -o json)
    if printf '%s\n' "$job_status" | jq -e '(.status.succeeded // 0) > 0' >/dev/null; then
        job_complete=true
        break
    fi
    if printf '%s\n' "$job_status" | jq -e '(.status.failed // 0) > 0' >/dev/null; then
        kubectl describe job "$JOB" --namespace "$NAMESPACE" >&2 || true
        kubectl logs "job/${JOB}" --namespace "$NAMESPACE" >&2 || true
        fail "real kubestr fio workflow failed"
    fi
    sleep 1
done
[ "$job_complete" = true ] || {
    kubectl describe job "$JOB" --namespace "$NAMESPACE" >&2 || true
    kubectl logs "job/${JOB}" --namespace "$NAMESPACE" >&2 || true
    fail "real kubestr fio workflow exceeded the 650-second proof bound"
}
kubectl logs "job/${JOB}" --namespace "$NAMESPACE" | jq -e '
  type == "array" and length == 1 and
  .[0].TestName == "FIO test results" and
  any(.[0].Status[]; .StatusCode == "OK") and
  (.[0].Raw.result.jobs | type == "array" and length == 4) and
  all(.[0].Raw.result.jobs[]; (.jobname | type == "string" and length > 0))
' >/dev/null || fail "kubestr did not emit a successful structured four-job fio result"

kubectl get configmap session-sentinel --namespace "$NAMESPACE" -o jsonpath='{.data.value}' | grep -Fx preserve >/dev/null || fail "session sentinel ConfigMap was changed or deleted"
kubectl get pod session-sentinel --namespace "$NAMESPACE" >/dev/null || fail "session sentinel Pod was deleted"
kubectl get configmap outside-sentinel --namespace "$SENTINEL_NAMESPACE" -o jsonpath='{.data.value}' | grep -Fx preserve >/dev/null || fail "cross-namespace sentinel was changed or deleted"

generated_resources_present() {
    kubectl get pods,configmaps,persistentvolumeclaims --namespace "$NAMESPACE" -o json | jq -e '
      any(.items[];
        (.metadata.name | startswith("kubestr-fio-")) or
        ((.metadata.generateName // "") | startswith("kubestr-fio-"))
      )
    ' >/dev/null
}
for _ in $(seq 1 120); do
    generated_resources_present || break
    sleep 1
done
if generated_resources_present; then
    kubectl get pods,configmaps,persistentvolumeclaims --namespace "$NAMESPACE" >&2
    fail "kubestr left a generated fio resource behind"
fi

printf 'storage kubestr Kind behavior, cleanup, RBAC, and sentinel proofs passed\n'
