#!/usr/bin/env bash
# SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
#
# SPDX-License-Identifier: Apache-2.0

# The parent owns the disposable Kind cluster/namespace. This child owns only
# its fixed fixture ConfigMap and Pod, captured and deleted by immutable UID.
set -Eeuo pipefail
image=${1:?image is required}
namespace=${2:?owned namespace is required}
node=${3:?exact node is required}
script_dir="$(cd -- "$(dirname -- "$0")" && pwd)"
pod=exact-network-repair
configmap=exact-network-fixture
pod_uid=''
configmap_uid=''
KUBECONFIG_FILE=${KUBECONFIG:?owned kubeconfig is required}
# shellcheck disable=SC1091
. "${script_dir}/../../../hack/kubernetes-delete-uid.sh"

cleanup() {
	rc=$?
	set +e
	if [[ "${rc}" != 0 ]]; then kubectl logs -n "${namespace}" "${pod}" >&2 || true; fi
	if [[ -n "${pod_uid}" ]]; then
		kubernetes_delete_uid "${KUBECONFIG_FILE}" "/api/v1/namespaces/${namespace}/pods/${pod}" "${pod_uid}" >/dev/null || rc=1
		kubectl wait -n "${namespace}" --for=delete "pod/${pod}" --timeout=60s >/dev/null || rc=1
	fi
	if [[ -n "${configmap_uid}" ]]; then
		kubernetes_delete_uid "${KUBECONFIG_FILE}" "/api/v1/namespaces/${namespace}/configmaps/${configmap}" "${configmap_uid}" >/dev/null || rc=1
		kubectl get configmap -n "${namespace}" "${configmap}" >/dev/null 2>&1 && rc=1
	fi
	exit "${rc}"
}
trap cleanup EXIT

kubectl create configmap -n "${namespace}" "${configmap}" \
	--from-file=fixture.sh="${script_dir}/exact-network-fixture.sh" >/dev/null
configmap_uid="$(kubectl get configmap -n "${namespace}" "${configmap}" -o jsonpath='{.metadata.uid}')"
kubectl create -n "${namespace}" -f - >/dev/null <<YAML
apiVersion: v1
kind: Pod
metadata:
  name: ${pod}
spec:
  nodeName: ${node}
  hostNetwork: true
  automountServiceAccountToken: false
  restartPolicy: Never
  containers:
    - name: fixture
      image: ${image}
      imagePullPolicy: Never
      command: ["/bin/sh", "/fixture/fixture.sh"]
      env:
        - name: BREAKGLASS_NODE_NAME
          valueFrom:
            fieldRef:
              fieldPath: spec.nodeName
        - name: BREAKGLASS_FIXTURE_ID
          valueFrom:
            fieldRef:
              fieldPath: metadata.uid
      securityContext:
        runAsUser: 0
        runAsGroup: 0
        allowPrivilegeEscalation: false
        privileged: false
        readOnlyRootFilesystem: true
        seccompProfile:
          type: RuntimeDefault
        capabilities:
          drop: [ALL]
          add: [NET_ADMIN]
      volumeMounts:
        - name: evidence
          mountPath: /evidence
        - name: fixture
          mountPath: /fixture
          readOnly: true
  volumes:
    - name: evidence
      emptyDir:
        sizeLimit: 64Mi
    - name: fixture
      configMap:
        name: ${configmap}
YAML
pod_uid="$(kubectl get pod -n "${namespace}" "${pod}" -o jsonpath='{.metadata.uid}')"
kubectl get pod -n "${namespace}" "${pod}" -o json | jq -e --arg node "${node}" --arg configmap "${configmap}" --arg image "${image}" '
	.spec.nodeName == $node and .spec.hostNetwork == true and (.spec.hostPID // false) == false and
	(.spec.hostIPC // false) == false and .spec.automountServiceAccountToken == false and
	(.spec.containers | length) == 1 and (.spec.initContainers // [] | length) == 0 and
	(.spec.ephemeralContainers // [] | length) == 0 and
	.spec.containers[0].name == "fixture" and .spec.containers[0].image == $image and
	.spec.containers[0].command == ["/bin/sh", "/fixture/fixture.sh"] and
	.spec.containers[0].securityContext.runAsUser == 0 and
	.spec.containers[0].securityContext.runAsGroup == 0 and
	.spec.containers[0].securityContext.capabilities.drop == ["ALL"] and
	.spec.containers[0].securityContext.capabilities.add == ["NET_ADMIN"] and
	.spec.containers[0].securityContext.readOnlyRootFilesystem == true and
	.spec.containers[0].securityContext.allowPrivilegeEscalation == false and
	.spec.containers[0].securityContext.privileged == false and
	.spec.containers[0].securityContext.seccompProfile.type == "RuntimeDefault" and
	(.spec.volumes | length) == 2 and
	.spec.volumes[0].name == "evidence" and .spec.volumes[0].emptyDir.sizeLimit == "64Mi" and
	.spec.volumes[1].name == "fixture" and .spec.volumes[1].configMap.name == $configmap and
	all(.spec.volumes[]; has("hostPath") | not) and
	(.spec.containers[0].volumeMounts | length) == 2 and
	.spec.containers[0].volumeMounts[0].name == "evidence" and
	.spec.containers[0].volumeMounts[0].mountPath == "/evidence" and
	.spec.containers[0].volumeMounts[1].name == "fixture" and
	.spec.containers[0].volumeMounts[1].mountPath == "/fixture" and
	.spec.containers[0].volumeMounts[1].readOnly == true
' >/dev/null
for _ in $(seq 1 90); do
	phase="$(kubectl get pod -n "${namespace}" "${pod}" -o jsonpath='{.status.phase}')"
	case "${phase}" in Succeeded) break;; Failed) printf 'Exact-network fixture failed\n' >&2; exit 1;; esac
	sleep 2
done
[[ "${phase}" == Succeeded ]] || { printf 'Exact-network fixture timed out\n' >&2; exit 1; }
kubectl logs -n "${namespace}" "${pod}"
printf 'PASS: Kind exact-node ARP/FDB fixture with NET_ADMIN only\n'
