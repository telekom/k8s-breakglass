{{/*
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
*/}}
{{- define "debug-session-catalogue.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- define "debug-session-catalogue.fullname" -}}
{{- if .Values.fullnameOverride -}}{{ .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}{{- else -}}{{ include "debug-session-catalogue.name" . }}{{- end -}}
{{- end -}}
{{- define "debug-session-catalogue.labels" -}}
app.kubernetes.io/name: {{ include "debug-session-catalogue.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | quote }}
{{- end -}}
{{- define "debug-session-catalogue.profileName" -}}
{{- $raw := printf "%s-%s" (include "debug-session-catalogue.fullname" .root) .profile.name -}}
{{- if gt (len $raw) 63 -}}
{{- printf "%s-%s" ($raw | trunc 54 | trimSuffix "-") ($raw | sha256sum | trunc 8) -}}
{{- else -}}
{{- $raw | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- define "debug-session-catalogue.image" -}}
{{- $profile := .profile -}}
{{- if $profile.image -}}
{{- required (printf "profiles[%s].image.repository is required" $profile.name) $profile.image.repository -}}{{- if $profile.image.digest }}@{{ $profile.image.digest }}{{ else }}:{{ required (printf "profiles[%s].image.tag is required" $profile.name) $profile.image.tag }}{{ end -}}
{{- else -}}
{{- $key := required (printf "profiles[%s].imageKey or image is required" $profile.name) $profile.imageKey -}}
{{- $image := index .root.Values.images $key -}}
{{- if not $image }}{{ fail (printf "profiles[%s] references missing image key %s" $profile.name $key) }}{{ end -}}
{{- required (printf "images.%s.repository is required" $key) $image.repository -}}{{- if $image.digest }}@{{ $image.digest }}{{ else }}:{{ required (printf "images.%s.tag is required" $key) $image.tag }}{{ end -}}
{{- end -}}
{{- end -}}
{{- define "debug-session-catalogue.podSecurity" -}}
{{- $profile := .profile -}}
{{- $elevated := default false $profile.elevated -}}
{{- $preset := default "restricted" $profile.preset -}}
{{- $hostNetwork := default false $profile.hostNetwork -}}
{{- $hostNetworkIntents := list "network-diagnostics" "network-repair" "node-recovery" -}}
{{- if and $hostNetwork (not (has $profile.intent $hostNetworkIntents)) }}{{ fail (printf "profiles[%s] hostNetwork is reserved for network-diagnostics, network-repair, and node-recovery intents" $profile.name) }}{{ end }}
{{- if and $hostNetwork (not $elevated) }}{{ fail (printf "profiles[%s] hostNetwork requires explicit elevated: true" $profile.name) }}{{ end }}
{{- if and $hostNetwork (ne $preset "elevated-node") }}{{ fail (printf "profiles[%s] hostNetwork requires preset elevated-node" $profile.name) }}{{ end }}
{{- if and $profile.hostPID (not $hostNetwork) }}{{ fail (printf "profiles[%s] hostPID requires explicit hostNetwork: true" $profile.name) }}{{ end }}
securityContext:
  runAsNonRoot: {{ not $elevated }}
  {{- if $elevated }}
  # Elevated utility images are deliberately root-based; make this explicit
  # for admission policies and avoid relying on image USER metadata.
  runAsUser: 0
  runAsGroup: 0
  {{- else }}
  runAsUser: 65532
  runAsGroup: 65532
  fsGroup: 65532
  {{- end }}
  seccompProfile:
    type: RuntimeDefault
{{- end -}}
{{- define "debug-session-catalogue.containerSecurity" -}}
{{- $profile := .profile -}}
{{- $elevated := default false $profile.elevated -}}
{{- $preset := default "restricted" $profile.preset -}}
{{- $caps := default (list) $profile.capabilities -}}
{{- $allowedCaps := list "AUDIT_CONTROL" "BPF" "NET_ADMIN" "NET_RAW" "PERFMON" "SYS_ADMIN" "SYS_PTRACE" -}}
{{- range $cap := $caps }}{{- if not (has $cap $allowedCaps) }}{{ fail (printf "profiles[%s] capability %s is not permitted by the catalogue security contract" $profile.name $cap) }}{{ end }}{{- end }}
{{- if and (not $elevated) $caps }}{{ fail (printf "profiles[%s] restricted profiles may not add capabilities" $profile.name) }}{{ end }}
{{- if and (not $elevated) $profile.allowPrivilegeEscalation }}{{ fail (printf "profiles[%s] restricted profiles may not allow privilege escalation" $profile.name) }}{{ end }}
{{- if and $profile.privileged (ne $preset "elevated-node") }}{{ fail (printf "profiles[%s] privileged pods require preset elevated-node" $profile.name) }}{{ end }}
{{- if and $profile.hostPID (ne $preset "elevated-node") }}{{ fail (printf "profiles[%s] hostPID requires preset elevated-node" $profile.name) }}{{ end }}
securityContext:
  allowPrivilegeEscalation: {{ if $elevated }}{{ default false $profile.allowPrivilegeEscalation }}{{ else }}false{{ end }}
  privileged: {{ if $elevated }}{{ default false $profile.privileged }}{{ else }}false{{ end }}
  readOnlyRootFilesystem: true
  capabilities:
    drop: [ALL]
    {{- if and $elevated $caps }}
    add:
{{ toYaml $caps | nindent 6 }}
    {{- end }}
{{- end -}}
{{- define "debug-session-catalogue.validatorIdentity" -}}
{{- if eq (default "" .profile.intent) "cluster-validation" -}}
{{- with .profile.pod -}}
{{- range (default (list) .env) -}}
{{- if or (eq .name "VALIDATOR_POD_NAME") (eq .name "VALIDATOR_POD_NAMESPACE") -}}
{{- fail (printf "profiles[%s] validator identity environment variables are reserved" $.profile.name) -}}
{{- end -}}
{{- end -}}
{{- end -}}
- name: VALIDATOR_POD_NAME
  valueFrom:
    fieldRef:
      fieldPath: metadata.name
- name: VALIDATOR_POD_NAMESPACE
  valueFrom:
    fieldRef:
      fieldPath: metadata.namespace
{{- end -}}
{{- end -}}
{{- define "debug-session-catalogue.validatePodOverrides" -}}
{{- $profile := .profile -}}
{{- $elevatedNode := and (default false $profile.elevated) (eq (default "restricted" $profile.preset) "elevated-node") -}}
{{- with $profile.pod }}
{{- range $volume := (default (list) .volumes) }}
{{- if not $elevatedNode }}
{{- $safe := or (hasKey $volume "emptyDir") (hasKey $volume "configMap") (hasKey $volume "downwardAPI") }}
{{- if not $safe }}{{ fail (printf "profiles[%s] restricted volume %s must use emptyDir, configMap, or downwardAPI; sensitive or unbounded sources require explicit elevated: true and preset elevated-node" $profile.name $volume.name) }}{{ end }}
{{- end }}
{{- $serviceAccountToken := false -}}
{{- with $volume.projected }}
{{- range (default (list) .sources) }}
{{- if hasKey . "serviceAccountToken" }}{{ $serviceAccountToken = true }}{{ end }}
{{- end }}
{{- end }}
{{- if and $serviceAccountToken (not $elevatedNode) }}{{ fail (printf "profiles[%s] projected serviceAccountToken volume overrides require explicit elevated: true and preset elevated-node" $profile.name) }}{{ end }}
{{- end }}
{{- end }}
{{- end -}}
{{- define "debug-session-catalogue.serviceAccount" -}}
{{- $profile := .profile -}}
{{- $name := default "" $profile.serviceAccountName -}}
{{- $automount := default false $profile.automountServiceAccountToken -}}
{{- if or $name $automount }}
{{- if ne $profile.intent "cluster-validation" }}{{ fail (printf "profiles[%s] serviceAccountName and automountServiceAccountToken are reserved for cluster-validation" $profile.name) }}{{ end }}
{{- if not $name }}{{ fail "cluster-validation automountServiceAccountToken requires serviceAccountName" }}{{ end }}
{{- if not $automount }}{{ fail "cluster-validation serviceAccountName requires automountServiceAccountToken: true" }}{{ end }}
{{- if not (regexMatch "^[a-z0-9]([-a-z0-9]*[a-z0-9])?$" $name) }}{{ fail "serviceAccountName must be DNS-safe" }}{{ end }}
{{- if eq $name "default" }}{{ fail "cluster-validation must use a dedicated serviceAccountName" }}{{ end }}
{{- end }}
automountServiceAccountToken: {{ $automount }}
{{- if $name }}
serviceAccountName: {{ $name | quote }}
{{- end }}
{{- end -}}
{{- define "debug-session-catalogue.resources" -}}
resources:
  requests:
    cpu: 10m
    memory: 32Mi
  limits:
    cpu: 250m
    memory: 256Mi
{{- end -}}
{{- define "debug-session-catalogue.podOverrides" -}}
{{- $profile := .profile -}}
{{- with $profile.pod }}
{{- with .volumeMounts }}
volumeMounts:
{{ toYaml . | nindent 2 }}
{{- end }}
{{- with .volumes }}
volumes:
{{ toYaml . | nindent 0 }}
{{- end }}
{{- with .nodeSelector }}
nodeSelector:
{{ toYaml . | nindent 2 }}
{{- end }}
{{- end }}
{{- end -}}
{{- define "debug-session-catalogue.workload" -}}
workloadType: {{ default "Deployment" .profile.workloadType }}
replicas: {{ default 1 .profile.replicas }}
{{- end -}}
{{- define "debug-session-catalogue.authorization" -}}
allowed:
  groups:
{{ toYaml .root.Values.requesters.groups | nindent 4 }}
  users:
{{ toYaml .root.Values.requesters.users | nindent 4 }}
  clusters:
{{ toYaml .root.Values.targets.clusters | nindent 4 }}
{{- with .root.Values.targets.clusterSelector }}
{{- if . }}
  clusterSelector:
{{ toYaml . | nindent 4 }}
{{- end }}
{{- end }}
approvers:
  groups:
{{ toYaml .root.Values.approvers.groups | nindent 4 }}
  users:
{{ toYaml .root.Values.approvers.users | nindent 4 }}
{{- end -}}
{{- define "debug-session-catalogue.lifecycle" -}}
constraints:
  defaultDuration: {{ .root.Values.defaultDuration | quote }}
  maxDuration: {{ .root.Values.maxDuration | quote }}
  maxConcurrentSessions: {{ .root.Values.maxConcurrentSessions }}
  allowRenewal: false
  maxRenewals: 0
targetNamespace: {{ .root.Values.targetNamespace | quote }}
namespaceConstraints:
  defaultNamespace: {{ .root.Values.targetNamespace | quote }}
  allowUserNamespace: false
  createIfNotExists: false
failMode: closed
{{- end -}}
{{- define "debug-session-catalogue.audit" -}}
{{- $allowExec := true -}}
{{- if hasKey .profile "allowExec" }}{{ $allowExec = .profile.allowExec }}{{ end }}
requestReason:
  mandatory: true
  minLength: 10
  maxLength: 1000
  description: Explain the incident, scope, and intended diagnostic action.
audit:
  enabled: true
allowedPodOperations:
  exec: {{ $allowExec }}
  attach: false
  logs: true
  portForward: false
{{- end -}}
