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
{{- $node := and $elevated (eq (default "restricted" $profile.preset) "elevated-node") -}}
securityContext:
  runAsNonRoot: {{ not $elevated }}
  {{- if not $elevated }}
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
{{- $caps := default (list) $profile.capabilities -}}
securityContext:
  allowPrivilegeEscalation: {{ $elevated }}
  privileged: {{ if $elevated }}{{ default false $profile.privileged }}{{ else }}false{{ end }}
  capabilities:
    drop: [ALL]
    {{- if and $elevated $caps }}
    add:
{{ toYaml $caps | nindent 6 }}
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
requestReason:
  mandatory: true
  minLength: 10
  maxLength: 1000
  description: Explain the incident, scope, and intended diagnostic action.
audit:
  enabled: true
allowedPodOperations:
  exec: true
  attach: false
  logs: true
  portForward: false
{{- end -}}
