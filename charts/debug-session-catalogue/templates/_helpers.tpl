{{/*
SPDX-FileCopyrightText: 2026 Deutsche Telekom AG
SPDX-License-Identifier: Apache-2.0
*/}}
{{- define "debug-session-catalogue.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- define "debug-session-catalogue.fullname" -}}
{{- if .Values.fullnameOverride -}}{{ .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}{{- else -}}{{ include "debug-session-catalogue.name" . }}{{- end -}}
{{- end -}}
{{- define "debug-session-catalogue.labels" -}}
app.kubernetes.io/name: {{ include "debug-session-catalogue.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | quote }}
{{- end -}}
{{- define "debug-session-catalogue.image" -}}
{{- $image := index .root.Values.images .key -}}
{{- if $image.digest }}{{ printf "%s@%s" $image.repository $image.digest }}{{- else }}{{ printf "%s:%s" $image.repository $image.tag }}{{- end -}}
{{- end -}}
