{{/*
Expand the name of the chart.
*/}}
{{- define "airlock.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "airlock.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "airlock.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels
*/}}
{{- define "airlock.labels" -}}
helm.sh/chart: {{ include "airlock.chart" . }}
{{ include "airlock.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels
*/}}
{{- define "airlock.selectorLabels" -}}
app.kubernetes.io/name: {{ include "airlock.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Create the name of the service account to use
*/}}
{{- define "airlock.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "airlock.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Create the image name
*/}}
{{- define "airlock.image" -}}
{{- $registry := .Values.global.imageRegistry | default .Values.image.registry -}}
{{- $repository := .Values.image.repository -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- if $registry -}}
{{- printf "%s/%s:%s" $registry $repository $tag -}}
{{- else -}}
{{- printf "%s:%s" $repository $tag -}}
{{- end -}}
{{- end }}

{{/*
Create image pull secrets
*/}}
{{- define "airlock.imagePullSecrets" -}}
{{- $pullSecrets := list }}
{{- if .Values.global.imagePullSecrets }}
{{- $pullSecrets = concat $pullSecrets .Values.global.imagePullSecrets }}
{{- end }}
{{- if .Values.image.pullSecrets }}
{{- $pullSecrets = concat $pullSecrets .Values.image.pullSecrets }}
{{- end }}
{{- if $pullSecrets }}
imagePullSecrets:
{{- range $pullSecrets }}
  - name: {{ . }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Pod Security Context
*/}}
{{- define "airlock.podSecurityContext" -}}
{{- toYaml .Values.podSecurityContext }}
{{- end }}

{{/*
Container Security Context
*/}}
{{- define "airlock.securityContext" -}}
{{- toYaml .Values.securityContext }}
{{- end }}

{{/*
Create configuration checksum for rolling updates
*/}}
{{- define "airlock.configChecksum" -}}
{{- include (print $.Template.BasePath "/configmap.yaml") . | sha256sum }}
{{- end }}