{{/*
Expand the name of the chart.
*/}}
{{- define "agent-triad.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
*/}}
{{- define "agent-triad.fullname" -}}
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
{{- define "agent-triad.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "agent-triad.labels" -}}
helm.sh/chart: {{ include "agent-triad.chart" . }}
{{ include "agent-triad.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/*
Selector labels.
*/}}
{{- define "agent-triad.selectorLabels" -}}
app.kubernetes.io/name: {{ include "agent-triad.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{/*
Component-specific selector labels.
*/}}
{{- define "agent-triad.componentLabels" -}}
{{ include "agent-triad.labels" .root }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{- define "agent-triad.componentSelectorLabels" -}}
{{ include "agent-triad.selectorLabels" .root }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{/*
Pod labels including optional Azure AKS Workload Identity label.
*/}}
{{- define "agent-triad.podLabels" -}}
{{ include "agent-triad.componentLabels" . }}
{{- if .root.Values.serviceAccount.aksClientId }}
azure.workload.identity/use: "true"
{{- end }}
{{- end }}

{{/*
ServiceAccount name.
*/}}
{{- define "agent-triad.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "agent-triad.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Secret name (supports external secret managers via existingSecret).
*/}}
{{- define "agent-triad.secretName" -}}
{{- if .Values.existingSecret }}
{{- .Values.existingSecret }}
{{- else }}
{{- printf "%s-secrets" (include "agent-triad.fullname" .) }}
{{- end }}
{{- end }}

{{/*
Resolved PostgreSQL DSN (external managed DB or in-cluster StatefulSet).
*/}}
{{- define "agent-triad.postgresDsn" -}}
{{- if .Values.postgres.externalDsn }}
{{- .Values.postgres.externalDsn }}
{{- else if .Values.postgres.enabled }}
{{- printf "postgresql://%s:%s@%s-postgres:%v/%s" .Values.postgres.auth.username .Values.postgres.auth.password (include "agent-triad.fullname" .) .Values.postgres.service.port .Values.postgres.auth.database }}
{{- else }}
{{- "" }}
{{- end }}
{{- end }}

{{/*
Resolved Redis URL (external managed cache or in-cluster Deployment).
*/}}
{{- define "agent-triad.redisUrl" -}}
{{- if .Values.redis.externalUrl }}
{{- .Values.redis.externalUrl }}
{{- else if .Values.redis.enabled }}
{{- printf "redis://%s-redis:%v/0" (include "agent-triad.fullname" .) .Values.redis.service.port }}
{{- else }}
{{- "" }}
{{- end }}
{{- end }}

{{/*
OpenShift-aware podSecurityContext.
Omits static runAsUser/runAsGroup/fsGroup when openshift.enabled=true so
OpenShift restricted-v2 SCC assigns namespace-scoped UID/GID cleanly.
*/}}
{{- define "agent-triad.podSecurityContext" -}}
runAsNonRoot: {{ .Values.podSecurityContext.runAsNonRoot }}
{{- if not .Values.openshift.enabled }}
{{- if .Values.podSecurityContext.runAsUser }}
runAsUser: {{ .Values.podSecurityContext.runAsUser }}
{{- end }}
{{- if .Values.podSecurityContext.runAsGroup }}
runAsGroup: {{ .Values.podSecurityContext.runAsGroup }}
{{- end }}
{{- if .Values.podSecurityContext.fsGroup }}
fsGroup: {{ .Values.podSecurityContext.fsGroup }}
{{- end }}
{{- end }}
{{- if .Values.podSecurityContext.seccompProfile }}
seccompProfile:
{{ toYaml .Values.podSecurityContext.seccompProfile | indent 2 }}
{{- end }}
{{- end }}
