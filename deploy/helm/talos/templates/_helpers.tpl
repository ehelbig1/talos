{{/*
Shared helpers for the Talos chart.

Naming convention:
  - {{ include "talos.fullname" . }}        = "<release>-talos"
  - {{ include "talos.componentName" (list . "controller") }} = "<release>-talos-controller"

Labels follow the Kubernetes recommended set (app.kubernetes.io/*).
*/}}

{{- define "talos.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "talos.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{- define "talos.componentName" -}}
{{- $ctx := index . 0 -}}
{{- $component := index . 1 -}}
{{- printf "%s-%s" (include "talos.fullname" $ctx) $component | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "talos.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/* Common labels for every Talos-owned resource. */}}
{{- define "talos.labels" -}}
helm.sh/chart: {{ include "talos.chart" . }}
{{ include "talos.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: talos
{{- end -}}

{{- define "talos.selectorLabels" -}}
app.kubernetes.io/name: {{ include "talos.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
Per-component labels. Pass list of (ctx, componentName).
*/}}
{{- define "talos.componentLabels" -}}
{{- $ctx := index . 0 -}}
{{- $component := index . 1 -}}
{{ include "talos.labels" $ctx }}
app.kubernetes.io/component: {{ $component }}
{{- end -}}

{{- define "talos.componentSelectorLabels" -}}
{{- $ctx := index . 0 -}}
{{- $component := index . 1 -}}
{{ include "talos.selectorLabels" $ctx }}
app.kubernetes.io/component: {{ $component }}
{{- end -}}

{{/* Image reference: repository@digest, with tag fallback if digest empty. */}}
{{- define "talos.image" -}}
{{- $img := . -}}
{{- if $img.digest -}}
{{ $img.repository }}@{{ $img.digest }}
{{- else if $img.tag -}}
{{ $img.repository }}:{{ $img.tag }}
{{- else -}}
{{ $img.repository }}:latest
{{- end -}}
{{- end -}}

{{/*
Secret name for bootstrap secrets. Operators running external-secrets
keep `bootstrapSecret.enabled: false` and supply the same name.
*/}}
{{- define "talos.bootstrapSecretName" -}}
{{- default (printf "%s-controller-secrets" (include "talos.fullname" .)) .Values.bootstrapSecret.secretName -}}
{{- end -}}

{{/* NATS in-cluster DNS (Service name). */}}
{{- define "talos.natsUrl" -}}
nats://{{ include "talos.componentName" (list . "nats") }}.{{ .Release.Namespace }}.svc.cluster.local:{{ .Values.nats.service.clientPort | default 4222 }}
{{- end -}}

{{/* Neo4j in-cluster URI. */}}
{{- define "talos.neo4jUri" -}}
{{- if .Values.neo4j.enabled -}}
bolt://{{ include "talos.componentName" (list . "neo4j") }}.{{ .Release.Namespace }}.svc.cluster.local:7687
{{- else -}}
{{ .Values.neo4j.external.uri }}
{{- end -}}
{{- end -}}

{{/* Vault address: in-cluster Service DNS or configured override. */}}
{{- define "talos.vaultAddr" -}}
{{- if .Values.vault.enabled -}}
http://{{ include "talos.componentName" (list . "vault") }}.{{ .Release.Namespace }}.svc.cluster.local:8200
{{- else if .Values.vault.addrOverride -}}
{{ .Values.vault.addrOverride }}
{{- else -}}
http://vault:8200
{{- end -}}
{{- end -}}

{{/* MinIO in-cluster endpoint. */}}
{{- define "talos.minioEndpoint" -}}
http://{{ include "talos.componentName" (list . "minio") }}.{{ .Release.Namespace }}.svc.cluster.local:{{ .Values.minio.service.apiPort | default 9000 }}
{{- end -}}

{{/* Render the pod securityContext. */}}
{{- define "talos.podSecurityContext" -}}
{{- toYaml .Values.podSecurityContext -}}
{{- end -}}

{{- define "talos.containerSecurityContext" -}}
{{- toYaml .Values.containerSecurityContext -}}
{{- end -}}

{{/*
Render a list of env var entries from a map of name→value.
Non-sensitive values only — sensitive values must come through secretKeyRef.
*/}}
{{- define "talos.envFromMap" -}}
{{- range $k, $v := . }}
- name: {{ $k }}
  value: {{ $v | quote }}
{{- end }}
{{- end -}}

{{/*
Render env entries sourced from a Secret key. Pass list of (secretName, [keys]).
*/}}
{{- define "talos.envFromSecret" -}}
{{- $secret := index . 0 -}}
{{- $keys := index . 1 -}}
{{- range $keys }}
- name: {{ . }}
  valueFrom:
    secretKeyRef:
      name: {{ $secret }}
      key: {{ . }}
      optional: true
{{- end }}
{{- end -}}

{{/* Image pull secrets block. */}}
{{- define "talos.imagePullSecrets" -}}
{{- with .Values.global.imagePullSecrets -}}
imagePullSecrets:
{{ toYaml . | indent 2 }}
{{- end -}}
{{- end -}}
