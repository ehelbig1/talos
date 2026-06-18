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

{{/* NATS in-cluster DNS (Service name). Uses the tls:// scheme when in-cluster
     TLS is enabled so the controller's production TLS gate (#243) is satisfied;
     the controller + worker trust the self-signed cert via NATS_CA_FILE. */}}
{{- define "talos.natsUrl" -}}
{{- $scheme := ternary "tls" "nats" .Values.tls.inCluster.enabled -}}
{{ $scheme }}://{{ include "talos.componentName" (list . "nats") }}.{{ .Release.Namespace }}.svc.cluster.local:{{ .Values.nats.service.clientPort | default 4222 }}
{{- end -}}

{{/* Neo4j in-cluster URI. Uses the bolt+ssc:// TLS scheme (encrypt + accept
     the chart's self-signed cert without verification) when in-cluster TLS is
     enabled, so the controller's production TLS gate (#243) is satisfied. */}}
{{- define "talos.neo4jUri" -}}
{{- if .Values.neo4j.enabled -}}
{{- $scheme := ternary "bolt+ssc" "bolt" .Values.tls.inCluster.enabled -}}
{{ $scheme }}://{{ include "talos.componentName" (list . "neo4j") }}.{{ .Release.Namespace }}.svc.cluster.local:7687
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

{{/*
Secret-content checksum for the `checksum/<secret>-data` pod annotation
pattern. Hashes ONLY the secret's `.data` (the actual values), not
managed metadata — those change on every helm operation and would
cause spurious rolls. When the secret doesn't exist yet (first
install, or `helm template` with no cluster), returns a fixed
placeholder so the annotation is stable across first-render attempts.

Usage:
    annotations:
      checksum/bootstrap-secret-data: {{ include "talos.secretChecksum" (dict "ns" .Release.Namespace "name" (include "talos.bootstrapSecretName" .)) }}

Why this matters: install.sh manages the bootstrap + postgres-
credentials + neo4j Secrets OUT OF BAND (so plaintext never
round-trips through `helm get values`). When the operator rotates
one of them (via `kubectl delete secret ... && rerun install.sh`),
the dependent pods don't automatically restart — `envFrom: secretKeyRef`
reads the secret only at pod-creation time. Pre-MCP-1231 the operator
had to `kubectl delete pod talos-nats-0 talos-neo4j-0` manually after
every rotation (we hit this on the 2026-05-19 in-cluster Postgres
deploy and again on the 2026-05-20 rebuild). With this annotation,
the next `helm upgrade` notices the secret data changed → annotation
hash changes → pod template hash changes → Deployment/StatefulSet
rolls the pod automatically.
*/}}
{{- define "talos.secretChecksum" -}}
{{- $ns   := .ns   -}}
{{- $name := .name -}}
{{- $secret := lookup "v1" "Secret" $ns $name -}}
{{- if and $secret $secret.data -}}
{{ $secret.data | toYaml | sha256sum }}
{{- else -}}
no-secret-yet
{{- end -}}
{{- end -}}

{{/* Image pull secrets block. */}}
{{- define "talos.imagePullSecrets" -}}
{{- with .Values.global.imagePullSecrets -}}
imagePullSecrets:
{{ toYaml . | indent 2 }}
{{- end -}}
{{- end -}}
