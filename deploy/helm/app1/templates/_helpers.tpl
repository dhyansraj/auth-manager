{{/*
Image registry helper -- prefixes with global registry if set.
*/}}
{{- define "app1.image" -}}
{{- $reg := .global.imageRegistry -}}
{{- if $reg -}}
{{- printf "%s/%s:%s" $reg .repository .tag -}}
{{- else -}}
{{- printf "%s:%s" .repository .tag -}}
{{- end -}}
{{- end -}}

{{/*
Common labels.
*/}}
{{- define "app1.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
app.kubernetes.io/name: {{ .Chart.Name }}
app.kubernetes.io/instance: {{ .Release.Name }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
{{- end }}
