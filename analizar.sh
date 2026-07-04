#!/usr/bin/env bash
set -euo pipefail

API_BASE="${API_BASE:-http://localhost:8000}"
POLL_INTERVAL="${POLL_INTERVAL:-2}"

usage() {
  echo "Uso: $0 <ruta-al-repo>" >&2
  exit 1
}

[[ $# -ge 1 ]] || usage

REPO="$1"
REPO_NAME="$(basename "${REPO%/}")"
OUTPUT_FILE="${REPO_NAME}.json"

json_field() {
  local json="$1"
  local field="$2"
  python3 -c "import sys, json; print(json.load(sys.stdin)['$field'])" <<< "$json"
}

json_error() {
  python3 -c "import sys, json; d=json.load(sys.stdin); print(d.get('error', 'error desconocido'))" <<< "$1"
}

echo "→ Iniciando análisis de: $REPO"

PAYLOAD=$(python3 -c "import json, sys; print(json.dumps({'target': sys.argv[1]}))" "$REPO")

CREATE_RESPONSE=$(curl -sS -X POST "${API_BASE}/v1/analyses" \
  -H "Content-Type: application/json" \
  -d "$PAYLOAD")

ANALYSIS_ID=$(json_field "$CREATE_RESPONSE" "analysis_id")
echo "→ Analysis ID: $ANALYSIS_ID"

while true; do
  STATUS_RESPONSE=$(curl -sS "${API_BASE}/v1/analyses/${ANALYSIS_ID}")
  STATUS=$(json_field "$STATUS_RESPONSE" "status")

  printf '\r→ Estado: %-12s (esperando...)' "$STATUS"

  case "$STATUS" in
    completed)
      echo
      break
      ;;
    failed)
      echo
      ERROR=$(json_error "$STATUS_RESPONSE")
      echo "✗ Análisis falló: $ERROR" >&2
      exit 1
      ;;
    pending|running)
      sleep "$POLL_INTERVAL"
      ;;
    *)
      echo
      echo "✗ Estado inesperado: $STATUS" >&2
      exit 1
      ;;
  esac
done

echo "→ Descargando controles..."
curl -sS "${API_BASE}/v1/analyses/${ANALYSIS_ID}/controls" -o "$OUTPUT_FILE"

CONTROL_COUNT=$(python3 -c "import json; print(len(json.load(open('$OUTPUT_FILE'))['controls']))")
echo "→ Guardado: $OUTPUT_FILE ($CONTROL_COUNT controles)"

REPORT_URL="${API_BASE}/v1/analyses/${ANALYSIS_ID}/report"
echo
echo "Reporte visual: $REPORT_URL"
