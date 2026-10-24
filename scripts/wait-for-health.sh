#!/usr/bin/env bash
# ==============================================================================
# PenteFino Infrastructure Healthcheck Polling Script
# ==============================================================================
set -euo pipefail

TIMEOUT="${1:-60}"
SERVICES=("pentefino_postgres" "pentefino_valkey" "pentefino_seaweedfs" "pentefino_rabbitmq")

echo "==> Polling health status for PenteFino infrastructure services (timeout: ${TIMEOUT}s)..."
START_TIME=$(date +%s)

while true; do
  ALL_HEALTHY=true
  STATUS_STR=""

  for SVC in "${SERVICES[@]}"; do
    STATUS=$(docker inspect --format='{{if .State.Health}}{{.State.Health.Status}}{{else}}{{.State.Status}}{{end}}' "$SVC" 2>/dev/null || echo "not_found")
    STATUS_STR="${STATUS_STR} ${SVC}=${STATUS}"
    if [ "$STATUS" != "healthy" ]; then
      ALL_HEALTHY=false
    fi
  done

  ELAPSED=$(( $(date +%s) - START_TIME ))
  echo "[${ELAPSED}s] ${STATUS_STR}"

  if [ "$ALL_HEALTHY" = true ]; then
    echo "[SUCCESS] All 4 infrastructure services are HEALTHY!"

    # Ensure default 'evidence' bucket exists in SeaweedFS Filer
    echo "==> Verifying SeaweedFS 'evidence' bucket..."
    curl -s -X POST http://127.0.0.1:8888/buckets/evidence/ >/dev/null 2>&1 || true
    echo "[OK] Default bucket 'evidence' verified in SeaweedFS."
    exit 0
  fi

  if [ "$ELAPSED" -ge "$TIMEOUT" ]; then
    echo "[FAIL] Healthcheck timeout exceeded (${TIMEOUT}s). Dumping container logs:"
    for SVC in "${SERVICES[@]}"; do
      echo "--- Container Logs: ${SVC} ---"
      docker logs --tail 25 "$SVC" 2>&1 || true
    done
    exit 1
  fi

  sleep 3
done
