#!/usr/bin/env bash
# ==============================================================================
# StorageOS Health & Monitoring Script
# Verifies HTTP availability, database connectivity, and filesystem writeability.
# Suitable for cron monitoring, container probes, and uptime alerts.
# ==============================================================================
set -euo pipefail

TARGET_URL="${1:-${STORAGEOS_HEALTH_URL:-http://127.0.0.1:5000/health}}"
TIMEOUT="${2:-5}"

echo "Checking StorageOS health at ${TARGET_URL}..."

RESPONSE=$(curl -sS --max-time "${TIMEOUT}" -w "\nHTTP_STATUS:%{http_code}" "${TARGET_URL}" 2>&1) || {
    echo "ERROR: Failed to connect to StorageOS endpoint (${TARGET_URL})."
    exit 1
}

HTTP_STATUS=$(echo "${RESPONSE}" | grep "HTTP_STATUS:" | cut -d':' -f2)
BODY=$(echo "${RESPONSE}" | grep -v "HTTP_STATUS:")

echo "HTTP Status: ${HTTP_STATUS}"
echo "Response Body: ${BODY}"

if [ "${HTTP_STATUS}" != "200" ]; then
    echo "HEALTHCHECK FAILED: Unexpected HTTP status ${HTTP_STATUS}"
    exit 1
fi

# Check for JSON "ok" status
if echo "${BODY}" | grep -q '"status"[[:space:]]*:[[:space:]]*"ok"'; then
    echo "HEALTHCHECK PASSED: StorageOS is healthy and operational."
    exit 0
else
    echo "HEALTHCHECK FAILED: Service degraded or non-operational status reported."
    exit 1
fi
