#!/usr/bin/env bash
# ==============================================================================
# SentinelCloud-Advanced Cloud Production Runner (Render)
# Boots:
#   1. Clinical Microservices (Ports 5000, 5001, 5002, 5003 in background)
#   2. FastAPI + Socket.IO Unified Gateway on $PORT (assigned dynamically by Render)
# ==============================================================================

set -e

echo "=== [1/2] Booting Clinical Medical Microservices ==="
python3 services/medical/vitals/app.py > /dev/null 2>&1 &
python3 services/medical/drug-dispenser/app.py > /dev/null 2>&1 &
python3 services/medical/ehr/app.py > /dev/null 2>&1 &
python3 services/medical/billing/app.py > /dev/null 2>&1 &

sleep 2

PORT="${PORT:-5050}"
echo "=== [2/2] Booting SentinelCloud Unified Engine on port ${PORT} ==="
exec uvicorn backend.main:app --host 0.0.0.0 --port "$PORT"
