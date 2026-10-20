#!/usr/bin/env bash
# ==============================================================================
# SentinelCloud: VM Runner (Option A — everything inside the Linux VM)
# Starts:
#   1. Medical services in Docker (Falco-monitored) + log feeds for the tailer
#   2. Backend API + WebSocket (:5050)
#   3. Next.js Dashboard (:3000)
#
# Usage: ./scripts/vm-start.sh        (run from repo root, inside the VM)
# Requires: .venv (uv, python 3.12), npm install done, .env present,
#           Docker with medical services, Falco pointed at localhost:5050.
# ==============================================================================

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
cd "$PROJECT_DIR"

# Colors
GREEN='\033[0;32m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"
echo -e "${BLUE}  SentinelCloud · VM Mode (all-in-one Linux)           ${NC}"
echo -e "${BLUE}═══════════════════════════════════════════════════════${NC}"

# .env check (it is gitignored — must exist on this machine)
if [ ! -f ".env" ]; then
    echo -e "  [FATAL] .env missing. Create it first with:"
    echo -e "    SENTINEL_MODE=dev"
    echo -e "    SENTINEL_ADMIN_USER=admin"
    echo -e "    SENTINEL_ADMIN_PASSWORD=sentinel-admin-2026"
    echo -e "    SENTINEL_SECRET_KEY=\$(python3 -c 'import secrets; print(secrets.token_hex(32))')"
    echo -e "    SENTINEL_HOST=0.0.0.0"
    echo -e "    SENTINEL_PORT=5050"
    echo -e "    SENTINEL_FALCO_ENABLED=true"
    echo -e "    SENTINEL_LOG_TAIL_ENABLED=true"
    exit 1
fi

# venv check
if [ ! -x ".venv/bin/python" ]; then
    echo -e "  [FATAL] .venv missing. Create it with:"
    echo -e "    uv venv --python 3.12 .venv && source .venv/bin/activate && uv pip install -r backend/requirements.txt"
    exit 1
fi

# Ensure data directory
mkdir -p data

# Medical services in Docker (same project name as the UTM guide so Falco
# rules and container names keep matching: sentinel-services-*)
export COMPOSE_PROJECT_NAME=sentinel-services
echo -e "[1/4] Medical services in Docker (Falco-monitored)..."
docker compose up -d vitals ehr billing drug-dispenser
docker ps --format '{{.Names}}' | grep -E 'ehr|vitals|billing|dispenser' || true

# Log feeds: stream each container's stdout into the files the log tailer
# watches. Replays history once on start (harmless backlog), then live.
echo -e "[2/4] Log feeds for the HTTP_LOG tailer..."
for svc in vitals:5000 drug-dispenser:5001 ehr:5002 billing:5003; do
    name="${svc%%:*}"
    log="data/${name}.log"
    [ "$name" = "drug-dispenser" ] && log="data/dispenser.log"
    [ "$name" = "ehr" ] && log="data/ehr.log"
    [ "$name" = "vitals" ] && log="data/vitals.log"
    [ "$name" = "billing" ] && log="data/billing.log"
    docker logs -f "sentinel-services-${name}-1" > "$log" 2>&1 &
done

# Backend
echo -e "[3/4] Backend on ${GREEN}http://0.0.0.0:5050${NC}..."
export SENTINEL_MODE=dev
.venv/bin/python -m backend.main > data/backend.log 2>&1 &
BACKEND_PID=$!

sleep 2

# Frontend
echo -e "[4/4] Dashboard on ${GREEN}http://0.0.0.0:3000${NC}..."
npx next dev -H 0.0.0.0 -p 3000 > data/frontend.log 2>&1 &
FRONTEND_PID=$!

echo ""
echo -e "${GREEN}✔ SentinelCloud VM Environment Ready${NC}"
echo -e "═══════════════════════════════════════════════════════"
echo -e "  ${CYAN}🛡  Dashboard:${NC}    http://localhost:3000 (via UTM port forward)"
echo -e "  ${CYAN}📡  Backend API:${NC}  http://localhost:5050 (via UTM port forward)"
echo -e "  ${CYAN}🏥  Services:${NC}      Docker (Falco-monitored) + log feeds in data/"
echo -e "Press Ctrl+C to stop."
echo ""

cleanup() {
    echo -e "\nShutting down SentinelCloud..."
    kill $BACKEND_PID $FRONTEND_PID 2>/dev/null || true
    pkill -f "docker logs -f sentinel-services" 2>/dev/null || true
    exit 0
}

trap cleanup SIGINT SIGTERM
wait
