#!/usr/bin/env bash
set -e

# Activate virtualenv if available
if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
fi

export PYTHONPATH="$PWD:$PYTHONPATH"
export OFFLINE_MODE=true
export REMEDIATION_DRY_RUN="${REMEDIATION_DRY_RUN:-true}"
export REMEDIATION_AUTONOMY_MODE="${REMEDIATION_AUTONOMY_MODE:-autonomous}"
export REMEDIATION_SIGKILL_THRESHOLD="${REMEDIATION_SIGKILL_THRESHOLD:-0.85}"
export REMEDIATION_YAML_THRESHOLD="${REMEDIATION_YAML_THRESHOLD:-0.75}"

cleanup() {
    echo ""
    echo "Shutting down Sentinel-Core services..."
    kill $FORWARDER_PID $DASHBOARD_PID $FRONTEND_PID 2>/dev/null
    docker stop sentinel-redis >/dev/null 2>&1 || true
    exit 0
}
trap cleanup INT TERM

echo "============================================================"
echo "  Sentinel-Core — Offline Development Mode"
echo "============================================================"

# 1. Start Redis (port 6379)
echo "[1/4] Starting Redis on port 6379..."
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^sentinel-redis$'; then
    echo "  ✓ Redis container already running"
elif docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q '^sentinel-redis$'; then
    docker start sentinel-redis >/dev/null
    echo "  ✓ Redis container restarted"
else
    docker run -d --name sentinel-redis -p 6379:6379 redis:7-alpine >/dev/null
    echo "  ✓ Redis container started"
fi
for i in $(seq 1 10); do
    if docker exec sentinel-redis redis-cli ping 2>/dev/null | grep -q PONG; then
        echo "  ✓ Redis is ready"
        break
    fi
    sleep 1
done

# 2. Start Event Forwarder (port 8081)
echo "[2/4] Starting Event Forwarder on port 8081..."
python -m forwarder.main --file fixtures/sample-tetragon-raw.jsonl &
FORWARDER_PID=$!
sleep 2
echo "  ✓ Forwarder PID: $FORWARDER_PID"

# 3. Start Dashboard API (port 8080)
echo "[3/4] Starting Dashboard API on port 8080..."
python dashboard_api.py &
DASHBOARD_PID=$!
sleep 2
echo "  ✓ Dashboard API PID: $DASHBOARD_PID"

# 4. Start Frontend (port 5173)
echo "[4/4] Starting Frontend Dashboard on port 5173..."
if [ -f dashboard/package.json ]; then
    cd dashboard
    if [ ! -d node_modules ]; then
        echo "  ↳ Installing npm dependencies..."
        npm install
    fi
    npm run dev &
    FRONTEND_PID=$!
    cd ..
    echo "  ✓ Frontend PID: $FRONTEND_PID"
fi

echo ""
echo "============================================================"
echo "  SENTINEL-CORE OFFLINE MODE RUNNING"
echo "============================================================"
echo "  Frontend Dashboard:  http://localhost:5173"
echo "  Dashboard API:       http://localhost:8080"
echo "  Forwarder API:       http://localhost:8081"
echo "============================================================"
echo "  Press Ctrl+C to stop all services"
echo ""

wait $FORWARDER_PID $DASHBOARD_PID $FRONTEND_PID
