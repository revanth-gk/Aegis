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
    exit 0
}
trap cleanup INT TERM

echo "============================================================"
echo "  Sentinel-Core — Offline Development Mode"
echo "============================================================"

# 1. Start Event Forwarder (port 8081)
echo "[1/3] Starting Event Forwarder on port 8081..."
python -m forwarder.main --file fixtures/sample-tetragon-raw.jsonl &
FORWARDER_PID=$!
sleep 2
echo "  ✓ Forwarder PID: $FORWARDER_PID"

# 2. Start Dashboard API (port 8080)
echo "[2/3] Starting Dashboard API on port 8080..."
python dashboard_api.py &
DASHBOARD_PID=$!
sleep 2
echo "  ✓ Dashboard API PID: $DASHBOARD_PID"

# 3. Start Frontend (port 5173)
echo "[3/3] Starting Frontend Dashboard on port 5173..."
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
