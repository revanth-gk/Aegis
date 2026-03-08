#!/bin/bash
set -e

# ── Virtual Environment ──────────────────────────────────────────
if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
fi

echo "============================================================"
echo "  Sentinel-Core: Real eBPF Security Pipeline"
echo "============================================================"

# ── 1. Hermetic Toolchain ────────────────────────────────────────
mkdir -p bin
export PATH="$PWD/bin:$PATH"

echo "[1/4] Checking tooling dependencies..."
if ! command -v kind &>/dev/null; then
    echo "  ↳ Downloading kind..."
    curl -sLo ./bin/kind https://kind.sigs.k8s.io/dl/v0.22.0/kind-linux-amd64
    chmod +x ./bin/kind
fi
if ! command -v kubectl &>/dev/null; then
    echo "  ↳ Downloading kubectl..."
    curl -sLo ./bin/kubectl "https://dl.k8s.io/release/v1.30.0/bin/linux/amd64/kubectl"
    chmod +x ./bin/kubectl
fi
if ! command -v helm &>/dev/null; then
    echo "  ↳ Downloading helm..."
    curl -fsSL -o /tmp/get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
    chmod 700 /tmp/get_helm.sh
    HELM_INSTALL_DIR=$PWD/bin USE_SUDO="false" /tmp/get_helm.sh >/dev/null 2>&1 || true
    rm -f /tmp/get_helm.sh
fi
echo "  ✓ kind=$(kind --version 2>/dev/null | awk '{print $3}')"
echo "  ✓ kubectl=$(kubectl version --client -o json 2>/dev/null | python3 -c 'import sys,json;print(json.load(sys.stdin)["clientVersion"]["gitVersion"])' 2>/dev/null || echo 'ok')"
echo "  ✓ helm=$(helm version --short 2>/dev/null)"

CLUSTER_NAME="sentinel-cluster"

# ── 2. Kubernetes Cluster ────────────────────────────────────────
echo ""
echo "[2/4] Provisioning Kubernetes cluster..."
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    echo "  ✓ Cluster '${CLUSTER_NAME}' already exists"
else
    echo "  ↳ Creating kind cluster with kernel debug/trace mounts..."
    cat > /tmp/kind-config.yaml <<'KINDEOF'
kind: Cluster
apiVersion: kind.x-k8s.io/v1alpha4
nodes:
- role: control-plane
  extraMounts:
  - hostPath: /sys/kernel/debug
    containerPath: /sys/kernel/debug
    propagation: Bidirectional
  - hostPath: /sys/kernel/tracing
    containerPath: /sys/kernel/tracing
    propagation: Bidirectional
KINDEOF
    kind create cluster --name "${CLUSTER_NAME}" --config /tmp/kind-config.yaml
    rm -f /tmp/kind-config.yaml
fi

# Mount tracefs/debugfs inside the Kind node (required for eBPF on Arch)
echo "  ↳ Mounting kernel trace filesystems inside node..."
docker exec ${CLUSTER_NAME}-control-plane \
    mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
docker exec ${CLUSTER_NAME}-control-plane \
    mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true

# ── 3. Tetragon eBPF Agent ───────────────────────────────────────
echo ""
echo "[3/4] Deploying Tetragon eBPF agent..."
if helm list -n kube-system 2>/dev/null | grep -q tetragon; then
    echo "  ✓ Tetragon already installed"
else
    echo "  ↳ Installing via Helm with tracefs/debugfs mounts..."
    helm repo add cilium https://helm.cilium.io >/dev/null 2>&1
    helm repo update >/dev/null 2>&1
    helm install tetragon cilium/tetragon -n kube-system -f tetragon-values.yaml --wait --timeout=180s
fi

echo "  ↳ Waiting for Tetragon readiness..."
kubectl wait --for=condition=ready pod \
    -l app.kubernetes.io/name=tetragon \
    -n kube-system --timeout=180s

echo "  ↳ Applying TracingPolicy..."
kubectl apply -f sentinel-policy.yaml

echo "  ✓ Tetragon is LIVE and monitoring"

# ── 4. Stream + Analyze ──────────────────────────────────────────
echo ""
echo "[4/4] Starting Sentinel-Core ML + RAG Pipeline..."
export PYTHONPATH="$PWD:$PYTHONPATH"

cat << 'PYEOF' > _sentinel_live.py
import sys
import time
import json
import logging
import threading
from pathlib import Path

import uvicorn
from forwarder.api import app as fastapi_app
from forwarder.api import set_redis_status, set_ml_triage
from forwarder.config import Config
from forwarder.main import process_line
from forwarder.ml_triage import MLTriage
from forwarder.publisher import EventPublisher
import forwarder.main

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s │ %(name)-22s │ %(levelname)-5s │ %(message)s",
    datefmt="%H:%M:%S"
)
logger = logging.getLogger("sentinel.live")

config = Config()

# API server
def run_api():
    uvicorn.run(fastapi_app, host="0.0.0.0", port=8081, log_level="warning")
threading.Thread(target=run_api, daemon=True).start()
time.sleep(2)

# ML Triage
ml = MLTriage(
    model_path=Path(config.ML_MODEL_PATH),
    feature_list_path=Path(config.FEATURE_LIST_PATH)
)
set_ml_triage(ml)
forwarder.main._ml_triage = ml

# Publisher
pub = EventPublisher(config)
set_redis_status(pub.is_connected)

# Try to trigger RAG + Gemini orchestration for high-severity events
try:
    from orchestrator import analyze_alert, ORCHESTRATOR_AVAILABLE
    rag_enabled = ORCHESTRATOR_AVAILABLE
    if rag_enabled:
        logger.info("🧠 RAG + Gemini orchestrator is ONLINE")
    else:
        logger.warning("⚠️  Orchestrator offline (missing API keys). ML triage only.")
except ImportError:
    rag_enabled = False
    logger.warning("⚠️  Orchestrator module not available")

print()
print("🚀 Sentinel API: http://127.0.0.1:8081")
print("📡 Processing REAL eBPF telemetry from Kubernetes cluster...")
print("   Press Ctrl+C to stop")
print()

event_count = 0
try:
    for line in sys.stdin:
        line = line.strip()
        if not line or not line.startswith("{"):
            continue
        try:
            sentinel_event = process_line(line, pub)
            if sentinel_event:
                event_count += 1
                triage = sentinel_event.get("triage", {})
                grade = triage.get("grade", "UNKNOWN")
                score = float(triage.get("confidence", 0.0))

                # For TP/BP events, run through the full orchestrator (RAG + Gemini)
                if rag_enabled and grade in ("TP", "BP") and event_count <= 20:
                    try:
                        raw = json.loads(line)
                        result = analyze_alert(
                            raw_event=raw,
                            guide_score=score,
                            guide_grade=grade,
                            stream=False
                        )
                        if result.get("final_report"):
                            logger.info("📋 ORCHESTRATOR REPORT:\n%s", result["final_report"][:500])
                        if result.get("yaml_fix"):
                            logger.info("🔧 YAML FIX:\n%s", result["yaml_fix"][:300])
                    except Exception as orch_err:
                        logger.warning("Orchestrator error: %s", orch_err)

        except Exception as e:
            logger.error("Event decode error: %s", e)

except KeyboardInterrupt:
    logger.info("Pipeline terminated. Processed %d events.", event_count)
    pub.close()
    sys.exit(0)
PYEOF

# Kill any previously running APIs
pkill -f "python3 dashboard_api.py" || true
pkill -f "uvicorn remediation.server:app" || true
pkill -f "uvicorn attacker-dashboard.app:app" || true

# Start APIs
python3 dashboard_api.py > dashboard_api.log 2>&1 &
DASHBOARD_PID=$!
echo "📊 Dashboard API: http://127.0.0.1:8080"

PYTHONPATH="$PWD" python3 -m uvicorn remediation.server:app --host 0.0.0.0 --port 8002 > remediation_api.log 2>&1 &
REMEDIATION_PID=$!
echo "🛡️ Remediation API: http://127.0.0.1:8002/api/remediation"

PYTHONPATH="$PWD" python3 -m uvicorn attacker-dashboard.app:app --host 0.0.0.0 --port 8003 > attacker_api.log 2>&1 &
ATTACKER_PID=$!
echo "⚔️ Attacker Control: http://127.0.0.1:8003"

npm --prefix dashboard run dev > /tmp/dashboard_ui.log 2>&1 &
DASHBOARD_UI_PID=$!
echo "🖥️  Main Dashboard UI: http://localhost:3000"

echo "============================================================"
echo "  STREAM ACTIVE — Real eBPF events flowing"
echo "============================================================"
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon \
    -c export-stdout -f --since=1m | python3 _sentinel_live.py
