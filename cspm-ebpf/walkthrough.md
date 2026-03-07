# RAG Integration — Final Walkthrough

## ✅ No Features Were Lost

Verified every file from the original main project is intact and unchanged:

| Main-Only Feature | Status |
|---|---|
| [forwarder/ml_triage.py](file:///home/revanth/sandbox/cspm-ebpf/forwarder/ml_triage.py) (152 lines) | ✅ Intact |
| `forwarder/model/xgboost_model.json` | ✅ Intact |
| `forwarder/model/feature_list.json` | ✅ Intact |
| [forwarder/api.py](file:///home/revanth/sandbox/cspm-ebpf/forwarder/api.py) — `/triage` endpoint | ✅ Intact |
| [forwarder/main.py](file:///home/revanth/sandbox/cspm-ebpf/forwarder/main.py) — ML triage pipeline | ✅ Intact |
| [forwarder/config.py](file:///home/revanth/sandbox/cspm-ebpf/forwarder/config.py) — ML_MODEL_PATH, FEATURE_LIST_PATH | ✅ Intact |
| [forwarder/requirements.txt](file:///home/revanth/sandbox/cspm-ebpf/forwarder/requirements.txt) — numpy, pandas, xgboost deps | ✅ Intact |
| [loop_demo.py](file:///home/revanth/sandbox/cspm-ebpf/loop_demo.py) — ML triage init | ✅ Intact |
| [start_app.sh](file:///home/revanth/sandbox/cspm-ebpf/start_app.sh) — ML triage init | ✅ Intact |
| `policies/host-sentinel.yaml` | ✅ Intact |
| `scripts/start-tetragon-host.sh` | ✅ Intact |

## New Files Added (from RAG)

[orchestrator.py](file:///home/revanth/sandbox/cspm-ebpf/RAG/orchestrator.py), [main.py](file:///home/revanth/sandbox/cspm-ebpf/RAG/main.py), [config.py](file:///home/revanth/sandbox/cspm-ebpf/RAG/config.py), [ingest.py](file:///home/revanth/sandbox/cspm-ebpf/RAG/ingest.py), [docker-compose.yml](file:///home/revanth/sandbox/cspm-ebpf/RAG/docker-compose.yml), [Dockerfile](file:///home/revanth/sandbox/cspm-ebpf/RAG/Dockerfile), [.env.example](file:///home/revanth/sandbox/cspm-ebpf/RAG/.env.example), [requirements.txt](file:///home/revanth/sandbox/cspm-ebpf/RAG/requirements.txt), [api_requirements.txt](file:///home/revanth/sandbox/cspm-ebpf/RAG/api_requirements.txt), `docs/` (7 files), `examples/`, `tests/` (3 files)

## About `"remediation": null`

This is **by design**, not a bug. In [forwarder/api.py](file:///home/revanth/sandbox/cspm-ebpf/forwarder/api.py#L136), line 136:
```python
"remediation": None, # Future Advisor task
```
This is a planned placeholder for a future remediation advisor feature.

## How to Test Every Aspect

### 1. Start the Forwarder (eBPF pipeline + ML triage)
```bash
cd /home/revanth/sandbox/cspm-ebpf
bash start_app.sh
```
**Expect**: `✅ ML model loaded`, `✅ Feature list loaded`, `✅ Connected to Redis`, events processing with triage grades.

### 2. Test Forwarder API (port 8081)

| Endpoint | Command | What to Check |
|---|---|---|
| Health | `curl http://127.0.0.1:8081/health` | `{"status":"ok"}` |
| Metrics | `curl http://127.0.0.1:8081/metrics` | event counts, uptime, Redis status |
| Latest Events | `curl http://127.0.0.1:8081/events/latest?limit=3` | events with triage grades |
| Triage (POST) | `curl -X POST http://127.0.0.1:8081/triage -H "Content-Type: application/json" -d '{"event_type":"process_exec","telemetry":{"binary":"curl","pid":1234,"uid":0}}'` | triage grade + confidence |
| Stream Info | `curl http://127.0.0.1:8081/events/stream` | Redis stream details |

### 3. Start the Orchestrator API (port 8000)

> [!IMPORTANT]
> Requires `.env` file with `GOOGLE_API_KEY`, `PINECONE_API_KEY`, `PINECONE_ENV`.

```bash
# Copy and fill in your keys
cp .env.example .env
# Edit .env with your actual API keys

# Then run:
source .venv/bin/activate
python main.py
```

| Endpoint | Command | What to Check |
|---|---|---|
| Root | `curl http://127.0.0.1:8000/` | Welcome message |
| Health | `curl http://127.0.0.1:8000/health` | `{"status":"ok","version":"1.0.0"}` |
| Status | `curl http://127.0.0.1:8000/status` | orchestrator, rag_system, ingestor availability |
| Analyze (POST) | See below | Full security analysis + YAML fix |
| Analyze/Stream | SSE streaming version | Token-by-token report |
| Ingest Trigger | `curl -X POST http://127.0.0.1:8000/ingest/trigger` | Starts background ingestion |

**Analyze example:**
```bash
curl -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{
    "raw_event": {
      "process_name": "runc",
      "syscall": "execve",
      "file_path": "/bin/sh",
      "pod_name": "vulnerable-app",
      "namespace": "production",
      "user": "root",
      "pid": 12345
    },
    "guide_score": 0.92,
    "guide_grade": "TP"
  }'
```

### 4. Docker Compose (optional)
```bash
docker compose up --build
```
Runs FastAPI orchestrator API + ChromaDB fallback.

### 5. Run Tests
```bash
# Orchestrator/API tests
cd /home/revanth/sandbox/cspm-ebpf
pytest tests/ -v

# Forwarder tests
pytest forwarder/tests/ -v
```
